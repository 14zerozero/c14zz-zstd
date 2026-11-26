//! The block splitter that works on a block's sequences, after the reference
//! implementation's `ZSTD_compressBlock_splitBlock`: with the strategies from `btopt` on and
//! windows of 128 KB or more, a block whose halves, each with tables of its own, are
//! estimated to be smaller than the whole is written as two blocks, and so on for the halves.

use super::params::{Params, Strategy};
use super::seq::{Seq, SeqStore};
use super::{Encoder, Out};
use crate::error::Result;

/// Fewer sequences than this are not split.
const MIN_SEQUENCES: usize = 300;
/// The most splits of a block.
const MAX_SPLITS: usize = 196;

/// Whether the blocks of `p` are looked at for splitting.
pub(super) fn enabled(p: &Params) -> bool {
    p.strategy >= Strategy::BtOpt && p.window_log >= 17
}

/// What the splitter keeps: its buffers.
pub(crate) struct Parts {
    /// The literals and sequences of one part.
    store: SeqStore,
    /// The number of the literals before each sequence of the block.
    lit_at: Vec<u32>,
    /// The parts' ends, as numbers of sequences.
    ends: Vec<u32>,
}

impl Parts {
    pub fn heap_size(&self) -> usize {
        self.store.heap_size() + 4 * (self.lit_at.capacity() + self.ends.capacity())
    }

    pub fn new() -> Self {
        Parts { store: SeqStore::new(), lit_at: Vec::new(), ends: Vec::new() }
    }
}

/// The offset a repeat offset code `off` (1 to 3) of a sequence means with the offsets `rep`
/// before it; `ll0`: the sequence has no literals.
fn repeat_offset(rep: &[u32; 3], off: u32, ll0: bool) -> u32 {
    match off - 1 + ll0 as u32 {
        3 => rep[0].wrapping_sub(1),
        code => rep[code as usize],
    }
}

/// Makes the repeat offset codes of `seqs` mean what the match finder meant: it had the
/// offsets `found` before them, a decoder has `decoded`, which are others if a part before
/// was not written as sequences. Both are moved on to behind `seqs`.
fn resolve_offsets(decoded: &mut [u32; 3], found: &mut [u32; 3], seqs: &mut [Seq]) {
    for seq in seqs {
        let ll0 = seq.ll == 0;
        let off = seq.off;
        if off <= 3 {
            let meant = repeat_offset(found, off, ll0);
            if repeat_offset(decoded, off, ll0) != meant {
                seq.off = meant + 3;
            }
        }
        *decoded = super::opt::new_rep(*decoded, seq.off, ll0);
        *found = super::opt::new_rep(*found, off, ll0);
    }
}

impl Encoder {
    /// The literals of the sequences `a..b` of the block in `self.store`, with those behind
    /// the last sequence if that is one of them.
    fn literals_of(&self, a: usize, b: usize) -> &[u8] {
        let to = if b == self.store.nseq { self.store.nlit } else { self.parts.lit_at[b] as usize };
        &self.store.lits[self.parts.lit_at[a] as usize..to]
    }

    /// Looks for splits of the sequences `a..b` and adds them to `self.parts.ends`
    /// (`ZSTD_deriveBlockSplitsHelper`).
    fn derive_splits(&mut self, a: usize, b: usize, strategy: Strategy) {
        if b - a < MIN_SEQUENCES || self.parts.ends.len() >= MAX_SPLITS {
            return;
        }
        let mid = (a + b) / 2;
        let mut estimate = |a: usize, b: usize| {
            let to = if b == self.store.nseq { self.store.nlit } else { self.parts.lit_at[b] as usize };
            self.blocks.estimate(&self.store.lits[self.parts.lit_at[a] as usize..to], &self.store.seqs[a..b], strategy)
        };
        let (Some(whole), Some(first), Some(second)) = (estimate(a, b), estimate(a, mid), estimate(mid, b)) else {
            return;
        };
        if first + second < whole {
            self.derive_splits(a, mid, strategy);
            if self.parts.ends.len() >= MAX_SPLITS {
                return;
            }
            self.parts.ends.push(mid as u32);
            self.derive_splits(mid, b, strategy);
        }
    }

    /// Writes the block `data[at..end]`, whose sequences are in `self.store`, as several
    /// blocks if that is estimated to be smaller; returns the size of what was written, or
    /// `None` with nothing written: the block is to be written as one. `rep_before`: the
    /// repeat offsets before the block. (See `Encoder::block` for the rest.)
    #[allow(clippy::too_many_arguments)]
    pub(super) fn split<O: Out>(&mut self, p: &Params, data: &[u8], at: usize, end: usize, last: bool, first: bool, rep_before: [u32; 3], out: &mut O) -> Result<Option<usize>> {
        let nseq = self.store.nseq;
        if nseq <= 4 {
            return Ok(None);
        }
        self.parts.lit_at.clear();
        let mut lits = 0;
        for seq in &self.store.seqs[..nseq] {
            self.parts.lit_at.push(lits);
            lits += seq.ll;
        }
        self.parts.ends.clear();
        self.derive_splits(0, nseq, p.strategy);
        if self.parts.ends.is_empty() {
            return Ok(None);
        }
        self.parts.ends.push(nseq as u32);

        // A part that is not written as sequences leaves the decoder's repeat offsets as
        // they were: the sequences behind it must not rely on those the match finder had.
        let (mut decoded, mut found) = (rep_before, rep_before);
        let mut ip = at;
        let mut written = 0;
        let mut a = 0;
        self.parts.store.reset(end - at);
        for i in 0..self.parts.ends.len() {
            let b = self.parts.ends[i] as usize;
            let last_part = i + 1 == self.parts.ends.len();
            let n = b - a;
            let lits = self.literals_of(a, b).len();
            let from = self.parts.lit_at[a] as usize;
            let part = &mut self.parts.store;
            part.seqs[..n].copy_from_slice(&self.store.seqs[a..b]);
            part.nseq = n;
            part.lits[..lits].copy_from_slice(&self.store.lits[from..from + lits]);
            part.nlit = lits;
            let size = if last_part { end - ip } else { part.seqs[..n].iter().map(|s| (s.ll + s.ml) as usize).sum() };
            let decoded_before = decoded;
            resolve_offsets(&mut decoded, &mut found, &mut part.seqs[..n]);
            let mut compressed = self.blocks.encode(part, size, p.strategy, true);
            if !first && compressed < 25 && data[ip..ip + size].iter().all(|&b| b == data[ip]) {
                compressed = 1;
            }
            let last_block = last && last_part;
            let header = |kind: u32, size: usize| ((last_block as u32) | kind << 1 | (size as u32) << 3).to_le_bytes();
            match compressed {
                0 => {
                    decoded = decoded_before;
                    out.put(&header(0, size)[..3])?;
                    out.put(&data[ip..ip + size])?;
                    written += 3 + size;
                }
                1 => {
                    decoded = decoded_before;
                    out.put(&header(1, size)[..3])?;
                    out.put(&data[ip..ip + 1])?;
                    written += 4;
                }
                n => {
                    self.blocks.confirm();
                    out.put(&header(2, n)[..3])?;
                    out.put(&self.blocks.out[..n])?;
                    written += 3 + n;
                }
            }
            ip += size;
            a = b;
        }
        self.rep = decoded;
        Ok(Some(written))
    }
}
