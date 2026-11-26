//! What a match finder finds in a block: literals and sequences.

use crate::dec::block::BLOCK_MAX;

/// A sequence: `ll` literals, then a match of `ml` bytes. `off` is 1 to 3 for the repeat
/// offsets (as the format counts them, which depends on `ll` being 0), else the offset + 3.
#[derive(Clone, Copy, Default)]
pub(crate) struct Seq {
    pub ll: u32,
    pub ml: u32,
    pub off: u32,
}

pub(crate) const REP1: u32 = 1;

/// An offset as a sequence has it.
#[inline(always)]
pub(crate) fn off_base(offset: u32) -> u32 {
    offset + 3
}

pub(crate) struct SeqStore {
    /// The literals of all sequences and those behind the last one; room for 16 bytes more.
    pub lits: Vec<u8>,
    pub nlit: usize,
    pub seqs: Vec<Seq>,
    pub nseq: usize,
}

impl SeqStore {
    pub fn new() -> Self {
        SeqStore { lits: Vec::new(), nlit: 0, seqs: Vec::new(), nseq: 0 }
    }

    /// Empties the store and makes room for a block of `size` bytes.
    #[inline]
    pub fn reset(&mut self, size: usize) {
        debug_assert!(size <= BLOCK_MAX);
        if self.lits.len() < size + 32 {
            self.lits.resize(size + 32, 0);
            // a match has 3 bytes or more
            self.seqs.resize(size / 3 + 2, Seq::default());
        }
        self.nlit = 0;
        self.nseq = 0;
    }

    /// Adds a sequence: the literals `src[anchor..anchor + ll]` and a match.
    #[inline(always)]
    pub fn store(&mut self, src: &[u8], anchor: usize, ll: usize, off: u32, ml: usize) {
        let dst = &mut self.lits[self.nlit..];
        if ll <= 16 && anchor + 16 <= src.len() {
            dst[..16].copy_from_slice(&src[anchor..anchor + 16]);
        } else {
            dst[..ll].copy_from_slice(&src[anchor..anchor + ll]);
        }
        self.nlit += ll;
        self.seqs[self.nseq] = Seq { ll: ll as u32, ml: ml as u32, off };
        self.nseq += 1;
    }

    /// Adds the literals behind the last sequence.
    #[inline]
    pub fn last_literals(&mut self, lits: &[u8]) {
        self.lits[self.nlit..self.nlit + lits.len()].copy_from_slice(lits);
        self.nlit += lits.len();
    }
}
