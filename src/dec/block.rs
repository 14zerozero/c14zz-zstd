//! Decoding of a compressed block: the literals section, then the sequences, each executed
//! onto the output as it is decoded.

use super::tables::*;
use crate::bits::SeqBits;
use crate::dict::DecoderTables;
use crate::error::{Error, Result};
use crate::fse::{self, SeqSym, MAX_TABLE_SIZE, SEQ_ZERO};
use crate::huf;
use crate::mem::{rd16, rd24, rd32};
use std::sync::Arc;

/// The largest block of the format.
pub(crate) const BLOCK_MAX: usize = 128 * 1024;
/// The fast paths write and read up to this many bytes behind what they copy.
pub(crate) const SLACK: usize = 32;

#[derive(Clone, Copy, PartialEq)]
enum Cur {
    None,
    Default,
    Own,
}

/// What decoding keeps from block to block of a frame, and the buffers it works in.
pub(crate) struct BlockDecoder {
    huf: Box<huf::DTable>,
    huf_ok: bool,
    /// Literal lengths, offsets, match lengths: the tables in use (a predefined one is
    /// copied here), and the number of bits of their states.
    tabs: Box<Tabs>,
    logs: [u32; 3],
    cur: [Cur; 3],
    rep: [usize; 3],
    /// Decoded literals, with `SLACK` behind.
    lit: Vec<u8>,
    /// The dictionary (its `uid`) whose tables were copied here last, 0 for none, and which
    /// of them are no longer its tables: the Huffman table, then the three of `tabs`.
    dict: usize,
    dirty: [bool; 4],
    /// The tables of that dictionary, and which of them the frame has in the place of a
    /// previous block's without their being here yet: one is copied when a block repeats
    /// it, and only if it is not here from an earlier frame. (Small frames of the same kind
    /// mostly need the same tables: after the first few, nothing is copied.)
    held: Option<Arc<DecoderTables>>,
    pending: [bool; 4],
}

/// The three sequence tables. A table has 512 states at most; it has room for twice as many
/// because the sum of what makes a next state (a base and some bits of the stream, each
/// less than 512 by the way it is taken) is then within it without a check.
pub(crate) type Tabs = [[SeqSym; 2 * MAX_TABLE_SIZE]; 3];
const MASK: usize = 2 * MAX_TABLE_SIZE - 1;

impl BlockDecoder {
    pub fn new() -> Self {
        BlockDecoder {
            huf: Box::new(huf::DTable::new()),
            huf_ok: false,
            tabs: Box::new([[SEQ_ZERO; 2 * MAX_TABLE_SIZE]; 3]),
            logs: [0; 3],
            cur: [Cur::None; 3],
            rep: [1, 4, 8],
            lit: Vec::new(),
            dict: 0,
            dirty: [false; 4],
            held: None,
            pending: [false; 4],
        }
    }

    /// Forgets the previous frame.
    pub fn reset(&mut self) {
        self.huf_ok = false;
        self.cur = [Cur::None; 3];
        self.rep = [1, 4, 8];
        self.pending = [false; 4];
    }

    /// Starts a frame with a dictionary: the frame's first block may repeat the
    /// dictionary's tables and offsets as if they were a previous block's.
    pub fn reset_with(&mut self, dict: &crate::dict::Inner) {
        self.reset();
        let Some(t) = &dict.entropy else { return };
        if self.dict != dict.uid {
            self.dict = dict.uid;
            self.dirty = [true; 4];
            self.held = Some(t.clone());
        }
        self.pending = self.dirty;
        self.huf_ok = true;
        self.logs = t.logs;
        self.cur = [Cur::Own; 3];
        self.rep = t.rep;
    }

    /// Decodes the block at `input[at..at + size]` to `out[op..]`. The frame's earlier data is
    /// `out[..op]`, and before that the content of its dictionary, `ext`, which is not in
    /// `out`. Nothing is written at or behind `limit` (`<= out.len()`) except scratch.
    /// Returns the end of the block's data in `out`.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(&mut self, input: &[u8], at: usize, size: usize, out: &mut [u8], op: usize, limit: usize, ext: &[u8]) -> Result<usize> {
        #[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
        if std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("lzcnt") {
            // SAFETY: the processor has the instructions the function is compiled for.
            return unsafe { self.decode_bmi2(input, at, size, out, op, limit, ext) };
        }
        self.decode_any(input, at, size, out, op, limit, ext)
    }

    /// `decode_any` for processors with BMI2: the shifts by a variable number of bits, of
    /// which the bit readers are made, need no fixed register there. (With the feature
    /// `unsafe`: its call is not safe.)
    #[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
    #[target_feature(enable = "bmi1,bmi2,lzcnt")]
    #[allow(clippy::too_many_arguments)]
    fn decode_bmi2(&mut self, input: &[u8], at: usize, size: usize, out: &mut [u8], op: usize, limit: usize, ext: &[u8]) -> Result<usize> {
        decode_body!(self, input, at, size, out, op, limit, ext, sequences_bmi2, one_bmi2, four_bmi2, double_bmi2)
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_any(&mut self, input: &[u8], at: usize, size: usize, out: &mut [u8], op: usize, limit: usize, ext: &[u8]) -> Result<usize> {
        decode_body!(self, input, at, size, out, op, limit, ext, sequences_any, one_any, four_any, double_any)
    }

    /// Reads the literals section of the block: their number, where they are (in the input
    /// at a position, or in `self.lit`), and where the sequences section starts in the block.
    /// `decode` decodes Huffman streams (four of them, or one) with a table.
    #[inline(always)]
    fn literals(&mut self, input: &[u8], at: usize, size: usize, decode: impl Fn(&mut huf::DTable, &[u8], &mut [u8], bool) -> Result<()>) -> Result<(usize, Option<usize>, usize)> {
        let block = &input[at..at + size];
        let &b0 = block.first().ok_or(Error::Corrupt("empty compressed block"))?;
        let kind = b0 & 3;
        let format = (b0 >> 2) & 3;
        let lit_len;
        let lit_at;
        let seq_at;
        if kind < 2 {
            let (len, header) = match format {
                0 | 2 => ((b0 >> 3) as usize, 1),
                1 => {
                    if block.len() < 2 {
                        return Err(Error::Truncated);
                    }
                    ((rd16(block, 0) >> 4) as usize, 2)
                }
                _ => {
                    if block.len() < 3 {
                        return Err(Error::Truncated);
                    }
                    ((rd24(block, 0) >> 4) as usize, 3)
                }
            };
            if len > BLOCK_MAX {
                return Err(Error::Corrupt("literals larger than a block"));
            }
            lit_len = len;
            if kind == 0 {
                if header + len > block.len() {
                    return Err(Error::Truncated);
                }
                // in place; the fast path may read behind them, within the input
                lit_at = Some(at + header);
                seq_at = header + len;
            } else {
                let &byte = block.get(header).ok_or(Error::Truncated)?;
                if self.lit.len() < len + SLACK {
                    self.lit.resize(len + SLACK, 0);
                }
                self.lit[..len + SLACK].fill(byte);
                lit_at = None;
                seq_at = header + 1;
            }
        } else {
            if block.len() < 5 {
                return Err(Error::Truncated);
            }
            let h = rd32(block, 0);
            let (regen, comp, header, four) = match format {
                0 => (((h >> 4) & 0x3ff) as usize, ((h >> 14) & 0x3ff) as usize, 3, false),
                1 => (((h >> 4) & 0x3ff) as usize, ((h >> 14) & 0x3ff) as usize, 3, true),
                2 => (((h >> 4) & 0x3fff) as usize, (h >> 18) as usize, 4, true),
                _ => (((h >> 4) & 0x3ffff) as usize, ((h >> 22) as usize) | (block[4] as usize) << 10, 5, true),
            };
            if regen > BLOCK_MAX || regen == 0 {
                return Err(Error::Corrupt("size of the literals"));
            }
            if header + comp > block.len() {
                return Err(Error::Truncated);
            }
            let mut body = &block[header..header + comp];
            if kind == 2 {
                self.dirty[0] = true;
                self.pending[0] = false;
                let used = self.huf.read(body).inspect_err(|_| self.huf_ok = false)?;
                self.huf_ok = true;
                body = &body[used..];
            } else if !self.huf_ok {
                return Err(Error::Corrupt("no Huffman table to repeat"));
            } else if self.pending[0] {
                // the dictionary's
                if let Some(t) = &self.held {
                    (*self.huf).clone_from(&t.huf);
                }
                self.pending[0] = false;
                self.dirty[0] = false;
            }
            if self.lit.len() < regen + SLACK {
                self.lit.resize(regen + SLACK, 0);
            }
            decode(&mut self.huf, body, &mut self.lit[..regen], four)?;
            lit_len = regen;
            lit_at = None;
            seq_at = header + comp;
        }

        Ok((lit_len, lit_at, seq_at))
    }

    /// Reads the header of the sequences section `seq` and its tables: the number of
    /// sequences and where their stream starts.
    #[inline(never)]
    fn seq_tables(&mut self, seq: &[u8]) -> Result<(usize, usize)> {
        let &s0 = seq.first().ok_or(Error::Truncated)?;
        let (nseq, mut at) = if s0 < 128 {
            (s0 as usize, 1)
        } else if s0 < 255 {
            (((s0 as usize - 128) << 8) + *seq.get(1).ok_or(Error::Truncated)? as usize, 2)
        } else {
            if seq.len() < 3 {
                return Err(Error::Truncated);
            }
            (rd16(seq, 1) as usize + 0x7f00, 3)
        };
        if nseq == 0 {
            if seq.len() != 1 {
                return Err(Error::Corrupt("data behind a block without sequences"));
            }
            return Ok((0, 1));
        }
        let &modes = seq.get(at).ok_or(Error::Truncated)?;
        at += 1;
        if modes & 3 != 0 {
            return Err(Error::Corrupt("reserved bits of the sequences section"));
        }
        const KINDS: [(&[u32], &[u8], u32); 3] = [(&LL_BASE, &LL_BITS, 9), (&OF_BASE, &OF_BITS, 8), (&ML_BASE, &ML_BITS, 9)];
        for (k, (base, bits, max_log)) in KINDS.into_iter().enumerate() {
            let mode = (modes >> (6 - 2 * k)) & 3;
            if mode != 3 {
                self.dirty[1 + k] = true;
                self.pending[1 + k] = false;
            } else if self.pending[1 + k] {
                // the dictionary's
                if let Some(t) = &self.held {
                    t.copy_table(k, &mut self.tabs);
                }
                self.pending[1 + k] = false;
                self.dirty[1 + k] = false;
            }
            match mode {
                0 => {
                    if self.cur[k] != Cur::Default {
                        let (default, log): (&[SeqSym; MAX_TABLE_SIZE], u32) = match k {
                            0 => (&LL_DEFAULT, LL_DEFAULT_LOG),
                            1 => (&OF_DEFAULT, OF_DEFAULT_LOG),
                            _ => (&ML_DEFAULT, ML_DEFAULT_LOG),
                        };
                        let n = 1usize << log;
                        self.tabs[k][..n].copy_from_slice(&default[..n]);
                        self.logs[k] = log;
                        self.cur[k] = Cur::Default;
                    }
                }
                1 => {
                    let &symbol = seq.get(at).ok_or(Error::Truncated)?;
                    at += 1;
                    if symbol as usize >= base.len() {
                        self.cur[k] = Cur::None;
                        return Err(Error::Corrupt("symbol of an RLE table"));
                    }
                    self.tabs[k][0] = SeqSym::new(0, bits[symbol as usize], 0, base[symbol as usize]);
                    self.logs[k] = 0;
                    self.cur[k] = Cur::Own;
                }
                2 => {
                    self.cur[k] = Cur::None;
                    let mut norm = [0i16; fse::MAX_SYMBOL + 1];
                    let (n, log, used) = fse::read_ncount(&mut norm[..base.len()], max_log, &seq[at..])?;
                    at += used;
                    let table: &mut [SeqSym; MAX_TABLE_SIZE] = (&mut self.tabs[k][..MAX_TABLE_SIZE]).try_into().unwrap();
                    if !fse::seq_table(table, &norm, n, log, base, bits) {
                        return Err(Error::Corrupt("FSE table of the sequences"));
                    }
                    self.logs[k] = log;
                    self.cur[k] = Cur::Own;
                }
                _ => {
                    if self.cur[k] == Cur::None {
                        return Err(Error::Corrupt("no FSE table to repeat"));
                    }
                }
            }
        }
        Ok((nseq, at))
    }
}

/// The parts of `decode`, with the functions for the sequences and the literals to use.
macro_rules! decode_body {
    ($self:ident, $input:ident, $at:ident, $size:ident, $out:ident, $op:ident, $limit:ident, $ext:ident, $sequences:ident, $one:ident, $four:ident, $double:ident) => {{
        let clock = crate::prof::start();
        // (the decoders of the literals are functions for the processor this is compiled
        // for, as the one for the sequences)
        let huffman = |table: &mut huf::DTable, src: &[u8], out: &mut [u8], four: bool| {
            if !four {
                huf::$one(table, src, out)
            } else if table.double_gains(out.len()) {
                huf::$double(table, src, out)
            } else {
                huf::$four(table, src, out)
            }
        };
        let (lit_len, lit_at, seq_at) = $self.literals($input, $at, $size, huffman)?;
        let clock = crate::prof::stop(clock, 0);
        let (nseq, stream_at) = $self.seq_tables(&$input[$at + seq_at..$at + $size])?;
        let clock = crate::prof::stop(clock, 1);
        let lits: &[u8] = match lit_at {
            Some(a) => &$input[a..],
            None => &$self.lit,
        };
        let stream = &$input[$at + seq_at + stream_at..$at + $size];
        let end = $sequences(&$self.tabs, $self.logs, &mut $self.rep, stream, nseq, lits, lit_len, $out, $op, $limit, $ext);
        crate::prof::stop(clock, 2);
        end
    }};
}
use decode_body;

/// The low `n` bits of `x`, with the instruction for it. (`n` is 16 at most here.)
#[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
macro_rules! low_bmi2 {
    ($x:expr, $n:expr) => {
        core::arch::x86_64::_bzhi_u64($x, $n)
    };
}

/// The low `n` bits of `x`, `n < 32`.
macro_rules! low_any {
    ($x:expr, $n:expr) => {
        $x & ((1u64 << ($n & 31)) - 1)
    };
}

#[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
#[target_feature(enable = "bmi1,bmi2,lzcnt")]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn sequences_bmi2(tabs: &Tabs, logs: [u32; 3], rep: &mut [usize; 3], stream: &[u8], nseq: usize, lits: &[u8], lit_len: usize, out: &mut [u8], op: usize, limit: usize, ext: &[u8]) -> Result<usize> {
    sequences!(low_bmi2, tabs, logs, rep, stream, nseq, lits, lit_len, out, op, limit, ext)
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn sequences_any(tabs: &Tabs, logs: [u32; 3], rep: &mut [usize; 3], stream: &[u8], nseq: usize, lits: &[u8], lit_len: usize, out: &mut [u8], op: usize, limit: usize, ext: &[u8]) -> Result<usize> {
    sequences!(low_any, tabs, logs, rep, stream, nseq, lits, lit_len, out, op, limit, ext)
}

/// Decodes the `nseq` sequences of `stream` and executes them onto `out[op..]` with the
/// literals `lits[..lit_len]`; the literals behind the last sequence follow. Gives the end
/// of the data. Before `out[0]` is the content of the dictionary, `ext`. `low` is the macro for the low bits of a word. (A macro, not a function:
/// the instruction of `low_bmi2` can be named only in a function that is compiled for it.)
macro_rules! sequences {
    ($low:ident, $tabs:ident, $logs:ident, $rep_io:ident, $stream:ident, $nseq:ident, $lits:ident, $lit_len:ident, $out:ident, $op:ident, $limit:ident, $ext:ident) => {{
        let (tabs, logs, rep_io, stream, nseq, lits, lit_len, out, op, limit, ext): (&Tabs, [u32; 3], &mut [usize; 3], &[u8], usize, &[u8], usize, &mut [u8], usize, usize, &[u8]) =
            ($tabs, $logs, $rep_io, $stream, $nseq, $lits, $lit_len, $out, $op, $limit, $ext);
        if nseq == 0 {
            let end = op + lit_len;
            if end > limit {
                return Err(if end > op + BLOCK_MAX { Error::Corrupt("block larger than the format allows") } else { Error::OutputTooSmall });
            }
            out[op..end].copy_from_slice(&lits[..lit_len]);
            return Ok(end);
        }
        let block_end = op + BLOCK_MAX;
        let over = |end: usize| if end > block_end { Error::Corrupt("block larger than the format allows") } else { Error::OutputTooSmall };
        let [ll_log, of_log, ml_log] = logs;
        let mut br = SeqBits::new(stream)?;
        let mut sl = $low!(br.take(ll_log), ll_log) as usize & MASK;
        let mut so = $low!(br.take(of_log), of_log) as usize & MASK;
        let mut sm = $low!(br.take(ml_log), ml_log) as usize & MASK;
        br.refill();
        let [mut rep0, mut rep1, mut rep2] = *rep_io;
        let [llt, oft, mlt] = tabs;
        let mut op = op;
        let mut lp = 0usize;
        // the fast path needs room behind what it copies: `SLACK` in `out`, 16 bytes in `lits`
        // (as the ends that a sequence's match and literals are to be before)
        let out_stop = ((limit + SLACK).min(out.len()) + 1).saturating_sub(SLACK);
        let lit_stop = ((lit_len + 16).min(lits.len()) + 1).saturating_sub(16);
        // (One loop for decoding a sequence and executing it: the copies run while the next
        // sequence's states, which wait for each other, are worked out.)
        let mut left = nseq;
        while left > 0 {
            // (by reference: a field is then read from the table where it is used, which
            // is less work than taking it out of a copy of the entry in a register)
            let l = &llt[sl];
            let m = &mlt[sm];
            let o = &oft[so];
            let ob = o.add_bits();
            let mb = m.add_bits();
            let lb = l.add_bits();
            let offset;
            if ob > 1 {
                offset = o.base() + $low!(br.take(ob), ob) as usize;
                rep2 = rep1;
                rep1 = rep0;
                rep0 = offset;
            } else {
                let ll0 = l.base() == 0;
                if ob == 0 {
                    offset = if ll0 { rep1 } else { rep0 };
                    rep1 = if ll0 { rep0 } else { rep1 };
                    rep0 = offset;
                } else {
                    let code = o.base() + ll0 as usize + (br.take(1) & 1) as usize;
                    let v = match code {
                        1 => rep1,
                        2 => rep2,
                        _ => rep0.wrapping_sub(1),
                    };
                    // 0 is no offset: make it one that no history has
                    let v = if v == 0 { usize::MAX } else { v };
                    if code != 1 {
                        rep2 = rep1;
                    }
                    rep1 = rep0;
                    rep0 = v;
                    offset = v;
                }
            }
            // (most lengths have no bits of their own)
            let mut ml = m.base();
            if mb > 0 {
                ml += $low!(br.take(mb), mb) as usize;
            }
            if ob + mb + lb >= 31 {
                br.refill();
            }
            let mut ll = l.base();
            if lb > 0 {
                ll += $low!(br.take(lb), lb) as usize;
            }
            left -= 1;
            if left > 0 {
                // (the sums are within the tables for every table that was accepted; `MASK`
                // says so to the compiler)
                let (nl, nm, no) = (l.nb_bits(), m.nb_bits(), o.nb_bits());
                sl = (l.next() + $low!(br.take(nl), nl) as usize) & MASK;
                sm = (m.next() + $low!(br.take(nm), nm) as usize) & MASK;
                so = (o.next() + $low!(br.take(no), no) as usize) & MASK;
                br.refill();
            }
            let lit_end = lp + ll;
            let match_at = op + ll;
            let end = match_at + ml;
            if lit_end < lit_stop && end < out_stop && offset.wrapping_sub(1) < match_at {
                // SAFETY:
                // - `lit_end + 16 <= lits.len()` (`lit_end < lit_stop`, which is at most
                //   `lits.len() + 1 - 16`), so the literal copies, in steps of 16 from `lp` to
                //   less than 16 behind `lit_end`, read within `lits`;
                // - `end + SLACK <= out.len()` (`end < out_stop`, which is at most
                //   `out.len() + 1 - SLACK`; `SLACK` is 32): the literal copies write up to
                //   less than 16 behind `match_at`, the match copies up to less than 32
                //   behind `end`;
                // - `1 <= offset <= match_at`, so the match is read from `out` at or after its
                //   start, and never further than it is written;
                // - `lits` is not `out` (`out` is borrowed mutably).
                // (Without the feature `unsafe`: the same copies as checked ones of slices.)
                #[cfg(feature = "unsafe")]
                unsafe {
                    let o = out.as_mut_ptr();
                    let l = lits.as_ptr().add(lp);
                    let d = o.add(op);
                    core::ptr::copy_nonoverlapping(l, d, 16);
                    if ll > 16 {
                        // (16 bytes at a time up to less than 16 behind the literals: a call
                        // of memcpy costs more than the rounds for the runs of literals that
                        // are common)
                        core::ptr::copy_nonoverlapping(l.add(16), d.add(16), 16);
                        let mut i = 32;
                        while i < ll {
                            core::ptr::copy_nonoverlapping(l.add(i), d.add(i), 16);
                            i += 16;
                        }
                    }
                    let mut d = o.add(match_at);
                    let mut s = o.add(match_at - offset);
                    let d_end = d.add(ml);
                    if offset >= 16 {
                        // (16 bytes, then 32 at a time: most matches are short, the long
                        // ones take half the rounds)
                        core::ptr::copy_nonoverlapping(s, d, 16);
                        if ml > 16 {
                            s = s.add(16);
                            d = d.add(16);
                            loop {
                                core::ptr::copy_nonoverlapping(s, d, 16);
                                core::ptr::copy_nonoverlapping(s.add(16), d.add(16), 16);
                                s = s.add(32);
                                d = d.add(32);
                                if d >= d_end {
                                    break;
                                }
                            }
                        }
                    } else {
                        // spread the pattern so that source and destination are 8 or more apart
                        if offset < 8 {
                            const ADVANCE: [usize; 8] = [0, 1, 2, 2, 4, 3, 2, 1];
                            const DEC32: [usize; 8] = [0, 1, 2, 1, 4, 4, 4, 4];
                            *d = *s;
                            *d.add(1) = *s.add(1);
                            *d.add(2) = *s.add(2);
                            *d.add(3) = *s.add(3);
                            core::ptr::copy_nonoverlapping(s.add(DEC32[offset]), d.add(4), 4);
                            s = s.add(ADVANCE[offset]);
                        } else {
                            core::ptr::copy_nonoverlapping(s, d, 8);
                            s = s.add(8);
                        }
                        d = d.add(8);
                        while d < d_end {
                            core::ptr::copy_nonoverlapping(s, d, 8);
                            s = s.add(8);
                            d = d.add(8);
                        }
                    }
                }
                #[cfg(not(feature = "unsafe"))]
                {
                    out[op..op + 16].copy_from_slice(&lits[lp..lp + 16]);
                    if ll > 16 {
                        // (16 bytes at a time up to less than 16 behind the literals: a call
                        // of memcpy costs more than the rounds for the runs of literals that
                        // are common)
                        let mut i = 16;
                        while i < ll {
                            out[op + i..op + i + 16].copy_from_slice(&lits[lp + i..lp + i + 16]);
                            i += 16;
                        }
                    }
                    let mut d = match_at;
                    let mut s = match_at - offset;
                    if offset >= 16 {
                        // (16 bytes, then 32 at a time: most matches are short, the long
                        // ones take half the rounds)
                        out.copy_within(s..s + 16, d);
                        if ml > 16 {
                            s += 16;
                            d += 16;
                            loop {
                                out.copy_within(s..s + 16, d);
                                out.copy_within(s + 16..s + 32, d + 16);
                                s += 32;
                                d += 32;
                                if d >= end {
                                    break;
                                }
                            }
                        }
                    } else {
                        // spread the pattern so that source and destination are 8 or more apart
                        if offset < 8 {
                            const ADVANCE: [usize; 8] = [0, 1, 2, 2, 4, 3, 2, 1];
                            const DEC32: [usize; 8] = [0, 1, 2, 1, 4, 4, 4, 4];
                            out[d] = out[s];
                            out[d + 1] = out[s + 1];
                            out[d + 2] = out[s + 2];
                            out[d + 3] = out[s + 3];
                            let from = s + DEC32[offset];
                            out.copy_within(from..from + 4, d + 4);
                            s += ADVANCE[offset];
                        } else {
                            out.copy_within(s..s + 8, d);
                            s += 8;
                        }
                        d += 8;
                        while d < end {
                            out.copy_within(s..s + 8, d);
                            s += 8;
                            d += 8;
                        }
                    }
                }
            } else {
                exec_far(out, op, lits, lit_len, lp, ll, ml, offset, limit, ext).map_err(|e| if e == Error::OutputTooSmall { over(end) } else { e })?;
            }
            op = end;
            lp = lit_end;
        }
        if !br.finished() {
            return Err(Error::Corrupt("sequences stream does not end with its data"));
        }
        *rep_io = [rep0, rep1, rep2];
        let rest = lit_len - lp;
        let end = op + rest;
        if end > limit {
            return Err(over(end));
        }
        out[op..end].copy_from_slice(&lits[lp..lit_len]);
        Ok(end)
    }};
}
use sequences;

/// One sequence that is not for the copies above. With a dictionary and small data that is
/// most of them: their matches are in the content, `ext`. Short ones that are in it as a
/// whole, with room for 16 and 32 bytes at a time as above, are copied that way here.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn exec_far(out: &mut [u8], op: usize, lits: &[u8], lit_len: usize, lp: usize, ll: usize, ml: usize, offset: usize, limit: usize, ext: &[u8]) -> Result<()> {
    let match_at = op + ll;
    let before = offset.wrapping_sub(match_at);
    if ll <= 16 && ml <= 32 && lp + ll <= lit_len && lp + 16 <= lits.len() && match_at + 32 <= limit && offset > match_at && before >= 32 && before <= ext.len() {
        let from = ext.len() - before;
        out[op..op + 16].copy_from_slice(&lits[lp..lp + 16]);
        out[match_at..match_at + 32].copy_from_slice(&ext[from..from + 32]);
        return Ok(());
    }
    exec_slow(out, op, lits, lit_len, lp, ll, ml, offset, limit, ext)
}

/// One sequence, checked byte for byte; its match may start in the dictionary's content,
/// `ext`, which is before `out[0]`.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn exec_slow(out: &mut [u8], op: usize, lits: &[u8], lit_len: usize, lp: usize, ll: usize, ml: usize, offset: usize, limit: usize, ext: &[u8]) -> Result<()> {
    if lp + ll > lit_len {
        return Err(Error::Corrupt("sequences use more literals than there are"));
    }
    let match_at = op + ll;
    if match_at + ml > limit {
        return Err(Error::OutputTooSmall);
    }
    if offset == 0 || offset - match_at.min(offset) > ext.len() {
        return Err(Error::Corrupt("offset beyond the start of the data"));
    }
    out[op..match_at].copy_from_slice(&lits[lp..lp + ll]);
    if offset > match_at {
        // from the dictionary, and on at the start of the data
        let before = offset - match_at;
        let n = before.min(ml);
        out[match_at..match_at + n].copy_from_slice(&ext[ext.len() - before..ext.len() - before + n]);
        for i in 0..ml - n {
            out[match_at + n + i] = out[i];
        }
        return Ok(());
    }
    let from = match_at - offset;
    if offset >= ml {
        out.copy_within(from..from + ml, match_at);
    } else {
        for i in 0..ml {
            out[match_at + i] = out[from + i];
        }
    }
    Ok(())
}
