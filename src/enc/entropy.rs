//! Encoding of a block's literals and sequences, with the choices of the reference
//! implementation: Huffman for the literals unless they are few or do not gain, with the
//! previous block's table when that is cheaper; for each of the sequences' three codes the
//! predefined table, a single symbol, the previous table or a new one.

use super::params::Strategy;
use super::seq::SeqStore;
use crate::bits::BitW;
use crate::dec::tables::*;
use crate::fse;
use crate::huf;
use crate::mem::highbit;
use std::sync::LazyLock;

mod estimate;

#[derive(Clone, Copy, PartialEq)]
enum Repeat {
    /// There is no table.
    None,
    /// There is one; whether it has all symbols needed is to be checked.
    Check,
    /// There is one that has all symbols a block may need: a dictionary's, before the
    /// frame's first block.
    Valid,
}

const LL_CODE: [u8; 64] = {
    let mut t = [0u8; 64];
    let mut v = 0;
    while v < 64 {
        let mut c = 0;
        while c + 1 < 36 && LL_BASE[c + 1] <= v as u32 {
            c += 1;
        }
        t[v] = c as u8;
        v += 1;
    }
    t
};
const ML_CODE: [u8; 128] = {
    let mut t = [0u8; 128];
    let mut v = 0;
    while v < 128 {
        let mut c = 0;
        while c + 1 < 53 && ML_BASE[c + 1] <= v as u32 + 3 {
            c += 1;
        }
        t[v] = c as u8;
        v += 1;
    }
    t
};

#[inline(always)]
pub(super) fn ll_code(ll: u32) -> u8 {
    if ll > 63 {
        (highbit(ll) + 19) as u8
    } else {
        LL_CODE[ll as usize]
    }
}

/// The code of a match length less 3.
#[inline(always)]
pub(super) fn ml_code(ml_base: u32) -> u8 {
    if ml_base > 127 {
        (highbit(ml_base) + 36) as u8
    } else {
        ML_CODE[ml_base as usize]
    }
}

struct Defaults {
    ll: fse::CTable,
    of: fse::CTable,
    ml: fse::CTable,
}

static DEFAULTS: LazyLock<Defaults> = LazyLock::new(|| {
    let mut d = Defaults { ll: fse::CTable::new(), of: fse::CTable::new(), ml: fse::CTable::new() };
    d.ll.build(&LL_DEFAULT_NORM, LL_DEFAULT_LOG);
    d.of.build(&OF_DEFAULT_NORM, OF_DEFAULT_LOG);
    d.ml.build(&ML_DEFAULT_NORM, ML_DEFAULT_LOG);
    d
});

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Basic = 0,
    Rle = 1,
    Compressed = 2,
    Repeat = 3,
}

/// The bytes a block must gain to be written compressed.
#[inline]
pub(crate) fn min_gain(size: usize, strategy: Strategy) -> usize {
    let min_log = if strategy >= Strategy::BtUltra { strategy as u32 - 1 } else { 6 };
    (size >> min_log) + 2
}

pub(crate) struct BlockEncoder {
    huf: Box<huf::CTable>,
    huf_next: Box<huf::CTable>,
    huf_repeat: Repeat,
    huf_new: bool,
    /// Literal lengths, offsets, match lengths.
    fse: [Box<fse::CTable>; 3],
    fse_next: [Box<fse::CTable>; 3],
    fse_repeat: [Repeat; 3],
    fse_new: [Option<Repeat>; 3],
    /// The codes of a block's sequences: of the literal length, the offset and the match
    /// length. (Side by side: what goes through them has one place to look at.)
    codes: Vec<[u8; 4]>,
    /// The encoded block.
    pub out: Vec<u8>,
}

impl BlockEncoder {
    pub fn new() -> Self {
        let t = || Box::new(fse::CTable::new());
        BlockEncoder {
            huf: Box::new(huf::CTable::new()),
            huf_next: Box::new(huf::CTable::new()),
            huf_repeat: Repeat::None,
            huf_new: false,
            fse: [t(), t(), t()],
            fse_next: [t(), t(), t()],
            fse_repeat: [Repeat::None; 3],
            fse_new: [None; 3],
            codes: Vec::new(),
            out: Vec::new(),
        }
    }

    /// Forgets the previous frame.
    pub fn reset(&mut self) {
        self.huf_repeat = Repeat::None;
        self.fse_repeat = [Repeat::None; 3];
    }

    /// Starts a frame with the tables of a dictionary in the place of a previous block's.
    pub fn reset_with(&mut self, t: &crate::dict::EncoderTables) {
        let mode = |valid: bool| if valid { Repeat::Valid } else { Repeat::Check };
        (*self.huf).clone_from(&t.huf);
        self.huf_repeat = mode(t.huf_valid);
        for k in 0..3 {
            (*self.fse[k]).clone_from(&t.fse[k]);
            self.fse_repeat[k] = mode(t.fse_valid[k]);
        }
    }

    /// A block of the frame was written, whatever its kind. (The offsets a dictionary's
    /// table has codes for are those the first block can have; later ones are to be
    /// checked.)
    pub fn block_done(&mut self) {
        if self.fse_repeat[1] == Repeat::Valid {
            self.fse_repeat[1] = Repeat::Check;
        }
    }

    /// Makes the tables of the block encoded last those of the previous block.
    pub fn confirm(&mut self) {
        if self.huf_new {
            core::mem::swap(&mut self.huf, &mut self.huf_next);
            self.huf_repeat = Repeat::Check;
        }
        for k in 0..3 {
            if let Some(repeat) = self.fse_new[k] {
                if repeat == Repeat::Check {
                    core::mem::swap(&mut self.fse[k], &mut self.fse_next[k]);
                }
                self.fse_repeat[k] = repeat;
            }
        }
    }

    /// Encodes the block of `size` bytes found in `store` into `self.out`; returns the size,
    /// 0 if that does not gain. `confirm` is to be called if the result is used.
    pub fn encode(&mut self, store: &SeqStore, size: usize, strategy: Strategy, literal_compression: bool) -> usize {
        #[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
        if std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("lzcnt") {
            // SAFETY: the processor has the instructions the function is compiled for.
            return unsafe { self.encode_bmi2(store, size, strategy, literal_compression) };
        }
        self.encode_any(store, size, strategy, literal_compression)
    }

    /// `encode_any` compiled for processors with BMI2: the bit writers' shifts by a variable
    /// number of bits need no fixed register there. (With the feature `unsafe`: its call is
    /// not safe. Without, the processor the crate is compiled for is all there is.)
    #[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
    #[target_feature(enable = "bmi1,bmi2,lzcnt")]
    fn encode_bmi2(&mut self, store: &SeqStore, size: usize, strategy: Strategy, literal_compression: bool) -> usize {
        self.encode_any(store, size, strategy, literal_compression)
    }

    #[inline(always)]
    fn encode_any(&mut self, store: &SeqStore, size: usize, strategy: Strategy, literal_compression: bool) -> usize {
        // (room for the block as it is and some more: what gets larger than that is given up)
        if self.out.len() < size + 1024 {
            self.out.resize(size + 1024, 0);
        }
        self.huf_new = false;
        self.fse_new = [None; 3];
        let nseq = store.nseq;
        let lits = &store.lits[..store.nlit];
        let suspect_uncompressible = nseq == 0 || lits.len() / nseq >= 20;
        let clock = crate::prof::start();
        let mut at = self.literals(lits, strategy, literal_compression, suspect_uncompressible);
        crate::prof::stop(clock, 4);
        if at == 0 {
            return 0;
        }
        let max_size = size.saturating_sub(min_gain(size, strategy));
        if at >= max_size {
            return 0;
        }

        // ---- sequences
        let out = &mut self.out[..];
        if nseq < 128 {
            out[at] = nseq as u8;
            at += 1;
        } else if nseq < 0x7f00 {
            out[at] = (nseq >> 8) as u8 + 0x80;
            out[at + 1] = nseq as u8;
            at += 2;
        } else {
            out[at] = 0xff;
            out[at + 1..at + 3].copy_from_slice(&((nseq - 0x7f00) as u16).to_le_bytes());
            at += 3;
        }
        if nseq == 0 {
            return if at >= max_size { 0 } else { at };
        }
        let modes_at = at;
        at += 1;

        if self.codes.len() < nseq {
            self.codes.resize(nseq.next_power_of_two().max(256), [0; 4]);
        }
        let codes = &mut self.codes[..nseq];
        let seqs = &store.seqs[..nseq];
        // (two sets of counters, taken in turn: a counter's increment waits for the previous
        // one of the same counter, and successive sequences often have the same codes)
        let mut counts = [[0u32; 64]; 3];
        let mut counts2 = [[0u32; 64]; 3];
        for (i, (s, code)) in seqs.iter().zip(codes.iter_mut()).enumerate() {
            let (l, o, m) = (ll_code(s.ll), highbit(s.off) as u8, ml_code(s.ml - 3));
            *code = [l, o, m, 0];
            let c = if i & 1 == 0 { &mut counts } else { &mut counts2 };
            c[0][l as usize & 63] += 1;
            c[1][o as usize & 63] += 1;
            c[2][m as usize & 63] += 1;
        }
        for (a, b) in counts.iter_mut().flatten().zip(counts2.iter().flatten()) {
            *a += b;
        }

        let codes = &*codes;
        let defaults = &*DEFAULTS;
        let mut modes = 0u8;
        let mut last_ncount = 0usize;
        // (default norm, default log, max log, largest symbol allowed for the default)
        type Kind = (&'static [i16], u32, u32, usize);
        let kinds: [Kind; 3] = [(&LL_DEFAULT_NORM, LL_DEFAULT_LOG, 9, 35), (&OF_DEFAULT_NORM, OF_DEFAULT_LOG, 8, 28), (&ML_DEFAULT_NORM, ML_DEFAULT_LOG, 9, 52)];
        for (k, (default_norm, default_log, max_log, default_max)) in kinds.into_iter().enumerate() {
            let count = &mut counts[k];
            let max = (0..64).rev().find(|&s| count[s] > 0).unwrap();
            let most = *count[..=max].iter().max().unwrap() as usize;
            let default_ok = max <= default_max;
            let count = &mut count[..=max];
            let mode = if most == nseq {
                if default_ok && nseq <= 2 {
                    Mode::Basic
                } else {
                    Mode::Rle
                }
            } else if strategy < Strategy::Lazy {
                let min_dynamic = ((1usize << default_log) * (10 - strategy as usize)) >> 3;
                if default_ok && self.fse_repeat[k] == Repeat::Valid && nseq < 1000 {
                    Mode::Repeat
                } else if default_ok && (nseq < min_dynamic || most < (nseq >> (default_log - 1))) {
                    Mode::Basic
                } else {
                    Mode::Compressed
                }
            } else {
                let basic = if default_ok { cross_entropy_cost(default_norm, default_log, count) } else { u64::MAX };
                let repeat = if self.fse_repeat[k] != Repeat::None { self.fse[k].bit_cost(count).map_or(u64::MAX, |c| c >> 8) } else { u64::MAX };
                let compressed = (ncount_cost(count, nseq, max_log) << 3) + entropy_cost(count, nseq);
                if basic <= repeat && basic <= compressed {
                    Mode::Basic
                } else if repeat <= compressed {
                    Mode::Repeat
                } else {
                    Mode::Compressed
                }
            };
            modes |= (mode as u8) << (6 - 2 * k);
            match mode {
                Mode::Basic => self.fse_new[k] = Some(Repeat::None),
                Mode::Rle => {
                    out[at] = codes[0][k];
                    at += 1;
                    self.fse_next[k].build_rle(codes[0][k]);
                    // the table goes to `fse` only with `Check`: an RLE table is not kept
                    self.fse_new[k] = Some(Repeat::None);
                }
                Mode::Compressed => {
                    let mut total = nseq;
                    let table_log = fse::optimal_table_log(max_log, nseq, max, 2);
                    let last = codes[nseq - 1][k] as usize;
                    if count[last] > 1 {
                        count[last] -= 1;
                        total -= 1;
                    }
                    let mut norm = [0i16; 64];
                    fse::normalize(&mut norm, table_log, &*count, total, total >= 2048);
                    let n = fse::write_ncount(&mut out[at..], &norm[..=max], table_log);
                    last_ncount = n;
                    at += n;
                    self.fse_next[k].build(&norm[..=max], table_log);
                    self.fse_new[k] = Some(Repeat::Check);
                }
                Mode::Repeat => {}
            }
        }
        out[modes_at] = modes;
        let table = |k: usize, default: &'static fse::CTable| -> &fse::CTable {
            match (modes >> (6 - 2 * k)) & 3 {
                0 => default,
                3 => &self.fse[k],
                _ => &self.fse_next[k],
            }
        };
        let (llt, oft, mlt) = (table(0, &defaults.ll), table(1, &defaults.of), table(2, &defaults.ml));

        let stream = encode_sequences(&mut out[at..], seqs, codes, llt, oft, mlt);
        if stream == 0 {
            return 0;
        }
        at += stream;
        // decoders before 1.3.4 fail on a table description with a stream of less than 4 bytes
        if last_ncount > 0 && last_ncount + stream < 4 {
            return 0;
        }
        if at >= max_size {
            return 0;
        }
        at
    }

    /// Writes the literals section into `self.out`; returns its size.
    #[inline(always)]
    fn literals(&mut self, lits: &[u8], strategy: Strategy, compression: bool, suspect_uncompressible: bool) -> usize {
        let n = lits.len();
        let out = &mut self.out[..];
        // (a dictionary's table is there without the cost of a description)
        let min_size = if self.huf_repeat == Repeat::Valid { 6 } else { 8usize << (9 - strategy as i32).min(3) };
        if !compression || n < min_size {
            return raw_literals(out, lits);
        }
        let header = 3 + (n >= 1024) as usize + (n >= 16384) as usize;
        let prefer_repeat = strategy < Strategy::Lazy && n <= 1024;
        let single = n < 256 || (self.huf_repeat == Repeat::Valid && header == 3);

        // 0: no gain; else the size of the streams and whether the previous table was used
        let mut compressed = 0usize;
        let mut repeated = false;
        'huf: {
            if prefer_repeat && self.huf_repeat == Repeat::Valid {
                // few literals and a table that has every byte: that one, without a look
                // at the literals
                let body = &mut out[header..];
                let streams = if single { self.huf.encode_1x(lits, body) } else { self.huf.encode_4x(lits, body) };
                if streams != 0 && streams < n - 1 {
                    compressed = streams;
                    repeated = true;
                }
                break 'huf;
            }
            if suspect_uncompressible && n >= 4096 * 10 {
                let mut count = [0u32; 256];
                let (_, a) = huf::histogram(&lits[..4096], &mut count);
                let (_, b) = huf::histogram(&lits[n - 4096..], &mut count);
                if (a + b) as usize <= ((2 * 4096) >> 7) + 4 {
                    break 'huf;
                }
            }
            let mut count = [0u32; 256];
            let (max_symbol, largest) = huf::histogram(lits, &mut count);
            if largest as usize == n {
                return rle_literals(out, lits[0], n);
            }
            if largest as usize <= (n >> 7) + 4 {
                break 'huf;
            }
            let mut repeat = self.huf_repeat;
            if repeat == Repeat::Check && !self.huf.covers(&count, max_symbol) {
                repeat = Repeat::None;
            }
            let body = &mut out[header..];
            let mut table: &huf::CTable = &self.huf;
            let mut at = 0;
            if !(prefer_repeat && repeat != Repeat::None) {
                let limit = estimate::huf_table_log(&mut self.huf_next, &count, max_symbol, n, strategy >= Strategy::BtUltra);
                if !self.huf_next.build(&count, max_symbol, limit) {
                    break 'huf;
                }
                let table_size = self.huf_next.write_table(body);
                if table_size == 0 {
                    break 'huf;
                }
                let use_old = repeat != Repeat::None && {
                    let old = self.huf.estimate(&count, max_symbol);
                    let new = self.huf_next.estimate(&count, max_symbol);
                    old <= table_size + new || table_size + 12 >= n
                };
                if !use_old {
                    if table_size + 12 >= n {
                        break 'huf;
                    }
                    table = &self.huf_next;
                    at = table_size;
                    repeat = Repeat::None;
                }
            }
            repeated = repeat != Repeat::None;
            let streams = if single { table.encode_1x(lits, &mut body[at..]) } else { table.encode_4x(lits, &mut body[at..]) };
            if streams == 0 || at + streams >= n - 1 {
                break 'huf;
            }
            compressed = at + streams;
        }
        if compressed == 0 || compressed >= n - min_gain(n, strategy) {
            return raw_literals(out, lits);
        }
        self.huf_new = !repeated;
        let kind = if repeated { 3u32 } else { 2 };
        let (n32, c32) = (n as u32, compressed as u32);
        match header {
            3 => {
                let h = kind | (!single as u32) << 2 | n32 << 4 | c32 << 14;
                out[..3].copy_from_slice(&h.to_le_bytes()[..3]);
            }
            4 => {
                let h = kind | 2 << 2 | n32 << 4 | c32 << 18;
                out[..4].copy_from_slice(&h.to_le_bytes());
            }
            _ => {
                let h = kind | 3 << 2 | n32 << 4 | c32 << 22;
                out[..4].copy_from_slice(&h.to_le_bytes());
                out[4] = (c32 >> 10) as u8;
            }
        }
        header + compressed
    }
}

/// `LL_BITS` and `ML_BITS` for any code of 6 bits: no code is then looked at for being one
/// of the table where its bits are looked up.
const LL_BITS_64: [u8; 64] = padded(&LL_BITS);
const ML_BITS_64: [u8; 64] = padded(&ML_BITS);

const fn padded(bits: &[u8]) -> [u8; 64] {
    let mut t = [0u8; 64];
    let mut i = 0;
    while i < bits.len() {
        t[i] = bits[i];
        i += 1;
    }
    t
}

/// Writes the sequences' stream, last sequence first; returns its size.
#[inline(always)]
fn encode_sequences(out: &mut [u8], seqs: &[super::seq::Seq], codes: &[[u8; 4]], llt: &fse::CTable, oft: &fse::CTable, mlt: &fse::CTable) -> usize {
    let mut w = BitW::new(out);
    let (Some((seq, seqs)), Some((&[lc, oc, mc, _], codes))) = (seqs.split_last(), codes.split_last()) else {
        return 0;
    };
    let mut sm = mlt.init(mc);
    let mut so = oft.init(oc);
    let mut sl = llt.init(lc);
    w.add(seq.ll as u64, LL_BITS_64[lc as usize & 63] as u32);
    w.flush();
    w.add((seq.ml - 3) as u64, ML_BITS_64[mc as usize & 63] as u32);
    w.flush();
    w.add(seq.off as u64, oc as u32);
    w.flush();
    // (from the last but one back)
    for (seq, &[lc, oc, mc, _]) in seqs.iter().zip(codes).rev() {
        let ll_bits = LL_BITS_64[lc as usize & 63] as u32;
        let ml_bits = ML_BITS_64[mc as usize & 63] as u32;
        let of_bits = oc as u32;
        oft.encode(&mut w, &mut so, oc);
        mlt.encode(&mut w, &mut sm, mc);
        llt.encode(&mut w, &mut sl, lc);
        if of_bits + ml_bits + ll_bits >= 64 - 7 - (9 + 9 + 8) {
            w.flush();
        }
        w.add(seq.ll as u64, ll_bits);
        w.add((seq.ml - 3) as u64, ml_bits);
        if of_bits + ml_bits + ll_bits > 56 {
            w.flush();
        }
        w.add(seq.off as u64, of_bits);
        w.flush();
    }
    mlt.flush_state(&mut w, sm);
    oft.flush_state(&mut w, so);
    llt.flush_state(&mut w, sl);
    w.close()
}

fn raw_literals(out: &mut [u8], lits: &[u8]) -> usize {
    let n = lits.len();
    let header = literals_header(out, 0, n);
    out[header..header + n].copy_from_slice(lits);
    header + n
}

fn rle_literals(out: &mut [u8], byte: u8, n: usize) -> usize {
    let header = literals_header(out, 1, n);
    out[header] = byte;
    header + 1
}

fn literals_header(out: &mut [u8], kind: u32, n: usize) -> usize {
    let n32 = n as u32;
    if n < 32 {
        out[0] = (kind | n32 << 3) as u8;
        1
    } else if n < 4096 {
        out[..2].copy_from_slice(&((kind | 1 << 2 | n32 << 4) as u16).to_le_bytes());
        2
    } else {
        out[..3].copy_from_slice(&(kind | 3 << 2 | n32 << 4).to_le_bytes()[..3]);
        3
    }
}

/// `-log2(x / 256)` in 1/256 bits, for `x` of 0 to 255 (the reference implementation's table).
static INVERSE_PROBABILITY_LOG2: [u32; 256] = [
    0, 2048, 1792, 1642, 1536, 1453, 1386, 1329, 1280, 1236, 1197, 1162, 1130, 1100, 1073, 1047,
    1024, 1001, 980, 960, 941, 923, 906, 889, 874, 859, 844, 830, 817, 804, 791, 779,
    768, 756, 745, 734, 724, 714, 704, 694, 685, 676, 667, 658, 650, 642, 633, 626,
    618, 610, 603, 595, 588, 581, 574, 567, 561, 554, 548, 542, 535, 529, 523, 517,
    512, 506, 500, 495, 489, 484, 478, 473, 468, 463, 458, 453, 448, 443, 438, 434,
    429, 424, 420, 415, 411, 407, 402, 398, 394, 390, 386, 382, 377, 373, 370, 366,
    362, 358, 354, 350, 347, 343, 339, 336, 332, 329, 325, 322, 318, 315, 311, 308,
    305, 302, 298, 295, 292, 289, 286, 282, 279, 276, 273, 270, 267, 264, 261, 258,
    256, 253, 250, 247, 244, 241, 239, 236, 233, 230, 228, 225, 222, 220, 217, 215,
    212, 209, 207, 204, 202, 199, 197, 194, 192, 190, 187, 185, 182, 180, 178, 175,
    173, 171, 168, 166, 164, 162, 159, 157, 155, 153, 151, 149, 146, 144, 142, 140,
    138, 136, 134, 132, 130, 128, 126, 123, 121, 119, 117, 115, 114, 112, 110, 108,
    106, 104, 102, 100, 98, 96, 94, 93, 91, 89, 87, 85, 83, 82, 80, 78,
    76, 74, 73, 71, 69, 67, 66, 64, 62, 61, 59, 57, 55, 54, 52, 50,
    49, 47, 46, 44, 42, 41, 39, 37, 36, 34, 33, 31, 30, 28, 26, 25,
    23, 22, 20, 19, 17, 16, 14, 13, 11, 10, 8, 7, 5, 4, 2, 1,
];

/// The entropy of the counts, in bits.
fn entropy_cost(count: &[u32], total: usize) -> u64 {
    let mut cost = 0u64;
    for &c in count {
        let mut norm = (256 * c as u64 / total as u64) as usize;
        if c != 0 && norm == 0 {
            norm = 1;
        }
        cost += c as u64 * INVERSE_PROBABILITY_LOG2[norm.min(255)] as u64;
    }
    cost >> 8
}

/// The cost in bits of the counts with the table of the normalized distribution `norm`.
fn cross_entropy_cost(norm: &[i16], log: u32, count: &[u32]) -> u64 {
    let shift = 8 - log;
    let mut cost = 0u64;
    for (s, &c) in count.iter().enumerate() {
        let n = if norm[s] == -1 { 1 } else { norm[s] as u32 };
        let n256 = (n << shift) as usize;
        cost += c as u64 * INVERSE_PROBABILITY_LOG2[n256.min(255)] as u64;
    }
    cost >> 8
}

/// The size in bytes of the table description for the counts.
fn ncount_cost(count: &[u32], total: usize, max_log: u32) -> u64 {
    let mut scratch = [0u8; 512];
    let mut norm = [0i16; 64];
    let table_log = fse::optimal_table_log(max_log, total, count.len() - 1, 2);
    fse::normalize(&mut norm, table_log, count, total, total >= 2048);
    fse::write_ncount(&mut scratch, &norm[..count.len()], table_log) as u64
}
