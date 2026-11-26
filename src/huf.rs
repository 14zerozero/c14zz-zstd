//! Huffman coding of literals: the table description (weights), decoding by table lookup
//! with four interleaved streams, and the encoder.

use crate::bits::{BitR, BitW};
use crate::error::{Error, Result};
use crate::fse;
use crate::mem::{highbit, rd64};

/// The longest code of a literals table.
pub(crate) const MAX_BITS: u32 = 11;
const DT_SIZE: usize = 1 << MAX_BITS;

/// A decoding table, always indexed by 11 bits: `symbol << 8 | code length`.
#[derive(Clone)]
pub(crate) struct DTable {
    t: [u16; DT_SIZE],
    /// The table of two symbols at a time, made of `t` when it is first used (`double`).
    t2: [Two; DT_SIZE],
    double: bool,
    /// How often, in 1024 lookups, the 11 bits a lookup sees are two whole codes.
    pairs: u32,
}

/// What the 11 bits of an index decode to, two symbols where two codes are whole in them:
/// the symbols (the first in the low byte), the bits of their codes, and whether they are two. (A
/// field each, of whole bytes: each is one read for the decoder, without shifts.)
#[derive(Clone, Copy)]
#[repr(C)]
struct Two {
    symbols: u16,
    bits: u8,
    /// Two symbols, not one. (A `bool`: the decoder moves on by one more than it, which is
    /// two at most whatever the table.)
    two: bool,
}

impl DTable {
    pub fn new() -> Self {
        DTable { t: [0; DT_SIZE], t2: [Two { symbols: 0, bits: 0, two: false }; DT_SIZE], double: false, pairs: 0 }
    }

    /// Whether `regen` bytes of literals are better decoded two symbols at a time. A lookup
    /// takes about a third longer that way than one of a single symbol (8 instructions
    /// instead of 6) and gives `1 + pairs / 1024` symbols; and the table is to be made, if
    /// it is not there yet. (In 1/1024 of a cycle; estimates that the measured times of the
    /// two decoders on the Silesia files agree with.)
    #[inline]
    pub fn double_gains(&self, regen: usize) -> bool {
        const SINGLE: u64 = 2250;
        const DOUBLE: u64 = 3000;
        const TABLE: u64 = 3500 << 10;
        let double = DOUBLE * 1024 / (1024 + self.pairs as u64);
        double < SINGLE && regen as u64 * (SINGLE - double) > if self.double { 0 } else { TABLE }
    }

    /// Makes the table of two symbols at a time: an entry has the symbol of its index and,
    /// where the bits behind that symbol's code are a whole code as well, that code's.
    #[inline(never)]
    fn make_double(&mut self) {
        let t = &self.t;
        for (i, to) in self.t2.iter_mut().enumerate() {
            let e1 = t[i] as u32;
            let l1 = e1 & 0xff;
            // (the bits behind the first code, with zeros behind them: a code that is whole
            // in them is found at any index that starts with it)
            let e2 = t[(i << l1) & (DT_SIZE - 1)] as u32;
            let l2 = e2 & 0xff;
            *to = if l1 + l2 <= MAX_BITS {
                Two { symbols: (e1 >> 8 | (e2 & 0xff00)) as u16, bits: (l1 + l2) as u8, two: true }
            } else {
                Two { symbols: (e1 >> 8) as u16, bits: l1 as u8, two: false }
            };
        }
        self.double = true;
    }

    /// Reads the table description at the start of `src`; the number of bytes read.
    #[inline(never)]
    pub fn read(&mut self, src: &[u8]) -> Result<usize> {
        let mut weights = [0u8; 256];
        let mut rank = [0u32; 13];
        let (n, table_log, size) = read_weights(src, &mut weights, &mut rank)?;
        // The codes of a weight follow those of the lower weights, in symbol order. The
        // symbols are put in that order first: those of a weight have codes of one length,
        // and their places in the table are then filled by a loop for that length (one loop
        // for all symbols, each with a length of its own, is a branch the processor does
        // not foresee per symbol).
        let scale = MAX_BITS - table_log;
        let mut first = [0usize; 14];
        for w in 0..13 {
            first[w + 1] = first[w] + rank[w] as usize;
        }
        // (the next place of each weight as the counts above: a place is below 256 as long
        // as a symbol goes there, and what the last one of all carries over reaches a
        // weight that has no symbols)
        let mut next = Lanes::default();
        for (w, &first) in first.iter().enumerate().take(13) {
            next.set(w as u8, first as u8);
        }
        let mut sorted = [0u8; 256];
        for (s, &w) in weights[..=n].iter().enumerate() {
            sorted[next.get(w) as usize] = s as u8;
            next.add(w);
        }
        let mut from = 0usize;
        for w in 1..=table_log as usize {
            let symbols = &sorted[first[w]..first[w + 1]];
            let bits = (table_log + 1 - w as u32) as u16;
            let len = 1usize << (w as u32 - 1 + scale);
            let to = &mut self.t[from..from + symbols.len() * len];
            from += symbols.len() * len;
            macro_rules! fill {
                ($len:literal) => {
                    for (to, &s) in to.as_chunks_mut::<$len>().0.iter_mut().zip(symbols) {
                        *to = [(s as u16) << 8 | bits; $len];
                    }
                };
            }
            match len {
                1 => fill!(1),
                2 => fill!(2),
                4 => fill!(4),
                8 => fill!(8),
                16 => fill!(16),
                _ => {
                    for (to, &s) in to.chunks_exact_mut(len).zip(symbols) {
                        to.fill((s as u16) << 8 | bits);
                    }
                }
            }
        }
        debug_assert_eq!(from, DT_SIZE);
        self.double = false;
        // Two codes are whole in 11 bits where their lengths are 11 together at most. The
        // codes of a length are as much of all 11-bit indexes as they are likely to come.
        let mut mass = [0u32; MAX_BITS as usize + 1];
        for (w, &codes) in rank.iter().enumerate().take(table_log as usize + 1).skip(1) {
            let len = table_log as usize + 1 - w;
            mass[len] = codes << (MAX_BITS as usize - len);
        }
        let (mut upto, mut pairs) = ([0u32; MAX_BITS as usize + 1], 0u32);
        for len in 1..=MAX_BITS as usize {
            upto[len] = upto[len - 1] + mass[len];
        }
        for len in 1..MAX_BITS as usize {
            pairs += mass[len] * upto[MAX_BITS as usize - len];
        }
        self.pairs = pairs >> (2 * MAX_BITS - 10);
        Ok(size)
    }

    /// Decodes one stream into the whole of `out`.
    #[inline(always)]
    fn decode_1x(&self, src: &[u8], out: &mut [u8]) -> Result<()> {
        let br = BitR::new(src)?;
        self.finish(br, out)
    }

    #[inline(always)]
    fn finish(&self, mut br: BitR<'_>, out: &mut [u8]) -> Result<()> {
        let (chunks, rest) = out.as_chunks_mut::<4>();
        for c in chunks {
            br.refill();
            for o in c {
                let e = self.t[br.peek_fast(MAX_BITS) as usize];
                br.skip(e as u32 & 0xff);
                *o = (e >> 8) as u8;
            }
        }
        br.refill();
        for o in rest {
            let e = self.t[br.peek_fast(MAX_BITS) as usize];
            br.skip(e as u32 & 0xff);
            *o = (e >> 8) as u8;
        }
        br.refill();
        if !br.finished() {
            return Err(Error::Corrupt("Huffman stream does not end with its data"));
        }
        Ok(())
    }

    /// Decodes four streams behind their jump table into the whole of `out`, two symbols at
    /// a time where the table has two for the bits it sees. (The ends of the streams, and
    /// streams of less than 8 bytes, are decoded symbol by symbol: that is where a stream is
    /// found to end with its data or not, the same way whatever the table.)
    #[inline(always)]
    fn decode_4x_double(&mut self, src: &[u8], out: &mut [u8]) -> Result<()> {
        if src.len() < 10 || out.len() < 6 {
            return Err(Error::Corrupt("Huffman streams too short"));
        }
        let l0 = u16::from_le_bytes([src[0], src[1]]) as usize;
        let l1 = u16::from_le_bytes([src[2], src[3]]) as usize;
        let l2 = u16::from_le_bytes([src[4], src[5]]) as usize;
        let e0 = 6 + l0;
        let e1 = e0 + l1;
        let e2 = e1 + l2;
        if l0 == 0 || l1 == 0 || l2 == 0 || e2 >= src.len() {
            return Err(Error::Corrupt("Huffman jump table"));
        }
        if !(l0 >= 8 && l1 >= 8 && l2 >= 8 && src.len() - e2 >= 8) {
            return self.decode_4x(src, out);
        }
        if !self.double {
            self.make_double();
        }
        let seg = out.len().div_ceil(4);
        let starts = [6, e0, e1, e2];
        let ends = [e0, e1, e2, src.len()];
        let mut ip = [0usize; 4];
        let mut bits = [0u64; 4];
        for k in 0..4 {
            let last = src[ends[k] - 1];
            if last == 0 {
                return Err(Error::Corrupt("bit stream without end mark"));
            }
            ip[k] = ends[k] - 8;
            bits[k] = (rd64(src, ip[k]) | 1) << (last.leading_zeros() + 1);
        }
        // The streams in step, five lookups of each between refills (55 bits at most, with
        // the 7 that may be left 62). A stream's register holds its unread bits at the top
        // and a 1 below them, as in `decode_4x`. A lookup stores two bytes and moves on by
        // one or two: where it was one, the next lookup writes over the second, and the
        // byte behind the last one of a round is written again by the next round or by the
        // end of the stream. A round starts only where each stream has 11 bytes of its part
        // of `out` left: it writes at most that many.
        let t2 = &self.t2;
        let [mut b0, mut b1, mut b2, mut b3] = bits;
        let [mut i0, mut i1, mut i2, mut i3] = ip;
        // where the streams' parts of `out` end, and where each stream is
        let ends_out = [seg, 2 * seg, 3 * seg, out.len()];
        let (mut q0, mut q1, mut q2, mut q3) = (0usize, seg, 2 * seg, 3 * seg);
        #[cfg(feature = "unsafe")]
        let to = out.as_mut_ptr();
        // (the 2 bytes `v` to the place `q` of `out`)
        #[cfg(feature = "unsafe")]
        macro_rules! store {
            ($q:ident, $v:expr) => {
                to.add($q).cast::<[u8; 2]>().write_unaligned($v)
            };
        }
        #[cfg(not(feature = "unsafe"))]
        macro_rules! store {
            ($q:ident, $v:expr) => {
                out[$q..$q + 2].copy_from_slice(&$v)
            };
        }
        loop {
            if i0 < starts[0] + 8 || i1 < starts[1] + 8 || i2 < starts[2] + 8 || i3 < starts[3] + 8 {
                break;
            }
            if ends_out[0] - q0 < 11 || ends_out[1] - q1 < 11 || ends_out[2] - q2 < 11 || ends_out[3] - q3 < 11 {
                break;
            }
            // SAFETY: each stream's place `q` is at least 11 bytes before the end of its part
            // of `out` (just checked; a place is never behind that end: it starts before it
            // and moves on in rounds that start with this check). A round is 5 lookups of a
            // stream, each of which writes the 2 bytes at the stream's place and moves it on
            // by 1 or 2 (`1 + bool`): the last one writes at most the bytes 8 and 9 from where
            // the round started, and leaves the place at most 10 from there. `to` is the
            // start of `out`, which is not used otherwise while it is written through.
            // (Without the feature `unsafe`, each store is checked.)
            macro_rules! round {
                () => {
                macro_rules! lookup {
                    ($b:ident, $q:ident) => {
                        let e = &t2[($b >> (64 - MAX_BITS)) as usize];
                        store!($q, e.symbols.to_le_bytes());
                        $b <<= e.bits & 63;
                        $q += 1 + e.two as usize;
                    };
                }
                lookup!(b0, q0);
                lookup!(b1, q1);
                lookup!(b2, q2);
                lookup!(b3, q3);
                lookup!(b0, q0);
                lookup!(b1, q1);
                lookup!(b2, q2);
                lookup!(b3, q3);
                lookup!(b0, q0);
                lookup!(b1, q1);
                lookup!(b2, q2);
                lookup!(b3, q3);
                lookup!(b0, q0);
                lookup!(b1, q1);
                lookup!(b2, q2);
                lookup!(b3, q3);
                lookup!(b0, q0);
                lookup!(b1, q1);
                lookup!(b2, q2);
                lookup!(b3, q3);
                };
            }
            #[cfg(feature = "unsafe")]
            unsafe {
                round!();
            }
            #[cfg(not(feature = "unsafe"))]
            {
                round!();
            }
            macro_rules! refill {
                ($b:ident, $i:ident) => {
                    let used = $b.trailing_zeros();
                    $i -= (used >> 3) as usize;
                    $b = (rd64(src, $i) | 1) << (used & 7);
                };
            }
            refill!(b0, i0);
            refill!(b1, i1);
            refill!(b2, i2);
            refill!(b3, i3);
        }
        // A stream that has more pairs than the others is at the end of its part of `out`
        // before they are: the others go on in rounds of their own, each as long as it has
        // the bits and the room for one. (The rounds of a stream wait for each other only,
        // not for those of the other streams.)
        let (mut b, mut i, mut q) = ([b0, b1, b2, b3], [i0, i1, i2, i3], [q0, q1, q2, q3]);
        loop {
            let mut rounds = 0;
            for k in 0..4 {
                if i[k] < starts[k] + 8 || ends_out[k] - q[k] < 11 {
                    continue;
                }
                rounds += 1;
                let (mut bits, mut at) = (b[k], q[k]);
                for _ in 0..5 {
                    let e = &t2[(bits >> (64 - MAX_BITS)) as usize];
                    out[at..at + 2].copy_from_slice(&e.symbols.to_le_bytes());
                    bits <<= e.bits & 63;
                    at += 1 + e.two as usize;
                }
                let used = bits.trailing_zeros();
                i[k] -= (used >> 3) as usize;
                b[k] = (rd64(src, i[k]) | 1) << (used & 7);
                q[k] = at;
            }
            if rounds == 0 {
                break;
            }
        }
        // hand what is left to the plain readers
        let (o0, rest) = out.split_at_mut(seg);
        let (o1, rest) = rest.split_at_mut(seg);
        let (o2, o3) = rest.split_at_mut(seg);
        let outs = [&mut o0[q[0]..], &mut o1[q[1] - seg..], &mut o2[q[2] - 2 * seg..], &mut o3[q[3] - 3 * seg..]];
        for (k, o) in outs.into_iter().enumerate() {
            let stream = &src[starts[k]..ends[k]];
            let br = BitR::resume(stream, i[k] - starts[k], b[k].trailing_zeros());
            self.finish(br, o)?;
        }
        Ok(())
    }

    /// Decodes four streams behind their jump table into the whole of `out`.
    #[inline(always)]
    fn decode_4x(&self, src: &[u8], out: &mut [u8]) -> Result<()> {
        if src.len() < 10 || out.len() < 6 {
            return Err(Error::Corrupt("Huffman streams too short"));
        }
        let l0 = u16::from_le_bytes([src[0], src[1]]) as usize;
        let l1 = u16::from_le_bytes([src[2], src[3]]) as usize;
        let l2 = u16::from_le_bytes([src[4], src[5]]) as usize;
        let e0 = 6 + l0;
        let e1 = e0 + l1;
        let e2 = e1 + l2;
        if l0 == 0 || l1 == 0 || l2 == 0 || e2 >= src.len() {
            return Err(Error::Corrupt("Huffman jump table"));
        }
        let seg = out.len().div_ceil(4);
        let (o0, rest) = out.split_at_mut(seg);
        let (o1, rest) = rest.split_at_mut(seg);
        let (o2, o3) = rest.split_at_mut(seg);
        let starts = [6, e0, e1, e2];
        let ends = [e0, e1, e2, src.len()];

        // The streams in step, five symbols of each between refills: a stream's register holds
        // its unread bits at the top, and a 1 below them whose place tells the bits used.
        let mut done = 0usize;
        if l0 >= 8 && l1 >= 8 && l2 >= 8 && src.len() - e2 >= 8 {
            let mut ip = [0usize; 4];
            let mut bits = [0u64; 4];
            for k in 0..4 {
                let last = src[ends[k] - 1];
                if last == 0 {
                    return Err(Error::Corrupt("bit stream without end mark"));
                }
                ip[k] = ends[k] - 8;
                bits[k] = (rd64(src, ip[k]) | 1) << (last.leading_zeros() + 1);
            }
            let t = &self.t;
            // (as arrays: their length is known where they are written)
            let it = o0.as_chunks_mut::<5>().0.iter_mut().zip(o1.as_chunks_mut::<5>().0.iter_mut()).zip(o2.as_chunks_mut::<5>().0.iter_mut()).zip(o3.as_chunks_mut::<5>().0.iter_mut());
            for (((c0, c1), c2), c3) in it {
                if ip[0] < starts[0] + 8 || ip[1] < starts[1] + 8 || ip[2] < starts[2] + 8 || ip[3] < starts[3] + 8 {
                    break;
                }
                macro_rules! sym {
                    ($k:expr, $c:expr, $i:expr) => {
                        let e = t[(bits[$k] >> (64 - MAX_BITS)) as usize];
                        bits[$k] <<= e & 0xff;
                        $c[$i] = (e >> 8) as u8;
                    };
                }
                for i in 0..5 {
                    sym!(0, c0, i);
                    sym!(1, c1, i);
                    sym!(2, c2, i);
                    sym!(3, c3, i);
                }
                for k in 0..4 {
                    let used = bits[k].trailing_zeros();
                    ip[k] -= (used >> 3) as usize;
                    bits[k] = (rd64(src, ip[k]) | 1) << (used & 7);
                }
                done += 5;
            }
            // hand what is left to the plain readers
            let outs = [&mut o0[done..], &mut o1[done..], &mut o2[done..], &mut o3[done..]];
            for (k, o) in outs.into_iter().enumerate() {
                let stream = &src[starts[k]..ends[k]];
                let pos = ip[k] - starts[k];
                let br = BitR::resume(stream, pos, bits[k].trailing_zeros());
                self.finish(br, o)?;
            }
            return Ok(());
        }
        self.decode_1x(&src[6..e0], o0)?;
        self.decode_1x(&src[e0..e1], o1)?;
        self.decode_1x(&src[e1..e2], o2)?;
        self.decode_1x(&src[e2..], o3)
    }
}

/// The decoders as functions of their own, for any processor and (with the feature `unsafe`,
/// which their call needs) for those with BMI2 (the shifts by a variable number of bits need
/// no fixed register there): what a decoder's loop keeps in registers is then its own,
/// whatever is around the call.
/// Reads the weights of a table description at the start of `src`: those of the symbols
/// `0..=n` into `weights` (the last one is not in the description: it completes the
/// others), and how many symbols there are of each weight into `rank`. Returns `n`, the
/// length of the longest code and the number of bytes read.
#[inline(always)]
fn read_weights(src: &[u8], weights: &mut [u8; 256], rank: &mut [u32; 13]) -> Result<(usize, u32, usize)> {
    let &header = src.first().ok_or(Error::Truncated)?;
    let (n, size) = if header >= 128 {
        let n = header as usize - 127;
        let bytes = n.div_ceil(2);
        let packed = src.get(1..1 + bytes).ok_or(Error::Truncated)?;
        for (i, w) in weights[..n].iter_mut().enumerate() {
            *w = (packed[i / 2] >> (4 * (1 - (i & 1)))) & 15;
        }
        (n, 1 + bytes)
    } else {
        let packed = src.get(1..1 + header as usize).ok_or(Error::Truncated)?;
        (read_weights_fse(weights, packed)?, 1 + header as usize)
    };
    // How many symbols have each weight. (Counted in two words, a byte for each of the
    // weights 0 to 7 and 8 to 15, not in an array: most symbols of a small table have
    // the same weight, none, and a count in memory is then read back as soon as it is
    // written, symbol after symbol. There are 255 weights at most: a byte holds a count.)
    let mut lanes = Lanes::default();
    for &w in &weights[..n] {
        lanes.add(w);
    }
    if lanes.above(MAX_BITS) {
        return Err(Error::Corrupt("Huffman weight too large"));
    }
    // the last weight completes the sum to a power of two
    let mut sum = 0u32;
    for (w, rank) in rank.iter_mut().enumerate().take(MAX_BITS as usize + 1) {
        let count = lanes.get(w as u8) as u32;
        *rank += count;
        sum += count * ((1u32 << w) >> 1);
    }
    if sum == 0 {
        return Err(Error::Corrupt("Huffman table without weights"));
    }
    let table_log = highbit(sum) + 1;
    if table_log > MAX_BITS {
        return Err(Error::Corrupt("Huffman table too deep"));
    }
    let rest = (1u32 << table_log) - sum;
    if !rest.is_power_of_two() {
        return Err(Error::Corrupt("Huffman weights do not complete"));
    }
    let last = highbit(rest) + 1;
    weights[n] = last as u8;
    rank[last as usize] += 1;
    if rank[1] < 2 || rank[1] & 1 != 0 {
        return Err(Error::Corrupt("Huffman weights do not complete"));
    }
    Ok((n, table_log, size))
}

macro_rules! decoders {
    ($($method:ident: $any:ident, $bmi2:ident;)*) => {
        $(
            #[inline(never)]
            pub(crate) fn $any(table: &mut DTable, src: &[u8], out: &mut [u8]) -> Result<()> {
                table.$method(src, out)
            }

            #[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
            #[target_feature(enable = "bmi1,bmi2,lzcnt")]
            #[inline(never)]
            pub(crate) fn $bmi2(table: &mut DTable, src: &[u8], out: &mut [u8]) -> Result<()> {
                table.$method(src, out)
            }
        )*
    };
}
decoders! {
    decode_1x: one_any, one_bmi2;
    decode_4x: four_any, four_bmi2;
    decode_4x_double: double_any, double_bmi2;
}

/// A byte for each of the weights 0 to 15 (of 4 bits), in two words that stay in registers.
#[derive(Clone, Copy, Default)]
struct Lanes {
    low: u64,
    high: u64,
}

impl Lanes {
    /// One more of the weight `w`. (What is added to the two words comes from a table: two
    /// reads and two additions, no shift by the weight.)
    #[inline(always)]
    fn add(&mut self, w: u8) {
        const ONE: [[u64; 2]; 16] = {
            let mut t = [[0u64; 2]; 16];
            let mut w = 0;
            while w < 16 {
                t[w][w >> 3] = 1 << (8 * (w & 7));
                w += 1;
            }
            t
        };
        let [low, high] = ONE[w as usize & 15];
        self.low = self.low.wrapping_add(low);
        self.high = self.high.wrapping_add(high);
    }

    #[inline(always)]
    fn set(&mut self, w: u8, v: u8) {
        let at = 8 * (w as u32 & 7);
        if w & 8 == 0 {
            self.low |= (v as u64) << at;
        } else {
            self.high |= (v as u64) << at;
        }
    }

    /// (The word is chosen with a mask: a branch on the weight is one the processor does
    /// not foresee where the weights are on both sides of 8.)
    #[inline(always)]
    fn get(&self, w: u8) -> u8 {
        let high = 0u64.wrapping_sub((w as u64 >> 3) & 1);
        (((self.low & !high) | (self.high & high)) >> (8 * (w as u32 & 7))) as u8
    }

    /// Whether a weight above `max` (7 to 14) was added.
    #[inline(always)]
    fn above(&self, max: u32) -> bool {
        self.high >> (8 * (max - 7)) != 0
    }
}

/// Reads FSE-compressed weights; the number of weights.
fn read_weights_fse(weights: &mut [u8; 256], src: &[u8]) -> Result<usize> {
    let mut norm = [0i16; 13];
    let (n, table_log, used) = fse::read_ncount(&mut norm, 6, src)?;
    let mut table = [fse::DSym::default(); fse::MAX_TABLE_SIZE];
    if !fse::build_dtable(&mut table, &norm[..n], table_log) {
        return Err(Error::Corrupt("FSE table of the Huffman weights"));
    }
    let mut br = BitR::new(&src[used..])?;
    let mask = fse::MAX_TABLE_SIZE - 1;
    let mut s1 = br.read(table_log) as usize;
    let mut s2 = br.read(table_log) as usize;
    br.refill();
    if br.overflown() {
        return Err(Error::Corrupt("Huffman weights stream"));
    }
    let mut count = 0usize;
    // Four weights for a refill while the stream has whole words left: a weight takes 6 bits
    // at most (the table's log), and a refill at 8 bytes or more from the start leaves 57.
    while br.pos >= 8 && count <= 250 {
        br.refill();
        for pair in weights[count..count + 4].as_chunks_mut::<2>().0 {
            let e = table[s1 & mask];
            pair[0] = e.symbol;
            s1 = e.next as usize + br.read(e.nb_bits as u32) as usize;
            let e = table[s2 & mask];
            pair[1] = e.symbol;
            s2 = e.next as usize + br.read(e.nb_bits as u32) as usize;
        }
        count += 4;
    }
    br.refill();
    loop {
        if count > 253 {
            return Err(Error::Corrupt("too many Huffman weights"));
        }
        let e = table[s1 & mask];
        weights[count] = e.symbol;
        count += 1;
        s1 = e.next as usize + br.read(e.nb_bits as u32) as usize;
        br.refill();
        if br.overflown() {
            weights[count] = table[s2 & mask].symbol;
            count += 1;
            break;
        }
        let e = table[s2 & mask];
        weights[count] = e.symbol;
        count += 1;
        s2 = e.next as usize + br.read(e.nb_bits as u32) as usize;
        br.refill();
        if br.overflown() {
            weights[count] = table[s1 & mask].symbol;
            count += 1;
            break;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------------------
// encoding

/// An encoding table.
#[derive(Clone)]
pub(crate) struct CTable {
    /// Per symbol: the code in the low 16 bits, its length above; 0 for a symbol without code.
    codes: [u32; 256],
    /// Per symbol, for the stream writer: the code in the highest bits, its length in the
    /// lowest.
    tops: [u64; 256],
    /// The largest symbol with a code.
    max_symbol: usize,
    /// The longest code's length.
    table_log: u32,
}

/// Counts the bytes of `src`; returns the largest symbol present and the largest count.
#[inline(never)]
pub(crate) fn histogram(src: &[u8], count: &mut [u32; 256]) -> (usize, u32) {
    // four tables: a store to a counter does not wait for the previous store to the same one
    let mut c = [[0u32; 256]; 4];
    let (chunks, rest) = src.as_chunks::<4>();
    for ch in chunks {
        c[0][ch[0] as usize] += 1;
        c[1][ch[1] as usize] += 1;
        c[2][ch[2] as usize] += 1;
        c[3][ch[3] as usize] += 1;
    }
    for &b in rest {
        c[0][b as usize] += 1;
    }
    let mut max_symbol = 0;
    let mut largest = 0;
    for s in 0..256 {
        let n = c[0][s] + c[1][s] + c[2][s] + c[3][s];
        count[s] = n;
        if n > 0 {
            max_symbol = s;
            largest = largest.max(n);
        }
    }
    (max_symbol, largest)
}

impl CTable {
    pub fn new() -> Self {
        CTable { codes: [0; 256], tops: [0; 256], max_symbol: 0, table_log: 0 }
    }

    #[inline(always)]
    fn nb_bits(&self, s: usize) -> u32 {
        self.codes[s] >> 16
    }

    /// Builds the table for `count` (at least two symbols present) with codes of at most
    /// `limit` bits. `false`: no table.
    #[inline(never)]
    pub fn build(&mut self, count: &[u32; 256], max_symbol: usize, limit: u32) -> bool {
        // the symbols present, by count
        let mut sorted = [0u64; 256];
        let mut other = [0u64; 256];
        let mut n = 0;
        let mut largest = 0;
        for (s, &c) in count[..=max_symbol].iter().enumerate() {
            if c > 0 {
                sorted[n] = (c as u64) << 8 | s as u64;
                largest = largest.max(c);
                n += 1;
            }
        }
        debug_assert!(n >= 2);
        // (by count, then symbol: passes of 9 bits of the count each, in which symbols of one
        // count keep their order; cheaper than a comparison sort for many of them. Counts
        // below 512 need one pass.)
        if n < 96 {
            sorted[..n].sort_unstable();
        } else {
            let passes = 1 + (largest >= 512) as u32;
            for pass in 0..passes {
                let shift = 8 + 9 * pass;
                let (from, to) = if pass == 0 { (&sorted, &mut other) } else { (&other, &mut sorted) };
                let mut at = [0u16; 513];
                for &e in &from[..n] {
                    at[((e >> shift) & 511) as usize + 1] += 1;
                }
                for d in 1..513 {
                    at[d] += at[d - 1];
                }
                for &e in &from[..n] {
                    let d = ((e >> shift) & 511) as usize;
                    to[at[d] as usize & 255] = e;
                    at[d] += 1;
                }
            }
            if passes == 1 {
                sorted[..n].copy_from_slice(&other[..n]);
            }
        }
        let sorted = &mut sorted[..n];
        debug_assert!(sorted.windows(2).all(|w| w[0] < w[1]));

        // the tree: leaves 0..n by count, inner nodes after them in the order they are made,
        // which is by count too, so that the two smallest are at the heads of two queues
        let mut weight = [0u64; 512];
        let mut parent = [0u16; 512];
        for (i, &e) in sorted.iter().enumerate() {
            weight[i] = e >> 8;
        }
        let (mut leaf, mut inner) = (0, n);
        for node in n..2 * n - 1 {
            let take = |leaf: &mut usize, inner: &mut usize| {
                if *leaf < n && (*inner >= node || weight[*leaf] <= weight[*inner]) {
                    *leaf += 1;
                    *leaf - 1
                } else {
                    *inner += 1;
                    *inner - 1
                }
            };
            let a = take(&mut leaf, &mut inner);
            let b = take(&mut leaf, &mut inner);
            weight[node] = weight[a] + weight[b];
            parent[a] = node as u16;
            parent[b] = node as u16;
        }
        let root = 2 * n - 2;
        let mut depth = [0u8; 512];
        for node in (0..root).rev() {
            depth[node] = depth[parent[node] as usize] + 1;
        }
        let lens = &mut depth[..n];

        // limit the lengths: cut at the limit, then pay for it with the cheapest symbols
        if lens.iter().any(|&l| l as u32 > limit) {
            let total = 1u32 << limit;
            let mut kraft = 0u32;
            for l in lens.iter_mut() {
                *l = (*l).min(limit as u8);
                kraft += 1 << (limit - *l as u32);
            }
            // the rarest symbol that is not at the limit: those before it are and stay there
            let mut i = 0;
            while kraft > total {
                while i < lens.len() && lens[i] as u32 >= limit {
                    i += 1;
                }
                if i == lens.len() {
                    return false;
                }
                lens[i] += 1;
                kraft -= 1 << (limit - lens[i] as u32);
            }
            while kraft < total {
                // what is left over goes to the most frequent symbol it fits
                let gap = total - kraft;
                let Some(i) = lens.iter().rposition(|&l| l > 1 && (1u32 << (limit - l as u32)) <= gap) else {
                    return false;
                };
                kraft += 1 << (limit - lens[i] as u32);
                lens[i] -= 1;
            }
        }

        // canonical codes: the longest first, within a length in symbol order
        let mut nb_per_rank = [0u16; MAX_BITS as usize + 2];
        let mut table_log = 0;
        for &l in lens.iter() {
            nb_per_rank[l as usize] += 1;
            table_log = table_log.max(l as u32);
        }
        let mut val_per_rank = [0u16; MAX_BITS as usize + 2];
        let mut min = 0u16;
        for r in (1..=table_log as usize).rev() {
            val_per_rank[r] = min;
            min += nb_per_rank[r];
            min >>= 1;
        }
        self.codes = [0; 256];
        self.tops = [0; 256];
        let mut len_of = [0u8; 256];
        for (i, &e) in sorted.iter().enumerate() {
            len_of[(e & 0xff) as usize] = lens[i];
        }
        for (s, &l) in len_of[..=max_symbol].iter().enumerate() {
            if l > 0 {
                self.codes[s] = (l as u32) << 16 | val_per_rank[l as usize] as u32;
                self.tops[s] = (val_per_rank[l as usize] as u64) << (64 - l as u32) | l as u64;
                val_per_rank[l as usize] += 1;
            }
        }
        self.max_symbol = max_symbol;
        self.table_log = table_log;
        true
    }

    /// The table of the description at the start of `src` (as a decoder reads it), for a
    /// table that is known before the data: returns the number of bytes read and whether
    /// every byte has a code.
    pub fn read(&mut self, src: &[u8]) -> Result<(usize, bool)> {
        let mut weights = [0u8; 256];
        let mut rank = [0u32; 13];
        let (n, table_log, size) = read_weights(src, &mut weights, &mut rank)?;
        // canonical codes, as in `build`: the longest first, within a length in symbol order
        let mut val_per_rank = [0u16; MAX_BITS as usize + 2];
        let mut min = 0u16;
        for len in (1..=table_log as usize).rev() {
            val_per_rank[len] = min;
            min += rank[table_log as usize + 1 - len] as u16;
            min >>= 1;
        }
        self.codes = [0; 256];
        self.tops = [0; 256];
        for (s, &w) in weights[..=n].iter().enumerate() {
            if w > 0 {
                let len = table_log as usize + 1 - w as usize;
                self.codes[s] = (len as u32) << 16 | val_per_rank[len] as u32;
                self.tops[s] = (val_per_rank[len] as u64) << (64 - len as u32) | len as u64;
                val_per_rank[len] += 1;
            }
        }
        self.max_symbol = n;
        self.table_log = table_log;
        Ok((size, n == 255 && weights.iter().all(|&w| w > 0)))
    }

    /// The length of the code of `symbol`, 0 if it has none.
    pub fn code_len(&self, symbol: usize) -> u32 {
        self.codes[symbol] >> 16
    }

    /// The length of the longest code.
    pub fn table_log(&self) -> u32 {
        self.table_log
    }

    /// Whether every symbol of `count` has a code.
    pub fn covers(&self, count: &[u32; 256], max_symbol: usize) -> bool {
        max_symbol <= self.max_symbol && (0..=max_symbol).all(|s| count[s] == 0 || self.codes[s] != 0)
    }

    /// The size in bytes of the streams for `count`.
    pub fn estimate(&self, count: &[u32; 256], max_symbol: usize) -> usize {
        let bits: u64 = (0..=max_symbol).map(|s| self.nb_bits(s) as u64 * count[s] as u64).sum();
        (bits >> 3) as usize
    }

    /// Writes the table description into `out` (room: 256 bytes); its size, 0 if it cannot be
    /// described.
    #[inline(never)]
    pub fn write_table(&self, out: &mut [u8]) -> usize {
        let n = self.max_symbol; // the last symbol's weight is implied
        let mut weights = [0u8; 256];
        for (s, w) in weights[..n].iter_mut().enumerate() {
            let nb = self.nb_bits(s);
            *w = if nb == 0 { 0 } else { (self.table_log + 1 - nb) as u8 };
        }
        let weights = &weights[..n];
        let size = compress_weights(weights, &mut out[1..]);
        if size > 1 && size < n / 2 {
            out[0] = size as u8;
            return size + 1;
        }
        if n > 128 {
            return 0;
        }
        out[0] = 128 + (n as u8 - 1);
        for (i, pair) in weights.chunks(2).enumerate() {
            out[1 + i] = pair[0] << 4 | pair.get(1).copied().unwrap_or(0);
        }
        1 + n.div_ceil(2)
    }

    /// Writes `src` as one stream into `buf` (room: `stream_bound`); returns its size, 0 if
    /// it does not fit.
    ///
    /// The way of the reference implementation's writer: the bits of the stream collect at
    /// the top of a word, the latest highest. A code goes in by shifting the word right by
    /// the code's length and putting the code on top: the entry of a symbol has the code in
    /// its highest bits and the length in its lowest. Every code waits for the one before
    /// it this way, so two words are filled side by side, 5 codes each, and the second is
    /// then put on top of the first like one long code.
    #[inline(always)]
    pub fn encode_1x(&self, src: &[u8], buf: &mut [u8]) -> usize {
        debug_assert!(self.table_log <= MAX_BITS);
        if buf.len() < 8 {
            return 0;
        }
        let last = buf.len() - 8;
        let tops = &self.tops;
        let mut word = 0u64;
        // how many bits at the top of `word` are the stream's and not yet in whole bytes in `buf`
        let mut nbits = 0u32;
        let mut pos = 0;
        // stores the stream's bits; up to 7 stay to be stored again with the next ones. (The
        // position stops at the last one 8 bytes can be stored at: a stream that gets there
        // did not fit.)
        macro_rules! flush {
            () => {
                buf[pos..pos + 8].copy_from_slice(&((word >> 1) >> (63 - nbits)).to_le_bytes());
                pos = (pos + (nbits >> 3) as usize).min(last);
                nbits &= 7;
            };
        }
        macro_rules! put {
            ($word:ident, $nbits:ident, $b:expr) => {
                let e = tops[$b as usize];
                $word = ($word >> (e & 63)) | (e & !0xff);
                $nbits += e as u32;
            };
        }
        // last symbol first; 5 codes of at most 11 bits between flushes, with the 7 bits
        // that may be left 62
        let rest = src.len() % 10;
        let (head, tail) = src.split_at(src.len() - rest);
        for (i, &b) in tail.iter().rev().enumerate() {
            if i == 5 {
                flush!();
            }
            put!(word, nbits, b);
        }
        flush!();
        for c in head.rchunks_exact(10) {
            let (mut second, mut second_bits) = (0u64, 0u32);
            put!(word, nbits, c[9]);
            put!(second, second_bits, c[4]);
            put!(word, nbits, c[8]);
            put!(second, second_bits, c[3]);
            put!(word, nbits, c[7]);
            put!(second, second_bits, c[2]);
            put!(word, nbits, c[6]);
            put!(second, second_bits, c[1]);
            put!(word, nbits, c[5]);
            put!(second, second_bits, c[0]);
            flush!();
            word = (word >> second_bits) | second;
            nbits += second_bits;
            flush!();
        }
        // the final 1 bit
        word = (word >> 1) | 1 << 63;
        nbits += 1;
        flush!();
        if pos >= last {
            return 0;
        }
        pos + (nbits > 0) as usize
    }

    /// Writes `src` as four streams behind their jump table into `buf` (room: 6 +
    /// 4 * `stream_bound` of a quarter); returns the size, 0 if a stream is too large
    /// for the jump table.
    #[inline(always)]
    pub fn encode_4x(&self, src: &[u8], buf: &mut [u8]) -> usize {
        debug_assert!(src.len() >= 12);
        let segment = src.len().div_ceil(4);
        let mut at = 6;
        for (i, part) in src.chunks(segment).enumerate() {
            let size = self.encode_1x(part, &mut buf[at..]);
            if size == 0 {
                return 0;
            }
            if i < 3 {
                if size > u16::MAX as usize {
                    return 0;
                }
                buf[i * 2..i * 2 + 2].copy_from_slice(&(size as u16).to_le_bytes());
            }
            at += size;
        }
        at
    }
}

/// Writes the weights FSE-compressed into `out`; the size, 0 if that does not work out.
fn compress_weights(weights: &[u8], out: &mut [u8]) -> usize {
    const MAX_LOG: u32 = 6;
    if weights.len() <= 1 {
        return 0;
    }
    let mut count = [0u32; 13];
    for &w in weights {
        count[w as usize] += 1;
    }
    let max_weight = (0..13).rev().find(|&w| count[w] > 0).unwrap();
    let max_count = *count.iter().max().unwrap() as usize;
    if max_count == weights.len() || max_count == 1 {
        return 0;
    }
    let count = &count[..=max_weight];
    let table_log = fse::optimal_table_log(MAX_LOG, weights.len(), max_weight, 2);
    let mut norm = [0i16; 13];
    fse::normalize(&mut norm, table_log, count, weights.len(), false);
    let norm = &norm[..=max_weight];
    let head = fse::write_ncount(out, norm, table_log);
    let mut ct = fse::CTable::new();
    ct.build(norm, table_log);

    // two states: the symbols at even places are the first one's
    let mut buf = [0u8; 256 + 16];
    let mut w = BitW::new(&mut buf);
    let n = weights.len();
    let (last_even, last_odd) = if n % 2 == 1 { (n - 1, n - 2) } else { (n - 2, n - 1) };
    let mut s1 = ct.init(weights[last_even]);
    let mut s2 = ct.init(weights[last_odd]);
    for i in (0..n.min(last_even).min(last_odd)).rev() {
        if i % 2 == 0 {
            ct.encode(&mut w, &mut s1, weights[i]);
        } else {
            ct.encode(&mut w, &mut s2, weights[i]);
        }
        w.flush();
    }
    ct.flush_state(&mut w, s2);
    ct.flush_state(&mut w, s1);
    let size = w.close();
    out[head..head + size].copy_from_slice(&buf[..size]);
    head + size
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counts of weights in two words against counts in an array.
    #[test]
    fn lanes() {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for round in 0..200 {
            let (mut lanes, mut count) = (Lanes::default(), [0u8; 16]);
            for i in 0..255 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // (all the same in some rounds: a count of 255)
                let w = if round % 8 == 0 { (round / 8 % 16) as u8 } else { (x >> 60) as u8 % (1 + round as u8 % 16) };
                lanes.add(w);
                count[w as usize] += 1;
                if i % 50 == 0 || i == 254 {
                    for w in 0..16 {
                        assert_eq!(lanes.get(w), count[w as usize]);
                    }
                    for max in 7..=14u32 {
                        assert_eq!(lanes.above(max), count[max as usize + 1..].iter().any(|&c| c != 0), "{max}");
                    }
                }
            }
            let mut set = Lanes::default();
            for w in 0..16 {
                set.set(w, count[w as usize]);
            }
            assert_eq!((set.low, set.high), (lanes.low, lanes.high));
        }
    }

    /// The stream writer against one that puts the codes in one by one (`BitW`), and through
    /// the table's description and the decoder back to the data: for the lengths around the
    /// writer's groups, for long and short codes, and into too little room.
    #[test]
    fn stream_writer() {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let more: &[usize] = if cfg!(miri) { &[100] } else { &[100, 1000, 4099, 20011] };
        // (0: all bytes alike often, codes of 8 bits; the others: rarer and rarer symbols,
        // codes up to the limit)
        for skew in [0u32, 1, 2] {
            for len in (2..=45usize).chain(more.iter().copied()) {
                let data: Vec<u8> = (0..len)
                    .map(|_| {
                        let r = next();
                        match skew {
                            0 => r as u8,
                            1 => (r.trailing_zeros() * 7 + (r >> 61) as u32) as u8,
                            _ => r.trailing_zeros().min(40) as u8,
                        }
                    })
                    .collect();
                let mut count = [0u32; 256];
                let (max_symbol, largest) = histogram(&data, &mut count);
                let mut table = CTable::new();
                if largest as usize == len || !table.build(&count, max_symbol, MAX_BITS) {
                    continue;
                }
                let mut buf = vec![0u8; len * 2 + 16];
                let n = table.encode_1x(&data, &mut buf);
                assert!(n > 0);

                let mut plain = vec![0u8; len * 2 + 16];
                let mut w = BitW::new(&mut plain);
                for &b in data.iter().rev() {
                    let e = table.codes[b as usize];
                    w.add((e & 0xffff) as u64, e >> 16);
                    w.flush();
                }
                let m = w.close();
                assert!(buf[..n] == plain[..m], "skew {skew}, {len} bytes");

                let mut description = [0u8; 256];
                let d = table.write_table(&mut description);
                if d > 0 {
                    let mut dt = DTable::new();
                    assert_eq!(dt.read(&description[..d]).unwrap(), d);
                    let mut back = vec![0u8; len];
                    dt.decode_1x(&buf[..n], &mut back).unwrap();
                    assert!(back == data, "skew {skew}, {len} bytes");
                }

                // four streams: two symbols at a time gives what one at a time gives, and
                // refuses what it refuses (a stream cut short, a byte too many)
                if d > 0 && len >= 12 {
                    let mut dt = DTable::new();
                    dt.read(&description[..d]).unwrap();
                    let mut four = vec![0u8; len * 2 + 64];
                    let n4 = table.encode_4x(&data, &mut four);
                    if n4 > 0 {
                        for cut in [0usize, 1] {
                            let src = &four[..n4 - cut];
                            let (mut one, mut two) = (vec![0u8; len], vec![0u8; len]);
                            let r1 = dt.decode_4x(src, &mut one);
                            let r2 = dt.decode_4x_double(src, &mut two);
                            assert_eq!(r1.is_ok(), r2.is_ok(), "skew {skew}, {len} bytes, cut {cut}");
                            if cut == 0 {
                                assert!(r1.is_ok() && one == data && two == data, "skew {skew}, {len} bytes");
                            }
                        }
                        let (mut one, mut two) = (vec![0u8; len + 1], vec![0u8; len + 1]);
                        assert_eq!(dt.decode_4x(&four[..n4], &mut one).is_ok(), dt.decode_4x_double(&four[..n4], &mut two).is_ok());
                    }
                }

                for room in [0, 1, 7, 8, n.saturating_sub(1), n, n + 7, n + 8, n + 9] {
                    let mut small = vec![0xAAu8; room + 4];
                    let k = table.encode_1x(&data, &mut small[..room]);
                    assert!(k == 0 || (k == n && small[..n] == buf[..n]));
                    assert!(k == n || room < n + 9, "room for the stream and a word is enough");
                    assert_eq!(small[room..], [0xAA; 4]);
                }
            }
        }
    }
}
