//! FSE (tANS) entropy coding: table descriptions, decoding tables, encoding tables.

use crate::bits::BitW;
use crate::error::{Error, Result};
use crate::mem::highbit;

/// The largest table log of the format (literal and match lengths: 9).
pub(crate) const MAX_TABLE_LOG: u32 = 9;
pub(crate) const MAX_TABLE_SIZE: usize = 1 << MAX_TABLE_LOG;
/// The largest symbol of the format's FSE tables (match length codes: 52).
pub(crate) const MAX_SYMBOL: usize = 52;
const MIN_TABLE_LOG: u32 = 5;

/// Reads a table description: the normalized counts of the symbols `0..n` into `norm`
/// (`-1`: a symbol of less than one state). Returns `(n, table log, bytes read)`.
#[inline(never)]
pub(crate) fn read_ncount(norm: &mut [i16], max_table_log: u32, src: &[u8]) -> Result<(usize, u32, usize)> {
    // the bits from bit position `at`, zeros behind the end
    let peek = |at: usize| -> u32 {
        let byte = at >> 3;
        let mut v = 0u64;
        if byte + 8 <= src.len() {
            v = u64::from_le_bytes(src[byte..byte + 8].try_into().unwrap());
        } else {
            for (i, &b) in src[byte.min(src.len())..].iter().enumerate() {
                v |= (b as u64) << (8 * i);
            }
        }
        (v >> (at & 7)) as u32
    };
    let table_log = (peek(0) & 15) + MIN_TABLE_LOG;
    if table_log > max_table_log {
        return Err(Error::Corrupt("FSE table log too large"));
    }
    let mut at = 4usize;
    let mut remaining = (1i32 << table_log) + 1;
    let mut threshold = 1i32 << table_log;
    let mut nb_bits = table_log + 1;
    let mut symbol = 0usize;
    let mut previous0 = false;
    while remaining > 1 {
        if previous0 {
            loop {
                let repeat = peek(at) & 3;
                at += 2;
                symbol += repeat as usize;
                if repeat != 3 {
                    break;
                }
                if symbol > norm.len() {
                    return Err(Error::Corrupt("FSE table with too many symbols"));
                }
            }
        }
        if symbol >= norm.len() {
            return Err(Error::Corrupt("FSE table with too many symbols"));
        }
        let bits = peek(at) as i32;
        let max = (2 * threshold - 1) - remaining;
        let mut count;
        if (bits & (threshold - 1)) < max {
            count = bits & (threshold - 1);
            at += nb_bits as usize - 1;
        } else {
            count = bits & (2 * threshold - 1);
            if count >= threshold {
                count -= max;
            }
            at += nb_bits as usize;
        }
        count -= 1;
        remaining -= count.abs();
        norm[symbol] = count as i16;
        symbol += 1;
        previous0 = count == 0;
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 {
        return Err(Error::Corrupt("FSE table counts exceed the table"));
    }
    let bytes = at.div_ceil(8);
    if bytes > src.len() {
        return Err(Error::Truncated);
    }
    Ok((symbol, table_log, bytes))
}

/// Spreads the symbols of a normalized distribution over the table (the format's order).
/// `symbols` gets the symbol of each state, `next` each symbol's first "next state" value.
/// `false`: the distribution does not fill the table.
const fn spread(norm: &[i16], n: usize, table_log: u32, symbols: &mut [u8; MAX_TABLE_SIZE], next: &mut [u16; MAX_SYMBOL + 1]) -> bool {
    let size = 1usize << table_log;
    let mask = size - 1;
    let step = (size >> 1) + (size >> 3) + 3;
    let mut high = size - 1;
    let mut total = 0usize;
    let mut s = 0;
    while s < n {
        if norm[s] == -1 {
            symbols[high] = s as u8;
            high = high.wrapping_sub(1);
            next[s] = 1;
            total += 1;
        } else {
            if norm[s] < 0 {
                return false;
            }
            next[s] = norm[s] as u16;
            total += norm[s] as usize;
        }
        s += 1;
    }
    if total != size {
        return false;
    }
    let mut pos = 0usize;
    let mut s = 0;
    while s < n {
        let mut i = 0;
        while i < norm[s] {
            symbols[pos] = s as u8;
            pos = (pos + step) & mask;
            while pos > high && high < size {
                pos = (pos + step) & mask;
            }
            i += 1;
        }
        s += 1;
    }
    pos == 0
}

/// `spread` for the tables made while data is decoded or compressed, with the same result.
/// The symbols are laid out in a row first, each as often as it has states, and then go to
/// their places one by one: no loop here runs as long as a symbol's count says, which the
/// processor does not foresee, and a place is no result of the place before. (The places
/// are all of the table in the order of the steps; those at its end, which the symbols of
/// less than one state have, take no symbol of the row, and get theirs afterwards.)
fn spread_runs(norm: &[i16], n: usize, table_log: u32, symbols: &mut [u8; MAX_TABLE_SIZE], next: &mut [u16; MAX_SYMBOL + 1]) -> bool {
    if n > MAX_SYMBOL + 1 || table_log > MAX_TABLE_LOG {
        return false;
    }
    let size = 1usize << table_log;
    let mut row = [0u8; MAX_TABLE_SIZE + 8];
    let mut low = [0u8; MAX_SYMBOL + 1];
    let (mut filled, mut lows) = (0usize, 0usize);
    for (s, (&count, next)) in norm[..n].iter().zip(next.iter_mut()).enumerate() {
        if count < 0 {
            if count != -1 {
                return false;
            }
            low[lows] = s as u8;
            lows += 1;
            *next = 1;
            continue;
        }
        let count = count as usize;
        *next = count as u16;
        if filled + count > size {
            return false;
        }
        // (8 at a time, up to 7 more than the count: the next symbol's start there)
        let mut at = filled;
        filled += count;
        loop {
            row[at..at + 8].copy_from_slice(&[s as u8; 8]);
            at += 8;
            if at >= filled {
                break;
            }
        }
    }
    if filled + lows != size {
        return false;
    }
    let mask = size - 1;
    let step = (size >> 1) + (size >> 3) + 3;
    let (mut pos, mut i) = (0usize, 0usize);
    for _ in 0..size {
        symbols[pos & (MAX_TABLE_SIZE - 1)] = row[i];
        i += (pos < filled) as usize;
        pos = (pos + step) & mask;
    }
    for (to, &s) in symbols[filled..size].iter_mut().rev().zip(&low[..lows]) {
        *to = s;
    }
    true
}

/// A state of a sequence decoding table: the symbol's base value and number of extra bits,
/// the bits to read for the next state and that state's base.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub(crate) struct SeqSym {
    next: u16,
    add_bits: u8,
    nb_bits: u8,
    base: u32,
}

// (Fields of their own, not parts of one word: the next state waits for `nb_bits`, and a
// byte loaded as such is there earlier than one shifted out of a word.)
impl SeqSym {
    pub const fn new(next: u16, add_bits: u8, nb_bits: u8, base: u32) -> Self {
        SeqSym { next, add_bits, nb_bits, base }
    }

    /// The base of the next state.
    #[inline(always)]
    pub fn next(&self) -> usize {
        self.next as usize
    }

    /// The number of bits to add to the base of the value.
    #[inline(always)]
    pub fn add_bits(&self) -> u32 {
        self.add_bits as u32
    }

    /// The number of bits to add to the base of the next state.
    #[inline(always)]
    pub fn nb_bits(&self) -> u32 {
        self.nb_bits as u32
    }

    /// The base of the value.
    #[inline(always)]
    pub fn base(&self) -> usize {
        self.base as usize
    }
}

pub(crate) const SEQ_ZERO: SeqSym = SeqSym::new(0, 0, 0, 0);

/// Builds a sequence decoding table (of 512 places, `1 << table_log` used).
#[inline(never)]
pub(crate) const fn build_seq_table(table: &mut [SeqSym; MAX_TABLE_SIZE], norm: &[i16], n: usize, table_log: u32, base: &[u32], bits: &[u8]) -> bool {
    let mut symbols = [0u8; MAX_TABLE_SIZE];
    let mut next = [0u16; MAX_SYMBOL + 1];
    if n > base.len() || !spread(norm, n, table_log, &mut symbols, &mut next) {
        return false;
    }
    let size = 1usize << table_log;
    let mut u = 0;
    while u < size {
        let s = symbols[u] as usize;
        let x = next[s] as u32;
        next[s] += 1;
        let nb = table_log - (31 - x.leading_zeros());
        table[u] = SeqSym::new(((x << nb) - size as u32) as u16, bits[s], nb as u8, base[s]);
        u += 1;
    }
    true
}

/// `build_seq_table` for the tables of a block, with the same result.
#[inline(never)]
pub(crate) fn seq_table(table: &mut [SeqSym; MAX_TABLE_SIZE], norm: &[i16], n: usize, table_log: u32, base: &[u32], bits: &[u8]) -> bool {
    let mut symbols = [0u8; MAX_TABLE_SIZE];
    let mut next = [0u16; MAX_SYMBOL + 1];
    if n > base.len() || n > bits.len() || !spread_runs(norm, n, table_log, &mut symbols, &mut next) {
        return false;
    }
    let size = 1usize << table_log;
    for (to, &s) in table[..size].iter_mut().zip(&symbols[..size]) {
        let s = s as usize;
        let x = next[s] as u32;
        next[s] += 1;
        let nb = table_log - highbit(x);
        *to = SeqSym::new(((x << nb) - size as u32) as u16, bits[s], nb as u8, base[s]);
    }
    true
}

/// A state of a plain FSE decoding table (the Huffman weights').
#[derive(Clone, Copy, Default)]
pub(crate) struct DSym {
    pub next: u16,
    pub symbol: u8,
    pub nb_bits: u8,
}

/// Builds a plain decoding table.
pub(crate) fn build_dtable(table: &mut [DSym; MAX_TABLE_SIZE], norm: &[i16], table_log: u32) -> bool {
    let mut symbols = [0u8; MAX_TABLE_SIZE];
    let mut next = [0u16; MAX_SYMBOL + 1];
    if !spread_runs(norm, norm.len(), table_log, &mut symbols, &mut next) {
        return false;
    }
    let size = 1usize << table_log;
    for u in 0..size {
        let s = symbols[u] as usize;
        let x = next[s] as u32;
        next[s] += 1;
        let nb = table_log - highbit(x);
        table[u] = DSym { next: ((x << nb) - size as u32) as u16, symbol: s as u8, nb_bits: nb as u8 };
    }
    true
}

// ---------------------------------------------------------------------------------------
// encoding

#[derive(Clone, Copy, Default)]
struct SymbolTT {
    delta_find_state: i32,
    delta_nb_bits: u32,
}

/// An encoding table.
#[derive(Clone)]
pub(crate) struct CTable {
    table_log: u32,
    /// The states, grouped by symbol in order of the symbols.
    state_table: [u16; MAX_TABLE_SIZE],
    symbol_tt: [SymbolTT; 64],
    /// The symbols `0..n_symbols` are the table's.
    n_symbols: usize,
}

/// An encoder state of a table.
#[derive(Clone, Copy)]
pub(crate) struct CState {
    value: u32,
}

impl CTable {
    pub fn new() -> Self {
        CTable { table_log: 0, state_table: [0; MAX_TABLE_SIZE], symbol_tt: [SymbolTT::default(); 64], n_symbols: 0 }
    }

    /// Builds the table of a normalized distribution over the symbols `0..norm.len()`.
    #[inline(never)]
    pub fn build(&mut self, norm: &[i16], table_log: u32) {
        debug_assert!(table_log <= MAX_TABLE_LOG && norm.len() <= MAX_SYMBOL + 1);
        let table_size = 1usize << table_log;
        let mut cumul = [0u32; MAX_SYMBOL + 2];
        let mut symbols = [0u8; MAX_TABLE_SIZE];
        let mut next = [0u16; MAX_SYMBOL + 1];
        let ok = spread_runs(norm, norm.len(), table_log, &mut symbols, &mut next);
        debug_assert!(ok);
        for (s, &n) in norm.iter().enumerate() {
            cumul[s + 1] = cumul[s] + n.unsigned_abs() as u32;
        }
        for (u, &s) in symbols[..table_size].iter().enumerate() {
            let c = &mut cumul[s as usize];
            self.state_table[*c as usize & (MAX_TABLE_SIZE - 1)] = (table_size + u) as u16;
            *c += 1;
        }
        let mut total = 0i32;
        for (s, &n) in norm.iter().enumerate() {
            self.symbol_tt[s] = match n {
                0 => SymbolTT { delta_find_state: 0, delta_nb_bits: ((table_log + 1) << 16) - (1 << table_log) },
                -1 | 1 => {
                    total += 1;
                    SymbolTT { delta_find_state: total - 2, delta_nb_bits: (table_log << 16) - (1 << table_log) }
                }
                n => {
                    let n = n as u32;
                    let max_bits_out = table_log - highbit(n - 1);
                    let min_state_plus = n << max_bits_out;
                    total += n as i32;
                    SymbolTT { delta_find_state: total - 2 * n as i32, delta_nb_bits: (max_bits_out << 16).wrapping_sub(min_state_plus) }
                }
            };
        }
        self.table_log = table_log;
        self.n_symbols = norm.len();
    }

    /// The table of a single symbol: its states cost no bits.
    pub fn build_rle(&mut self, symbol: u8) {
        self.table_log = 0;
        self.n_symbols = 0;
        self.state_table[0] = 0;
        self.state_table[1] = 0;
        self.symbol_tt[symbol as usize] = SymbolTT { delta_find_state: 0, delta_nb_bits: 0 };
    }

    /// The state to start with for the first symbol to encode (the last one decoded).
    #[inline(always)]
    pub fn init(&self, symbol: u8) -> CState {
        let tt = self.symbol_tt[symbol as usize & 63];
        let nb_bits_out = (tt.delta_nb_bits + (1 << 15)) >> 16;
        let value = (nb_bits_out << 16).wrapping_sub(tt.delta_nb_bits);
        let idx = (value >> nb_bits_out) as i32 + tt.delta_find_state;
        CState { value: self.state_table[idx as usize & (MAX_TABLE_SIZE - 1)] as u32 }
    }

    /// Encodes `symbol`: writes the state's low bits, moves the state on.
    #[inline(always)]
    pub fn encode(&self, w: &mut BitW<'_>, state: &mut CState, symbol: u8) {
        let tt = self.symbol_tt[symbol as usize & 63];
        let nb_bits_out = (state.value.wrapping_add(tt.delta_nb_bits)) >> 16;
        w.add(state.value as u64, nb_bits_out);
        let idx = (state.value >> nb_bits_out) as i32 + tt.delta_find_state;
        state.value = self.state_table[idx as usize & (MAX_TABLE_SIZE - 1)] as u32;
    }

    /// Writes the final state.
    #[inline(always)]
    pub fn flush_state(&self, w: &mut BitW<'_>, state: CState) {
        w.add(state.value as u64, self.table_log);
        w.flush();
    }

    /// The cost in bits (times 256) of the symbols counted in `count` with this table, `None`
    /// if a symbol counted has no state.
    pub fn bit_cost(&self, count: &[u32]) -> Option<u64> {
        const ACC: u32 = 8;
        let table_log = self.table_log;
        let table_size = 1u32 << table_log;
        let bad_cost = (table_log + 1) << ACC;
        let mut cost = 0u64;
        for (s, &c) in count.iter().enumerate() {
            if c == 0 {
                continue;
            }
            if s >= self.n_symbols {
                return None;
            }
            let tt = self.symbol_tt[s];
            let min_nb_bits = tt.delta_nb_bits >> 16;
            let threshold = (min_nb_bits + 1) << 16;
            let delta_from_threshold = threshold.wrapping_sub(tt.delta_nb_bits.wrapping_add(table_size));
            let normalized = (delta_from_threshold << ACC) >> table_log;
            let bit_cost = ((min_nb_bits + 1) << ACC).wrapping_sub(normalized);
            if bit_cost >= bad_cost {
                return None;
            }
            cost += c as u64 * bit_cost as u64;
        }
        Some(cost)
    }
}

/// The table log to use for `total` symbols with the largest symbol `max_symbol`: at most
/// `max_log`, less for few symbols (`minus`: 2 for FSE tables, 1 for Huffman).
pub(crate) fn optimal_table_log(max_log: u32, total: usize, max_symbol: usize, minus: u32) -> u32 {
    debug_assert!(total > 1);
    let max_bits_src = highbit(total as u32 - 1).saturating_sub(minus);
    let min_bits_src = highbit(total as u32) + 1;
    let min_bits_symbols = highbit(max_symbol.max(1) as u32) + 2;
    let min_bits = min_bits_src.min(min_bits_symbols);
    max_log.min(max_bits_src).max(min_bits).clamp(MIN_TABLE_LOG, max_log.max(MIN_TABLE_LOG))
}

/// Normalizes `count` (summing up to `total`) to a sum of `1 << table_log`. A single symbol
/// holding everything is not handled here (the caller uses RLE).
#[inline(never)]
pub(crate) fn normalize(norm: &mut [i16], table_log: u32, count: &[u32], total: usize, use_low_prob: bool) {
    const RTB: [u32; 8] = [0, 473195, 504333, 520860, 550000, 700000, 750000, 830000];
    let low_prob_count: i16 = if use_low_prob { -1 } else { 1 };
    let scale = 62 - table_log as u64;
    let step = (1u64 << 62) / total as u64;
    let v_step = 1u64 << (scale - 20);
    let mut still_to_distribute = 1i32 << table_log;
    let mut largest = 0;
    let mut largest_p = 0i16;
    let low_threshold = (total >> table_log) as u32;

    for (s, &c) in count.iter().enumerate() {
        debug_assert!(c as usize != total);
        if c == 0 {
            norm[s] = 0;
        } else if c <= low_threshold {
            norm[s] = low_prob_count;
            still_to_distribute -= 1;
        } else {
            let mut proba = ((c as u64 * step) >> scale) as i16;
            if proba < 8 {
                let rest_to_beat = v_step * RTB[proba as usize] as u64;
                proba += ((c as u64 * step) - ((proba as u64) << scale) > rest_to_beat) as i16;
            }
            if proba > largest_p {
                largest_p = proba;
                largest = s;
            }
            norm[s] = proba;
            still_to_distribute -= proba as i32;
        }
    }
    if -still_to_distribute >= (norm[largest] >> 1) as i32 {
        // corner case: the largest cannot take the correction
        normalize_m2(norm, table_log, count, total, low_prob_count);
    } else {
        norm[largest] += still_to_distribute as i16;
    }
    debug_assert_eq!(norm[..count.len()].iter().map(|n| n.unsigned_abs() as u32).sum::<u32>(), 1 << table_log);
}

fn normalize_m2(norm: &mut [i16], table_log: u32, count: &[u32], mut total: usize, low_prob_count: i16) {
    const NOT_YET_ASSIGNED: i16 = -2;
    let mut distributed = 0u32;
    let low_threshold = (total >> table_log) as u32;
    let mut low_one = ((total * 3) >> (table_log + 1)) as u32;

    for (s, &c) in count.iter().enumerate() {
        if c == 0 {
            norm[s] = 0;
        } else if c <= low_threshold {
            norm[s] = low_prob_count;
            distributed += 1;
            total -= c as usize;
        } else if c <= low_one {
            norm[s] = 1;
            distributed += 1;
            total -= c as usize;
        } else {
            norm[s] = NOT_YET_ASSIGNED;
        }
    }
    let mut to_distribute = (1u32 << table_log) - distributed;
    if to_distribute == 0 {
        return;
    }
    if (total / to_distribute as usize) as u32 > low_one {
        // risk of rounding to zero
        low_one = ((total * 3) / (to_distribute as usize * 2)) as u32;
        for (s, &c) in count.iter().enumerate() {
            if norm[s] == NOT_YET_ASSIGNED && c <= low_one {
                norm[s] = 1;
                distributed += 1;
                total -= c as usize;
            }
        }
        to_distribute = (1u32 << table_log) - distributed;
    }
    if distributed as usize == count.iter().filter(|&&c| c != 0).count() {
        // all are poor: everything left goes to the largest
        let max_v = (0..count.len()).rev().max_by_key(|&s| count[s]).unwrap();
        norm[max_v] += to_distribute as i16;
        return;
    }
    if total == 0 {
        let mut s = 0;
        while to_distribute > 0 {
            if norm[s] > 0 {
                to_distribute -= 1;
                norm[s] += 1;
            }
            s = (s + 1) % count.len();
        }
        return;
    }
    let v_step_log = 62 - table_log as u64;
    let mid = (1u64 << (v_step_log - 1)) - 1;
    let r_step = (((1u64 << v_step_log) * to_distribute as u64) + mid) / total as u64;
    let mut tmp_total = mid;
    for (s, &c) in count.iter().enumerate() {
        if norm[s] == NOT_YET_ASSIGNED {
            let end = tmp_total + c as u64 * r_step;
            let weight = (end >> v_step_log) as u32 - (tmp_total >> v_step_log) as u32;
            debug_assert!(weight >= 1);
            norm[s] = weight.max(1) as i16;
            tmp_total = end;
        }
    }
}

/// Writes the table description of a normalized distribution into `out` (room: 64 bytes for
/// the format's tables); the number of bytes written.
pub(crate) fn write_ncount(out: &mut [u8], norm: &[i16], table_log: u32) -> usize {
    let table_size = 1i32 << table_log;
    let mut bit_stream = 0u32;
    let mut bit_count = 0i32;
    let mut symbol = 0usize;
    let alphabet_size = norm.len();
    let mut previous_is_0 = false;
    let mut at = 0usize;

    bit_stream += table_log - MIN_TABLE_LOG;
    bit_count += 4;

    let mut remaining = table_size + 1;
    let mut threshold = table_size;
    let mut nb_bits = table_log as i32 + 1;

    fn put16(out: &mut [u8], at: &mut usize, bit_stream: &mut u32) {
        out[*at..*at + 2].copy_from_slice(&(*bit_stream as u16).to_le_bytes());
        *at += 2;
        *bit_stream >>= 16;
    }

    while symbol < alphabet_size && remaining > 1 {
        if previous_is_0 {
            let mut start = symbol;
            while symbol < alphabet_size && norm[symbol] == 0 {
                symbol += 1;
            }
            if symbol == alphabet_size {
                break;
            }
            while symbol >= start + 24 {
                start += 24;
                bit_stream += 0xFFFF << bit_count;
                put16(out, &mut at, &mut bit_stream);
            }
            while symbol >= start + 3 {
                start += 3;
                bit_stream += 3 << bit_count;
                bit_count += 2;
            }
            bit_stream += ((symbol - start) as u32) << bit_count;
            bit_count += 2;
            if bit_count > 16 {
                put16(out, &mut at, &mut bit_stream);
                bit_count -= 16;
            }
        }
        let mut count = norm[symbol] as i32;
        symbol += 1;
        let max = (2 * threshold - 1) - remaining;
        remaining -= count.abs();
        count += 1;
        if count >= threshold {
            count += max;
        }
        bit_stream += (count as u32) << bit_count;
        bit_count += nb_bits;
        bit_count -= (count < max) as i32;
        previous_is_0 = count == 1;
        debug_assert!(remaining >= 1);
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
        if bit_count > 16 {
            put16(out, &mut at, &mut bit_stream);
            bit_count -= 16;
        }
    }
    debug_assert_eq!(remaining, 1);
    let bytes = (bit_count as usize).div_ceil(8);
    out[at..at + bytes].copy_from_slice(&bit_stream.to_le_bytes()[..bytes]);
    at + bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ways of spreading give the same table, or both none, for distributions that
    /// fill the table and for ones that do not.
    #[test]
    fn spread_runs_as_spread() {
        let mut x = 0x9E3779B97F4A7C15u64;
        let mut rnd = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 11) % n
        };
        let mut good = 0;
        for round in 0..20000 {
            let table_log = 5 + rnd(5) as u32;
            let size = 1i32 << table_log;
            let n = 1 + rnd(MAX_SYMBOL as u64 + 1) as usize;
            let mut norm = [0i16; MAX_SYMBOL + 1];
            let mut left = size;
            for (s, c) in norm[..n].iter_mut().enumerate() {
                if left == 0 {
                    break;
                }
                *c = match rnd(8) {
                    0 => 0,
                    1 | 2 => -1,
                    3 => 1 + rnd(left as u64) as i16,
                    _ => 1 + rnd((left as u64).min(12)) as i16,
                };
                if s + 1 == n && round % 4 != 0 {
                    *c = left as i16;
                }
                left -= c.unsigned_abs() as i32;
            }
            if round % 50 == 0 {
                norm[rnd(n as u64) as usize] = -2 + rnd(8) as i16;
            }
            let (mut a, mut b) = ([0u8; MAX_TABLE_SIZE], [0u8; MAX_TABLE_SIZE]);
            let (mut na, mut nb) = ([0u16; MAX_SYMBOL + 1], [0u16; MAX_SYMBOL + 1]);
            let ok = spread(&norm, n, table_log, &mut a, &mut na);
            assert_eq!(ok, spread_runs(&norm, n, table_log, &mut b, &mut nb), "{norm:?} {table_log}");
            if ok {
                good += 1;
                assert_eq!(a[..size as usize], b[..size as usize], "{norm:?} {table_log}");
                assert_eq!(na, nb);
            }
        }
        assert!(good > 5000, "{good}");
    }
}
