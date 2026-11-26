//! How large a block of given literals and sequences would be, without writing it: what
//! the reference implementation's block splitter compares the two halves of a block with
//! (`ZSTD_buildEntropyStatisticsAndEstimateSubBlockSize`), and its choice of the Huffman
//! table's depth for the strongest strategies (`HUF_optimalTableLog`).
//!
//! The choice of the tables of the sequences' codes is that of `BlockEncoder::encode`,
//! written out again here: a change there belongs here too.

use super::*;
use crate::enc::seq::Seq;

/// The limit of the code lengths of the Huffman table for `count` (`n` symbols in all). With
/// `probe` (the strategies from `btultra` on), every limit is tried, from the smallest
/// possible one up, as long as the table and what it encodes get smaller; `table` is used
/// for that.
pub(super) fn huf_table_log(table: &mut huf::CTable, count: &[u32; 256], max_symbol: usize, n: usize, probe: bool) -> u32 {
    if !probe {
        return fse::optimal_table_log(huf::MAX_BITS, n, max_symbol, 1);
    }
    let cardinality = count[..=max_symbol].iter().filter(|&&c| c != 0).count() as u32;
    let min_log = highbit(cardinality) + 1;
    let mut best_size = usize::MAX - 1;
    let mut best_log = huf::MAX_BITS;
    let mut description = [0u8; 256];
    for log in min_log..=huf::MAX_BITS {
        if !table.build(count, max_symbol, log) {
            continue;
        }
        if table.table_log() < log && log > min_log {
            break;
        }
        let table_size = table.write_table(&mut description);
        if table_size == 0 {
            continue;
        }
        let size = table.estimate(count, max_symbol) + table_size;
        if size > best_size + 1 {
            break;
        }
        if size < best_size {
            best_size = size;
            best_log = log;
        }
    }
    best_log
}

impl BlockEncoder {
    /// About the size of the block of `lits` and `seqs` after the block encoded last, with
    /// its header; `None` if that cannot be said. (`huf_next` and `fse_next` are used.)
    pub(in crate::enc) fn estimate(&mut self, lits: &[u8], seqs: &[Seq], strategy: Strategy) -> Option<usize> {
        Some(self.estimate_literals(lits, strategy)? + self.estimate_sequences(seqs, strategy) + 3)
    }

    fn estimate_literals(&mut self, lits: &[u8], strategy: Strategy) -> Option<usize> {
        let n = lits.len();
        // (too few to try, unless a table is known to fit, as a dictionary's would be)
        if n <= if self.huf_repeat == Repeat::Valid { 6 } else { 63 } {
            return Some(n);
        }
        let mut count = [0u32; 256];
        let (max_symbol, largest) = huf::histogram(lits, &mut count);
        if largest as usize == n {
            return Some(1);
        }
        if largest as usize <= (n >> 7) + 4 {
            return Some(n);
        }
        let repeat = self.huf_repeat != Repeat::None && self.huf.covers(&count, max_symbol);
        let limit = huf_table_log(&mut self.huf_next, &count, max_symbol, n, strategy >= Strategy::BtUltra);
        if !self.huf_next.build(&count, max_symbol, limit) {
            return None;
        }
        let new = self.huf_next.estimate(&count, max_symbol);
        let mut description = [0u8; 256];
        let table_size = self.huf_next.write_table(&mut description);
        if table_size == 0 {
            return None;
        }
        // (the sizes of four streams)
        let more = 3 + (n >= 1024) as usize + (n >= 16384) as usize + if n < 256 { 0 } else { 6 };
        if repeat {
            let old = self.huf.estimate(&count, max_symbol);
            if old < n && (old <= table_size + new || table_size + 12 >= n) {
                return Some(old + more);
            }
        }
        if new + table_size >= n {
            return Some(n);
        }
        Some(new + table_size + more)
    }

    fn estimate_sequences(&mut self, seqs: &[Seq], strategy: Strategy) -> usize {
        let nseq = seqs.len();
        let mut size = 2 + (nseq >= 128) as usize + (nseq >= 0x7f00) as usize;
        let Some(last) = seqs.last() else {
            return size;
        };
        let last = [ll_code(last.ll), highbit(last.off) as u8, ml_code(last.ml - 3)];
        let mut counts = [[0u32; 64]; 3];
        // the bits behind the codes
        let mut extra = [0u64; 3];
        for s in seqs {
            let (l, o, m) = (ll_code(s.ll) as usize & 63, highbit(s.off) as usize & 63, ml_code(s.ml - 3) as usize & 63);
            counts[0][l] += 1;
            counts[1][o] += 1;
            counts[2][m] += 1;
            extra[0] += LL_BITS_64[l] as u64;
            extra[1] += o as u64;
            extra[2] += ML_BITS_64[m] as u64;
        }
        // (default norm, default log, max log, largest symbol allowed for the default)
        type Kind = (&'static [i16], u32, u32, usize);
        let kinds: [Kind; 3] = [(&LL_DEFAULT_NORM, LL_DEFAULT_LOG, 9, 35), (&OF_DEFAULT_NORM, OF_DEFAULT_LOG, 8, 28), (&ML_DEFAULT_NORM, ML_DEFAULT_LOG, 9, 52)];
        for (k, (default_norm, default_log, max_log, default_max)) in kinds.into_iter().enumerate() {
            let max = (0..64).rev().find(|&s| counts[k][s] > 0).unwrap();
            let count = &counts[k][..=max];
            let most = *count.iter().max().unwrap() as usize;
            let default_ok = max <= default_max;
            let mode = if most == nseq {
                if default_ok && nseq <= 2 {
                    Mode::Basic
                } else {
                    Mode::Rle
                }
            } else if strategy < Strategy::Lazy {
                let min_dynamic = ((1usize << default_log) * (10 - strategy as usize)) >> 3;
                if default_ok && (nseq < min_dynamic || most < (nseq >> (default_log - 1))) {
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
            // the bits of the codes with the table of the mode, and the size of its description
            let bits = match mode {
                Mode::Basic => Some(cross_entropy_cost(default_norm, default_log, count)),
                Mode::Rle => {
                    size += 1;
                    Some(0)
                }
                Mode::Repeat => self.fse[k].bit_cost(count).map(|c| c >> 8),
                Mode::Compressed => {
                    let mut total = nseq;
                    let table_log = fse::optimal_table_log(max_log, nseq, max, 2);
                    let mut less = [0u32; 64];
                    less[..=max].copy_from_slice(count);
                    let last = last[k] as usize & 63;
                    if less[last] > 1 {
                        less[last] -= 1;
                        total -= 1;
                    }
                    let mut norm = [0i16; 64];
                    fse::normalize(&mut norm, table_log, &less[..=max], total, total >= 2048);
                    let mut description = [0u8; 512];
                    size += fse::write_ncount(&mut description, &norm[..=max], table_log);
                    self.fse_next[k].build(&norm[..=max], table_log);
                    self.fse_next[k].bit_cost(count).map(|c| c >> 8)
                }
            };
            size += match bits {
                Some(bits) => ((bits + extra[k]) >> 3) as usize,
                None => nseq * 10,
            };
        }
        size
    }
}
