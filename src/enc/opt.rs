//! The strategies `btopt`, `btultra` and `btultra2`: the reference implementation's optimal
//! parser (`ZSTD_compressBlock_opt_generic`). Where a match is found, all matches of the
//! positions it covers are looked at, each position is given the price in bits of the
//! cheapest way to get there, and the cheapest way to the end is taken. Prices come from
//! counts of the literals and of the sequences' codes so far, which every sequence taken
//! adds to.

use crate::dict::{Counts, EncoderTables};
use super::bt::{Match, Tree, TreeTables, MATCHES, OPT_NUM};
use super::entropy::{ll_code, ml_code};
use super::params::{Params, Strategy};
use super::seq::SeqStore;
use super::Tables;
use crate::dec::block::BLOCK_MAX;
use crate::dec::tables::{LL_BITS, ML_BITS};
use crate::mem::highbit;

/// One bit, as prices count.
const BIT: u32 = 1 << 8;
/// The price of what cannot be.
const MAX_PRICE: i32 = 1 << 30;
/// A first block of up to this many bytes is priced without counts.
const PREDEF_THRESHOLD: usize = 8;

/// A position of the stretch being parsed: the cheapest way found to get there.
#[derive(Clone, Copy, Default)]
struct Optimal {
    /// The price of the stretch up to here.
    price: i32,
    /// The match of that way (`off` as a sequence has it), 0 for none yet, and the
    /// literals behind it up to here.
    off: u32,
    mlen: u32,
    litlen: u32,
    /// The repeat offsets here.
    rep: [u32; 3],
}

/// The counts the prices are made of.
struct Stats {
    lit: [u32; 256],
    ll: [u32; 36],
    ml: [u32; 53],
    of: [u32; 32],
    lit_sum: u32,
    /// 0: nothing counted yet in this frame.
    ll_sum: u32,
    ml_sum: u32,
    of_sum: u32,
    /// The prices of the sums: what a symbol counted once would cost.
    lit_base: u32,
    ll_base: u32,
    ml_base: u32,
    of_base: u32,
    /// Fixed prices, for very small inputs.
    predef: bool,
    /// The frame starts with the counts `dict`, those of its dictionary's tables.
    of_dict: bool,
    dict: Box<Counts>,
}

/// What the optimal parser keeps: the counts of the frame so far and its tables.
pub(crate) struct State {
    stats: Stats,
    table: Vec<Optimal>,
    matches: Vec<Match>,
}

/// The price of a symbol counted `stat` times, to be taken from that of the sum: in whole
/// bits for `btopt` (`LVL` 0), with a fraction for the others.
#[inline(always)]
fn weight<const LVL: u32>(stat: u32) -> u32 {
    let stat = stat + 1;
    let hb = highbit(stat);
    if LVL == 0 {
        hb * BIT
    } else {
        // (the fraction: between 1 and 2, by where the count is between two powers of two)
        hb * BIT + ((stat << 8) >> hb)
    }
}

/// The offsets after a sequence with the offset `off` (as a sequence has it); `ll0`: it has
/// no literals.
#[inline(always)]
pub(crate) fn new_rep(rep: [u32; 3], off: u32, ll0: bool) -> [u32; 3] {
    if off > 3 {
        return [off - 3, rep[0], rep[1]];
    }
    match off - 1 + ll0 as u32 {
        0 => rep,
        1 => [rep[1], rep[0], rep[2]],
        2 => [rep[2], rep[0], rep[1]],
        _ => [rep[0].wrapping_sub(1), rep[0], rep[1]],
    }
}

fn sum(table: &[u32]) -> u32 {
    table.iter().sum()
}

/// Scales the counts down by `shift` bits; `base1`: none becomes 0. Returns their sum.
fn downscale(table: &mut [u32], shift: u32, base1: bool) -> u32 {
    let mut total = 0;
    for t in table.iter_mut() {
        *t = (base1 || *t > 0) as u32 + (*t >> shift);
        total += *t;
    }
    total
}

/// Scales the counts down if their sum is well above `1 << log_target`; returns their sum.
fn scale(table: &mut [u32], log_target: u32) -> u32 {
    let total = sum(table);
    let factor = total >> log_target;
    if factor <= 1 {
        return total;
    }
    downscale(table, highbit(factor), true)
}

impl Stats {
    /// The counts a frame starts with (the first branch of the reference implementation's
    /// `ZSTD_rescaleFreqs`): the literals as the block `src` has them, the codes of the
    /// sequences as sequences usually have them. (Where the reference implementation takes
    /// the counts from a dictionary's tables instead, if there is one.)
    fn init(&mut self, src: &[u8]) {
        if self.of_dict {
            // (not for one frame more than the one they were set for)
            self.lit = self.dict.lit;
            self.ll = self.dict.ll;
            self.ml = self.dict.ml;
            self.of = self.dict.of;
            self.lit_sum = sum(&self.lit);
            self.ll_sum = sum(&self.ll);
            self.ml_sum = sum(&self.ml);
            self.of_sum = sum(&self.of);
            return;
        }
        self.predef = src.len() <= PREDEF_THRESHOLD;
        self.lit = [0; 256];
        for &b in src {
            self.lit[b as usize] += 1;
        }
        self.lit_sum = downscale(&mut self.lit, 8, false);
        self.ll = [1; 36];
        self.ll[0] = 4;
        self.ll[1] = 2;
        self.ll_sum = sum(&self.ll);
        self.ml = [1; 53];
        self.ml_sum = 53;
        self.of = [1; 32];
        self.of[..11].copy_from_slice(&[6, 2, 1, 1, 2, 3, 4, 4, 4, 3, 2]);
        self.of_sum = sum(&self.of);
    }

    /// Makes the counts those a block starts with (`ZSTD_rescaleFreqs`): for the first one
    /// of a frame those of `init`, then those of the blocks before, scaled down so that the
    /// new block's count.
    fn rescale<const LVL: u32>(&mut self, src: &[u8]) {
        self.predef = false;
        if self.ll_sum == 0 {
            self.init(src);
        } else {
            self.lit_sum = scale(&mut self.lit, 12);
            self.ll_sum = scale(&mut self.ll, 11);
            self.ml_sum = scale(&mut self.ml, 11);
            self.of_sum = scale(&mut self.of, 11);
        }
        self.set_base_prices::<LVL>();
    }

    #[inline(always)]
    fn set_base_prices<const LVL: u32>(&mut self) {
        self.lit_base = weight::<LVL>(self.lit_sum);
        self.ll_base = weight::<LVL>(self.ll_sum);
        self.ml_base = weight::<LVL>(self.ml_sum);
        self.of_base = weight::<LVL>(self.of_sum);
    }

    /// The price of the literal `b`, without that of a literal length.
    #[inline(always)]
    fn lit_price<const LVL: u32>(&self, b: u8) -> i32 {
        if self.predef {
            return (6 * BIT) as i32;
        }
        // (no literal is free)
        let price = weight::<LVL>(self.lit[b as usize]).min(self.lit_base.wrapping_sub(BIT));
        self.lit_base.wrapping_sub(price) as i32
    }

    /// The price of the length of `ll` literals.
    #[inline(always)]
    fn ll_price<const LVL: u32>(&self, ll: u32) -> i32 {
        if self.predef {
            return weight::<LVL>(ll) as i32;
        }
        // (a whole block of literals has no code: a bit more than one byte less)
        let (ll, more) = if ll as usize == BLOCK_MAX { (ll - 1, BIT) } else { (ll, 0) };
        let code = ll_code(ll) as usize;
        (more + LL_BITS[code] as u32 * BIT + self.ll_base).wrapping_sub(weight::<LVL>(self.ll[code])) as i32
    }

    /// What one more literal changes in the price of the length of `ll` literals.
    #[inline(always)]
    fn ll_inc_price<const LVL: u32>(&self, ll: u32) -> i32 {
        self.ll_price::<LVL>(ll) - self.ll_price::<LVL>(ll - 1)
    }

    /// The price of a match of `ml` bytes at `off` (as a sequence has it), without that of
    /// the literal length before it.
    #[inline(always)]
    fn match_price<const LVL: u32>(&self, off: u32, ml: u32) -> i32 {
        let of_code = highbit(off);
        let ml_base = ml - 3;
        if self.predef {
            return (weight::<LVL>(ml_base) + (16 + of_code) * BIT) as i32;
        }
        let mut price = of_code * BIT + self.of_base.wrapping_sub(weight::<LVL>(self.of[of_code as usize]));
        if LVL < 2 && of_code >= 20 {
            // far offsets cost the decoder time
            price += (of_code - 19) * 2 * BIT;
        }
        let code = ml_code(ml_base) as usize;
        price += ML_BITS[code] as u32 * BIT + self.ml_base.wrapping_sub(weight::<LVL>(self.ml[code]));
        // (a little more, for fewer sequences)
        (price + BIT / 5) as i32
    }

    /// Counts a sequence.
    #[inline(always)]
    fn update(&mut self, lits: &[u8], off: u32, ml: u32) {
        for &b in lits {
            self.lit[b as usize] += 2;
        }
        self.lit_sum += 2 * lits.len() as u32;
        self.ll[ll_code(lits.len() as u32) as usize] += 1;
        self.ll_sum += 1;
        self.of[highbit(off) as usize & 31] += 1;
        self.of_sum += 1;
        self.ml[ml_code(ml - 3) as usize] += 1;
        self.ml_sum += 1;
    }
}

impl State {
    pub fn new() -> Self {
        let stats = Stats {
            lit: [0; 256],
            ll: [0; 36],
            ml: [0; 53],
            of: [0; 32],
            lit_sum: 0,
            ll_sum: 0,
            ml_sum: 0,
            of_sum: 0,
            lit_base: 0,
            ll_base: 0,
            ml_base: 0,
            of_base: 0,
            predef: false,
            of_dict: false,
            dict: Box::new(Counts { lit: [0; 256], ll: [0; 36], ml: [0; 53], of: [0; 32] }),
        };
        State { stats, table: Vec::new(), matches: Vec::new() }
    }

    /// Forgets the counts: a frame starts.
    pub fn reset(&mut self) {
        self.stats.ll_sum = 0;
        self.stats.of_dict = false;
    }

    /// After `reset`: the frame has a dictionary with the tables `t`. If its Huffman table
    /// is one to use as it is, the frame's first counts are those the tables stand for (as
    /// in the reference implementation's `ZSTD_rescaleFreqs`).
    pub fn reset_with(&mut self, t: &EncoderTables) {
        if let Some(counts) = &t.counts {
            *self.stats.dict = *counts;
            self.stats.of_dict = true;
        }
    }

    /// Whether nothing was counted in this frame yet.
    pub fn is_new(&self) -> bool {
        self.stats.ll_sum == 0
    }
}

/// Whether the first block of a frame of `p` is parsed twice, the first time for its counts
/// only (`btultra2`). `at`: where the block starts in the data at hand, 0 if nothing is
/// before it.
pub(crate) fn seeds(p: &Params, st: &State, at: usize, size: usize) -> bool {
    p.strategy == Strategy::BtUltra2 && st.is_new() && at == 0 && size > PREDEF_THRESHOLD
}

/// The tree of `p` over the tables `t`, for the block `s[start..]` (see [`Tree::new`]).
pub(crate) fn tree<'a, 'b>(t: &'a mut Tables, p: &Params, s: &'b [u8], start: usize, low_idx: u32) -> Tree<'a, 'b> {
    let hash3_log = super::hash3_log(p);
    let tables = TreeTables {
        hash: &mut t.hash[..1 << p.hash_log],
        chain: &mut t.chain[..1 << p.chain_log],
        hash3: &mut t.hash3[..if hash3_log > 0 { 1 << hash3_log } else { 0 }],
        hash_log: p.hash_log,
        hash3_log,
        search_log: p.search_log,
        window_log: t.tree_window_log,
        target_length: p.target_length,
        next_to_update: &mut t.next_to_update,
    };
    Tree::new(tables, s, start, low_idx)
}

/// Finds the sequences of the block `s[start..]` with the optimal parser of `p`'s strategy;
/// `s[..start]` is its history, `low_idx` the index of `s[0]`. `seed`: see [`seeds`]; the
/// block's indexes are then those from `low_idx` plus its size on.
#[allow(clippy::too_many_arguments)]
pub(crate) fn block(t: &mut Tables, st: &mut State, p: &Params, store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize, mut low_idx: u32, seed: bool) {
    if st.table.is_empty() {
        st.table.resize(OPT_NUM + 3, Optimal::default());
        st.matches.resize(MATCHES, Match::default());
    }
    macro_rules! parse {
        ($lvl:literal, $rep:expr) => {{
            let tree = tree(t, p, s, start, low_idx);
            match p.min_match {
                0..=3 => parse::<$lvl, 3>(tree, st, store, $rep, s, start),
                4 => parse::<$lvl, 4>(tree, st, store, $rep, s, start),
                5 => parse::<$lvl, 5>(tree, st, store, $rep, s, start),
                _ => parse::<$lvl, 6>(tree, st, store, $rep, s, start),
            }
        }};
    }
    if seed {
        // The block once for its counts (`ZSTD_initStats_ultra`); then it is new data again,
        // at other indexes: the entries the first pass made are from before it.
        debug_assert!(start == 0);
        let size = s.len();
        parse!(2, &mut rep.clone());
        store.reset(size);
        low_idx = low_idx.wrapping_add(size as u32);
        t.next_to_update = low_idx;
    }
    if p.strategy == Strategy::BtOpt {
        parse!(0, rep)
    } else {
        parse!(2, rep)
    }
}

/// The parser. `LVL`: 0 for `btopt`, 2 for `btultra` and `btultra2`, which look closer;
/// `MLS`: the number of bytes hashed, 3 to 6 (3: matches may have 3 bytes).
#[inline(always)]
fn parse<const LVL: u32, const MLS: u32>(mut tree: Tree<'_, '_>, st: &mut State, store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize) {
    let end = s.len();
    let State { stats, table: opt, matches } = st;
    let opt = &mut opt[..OPT_NUM + 3];
    let matches = &mut matches[..];
    let sufficient_len = tree.sufficient_len();
    let min_match: usize = if MLS == 3 { 3 } else { 4 };
    let mut anchor = start;
    stats.rescale::<LVL>(&s[start..]);
    if end < 8 {
        store.last_literals(&s[anchor..]);
        return;
    }
    // (the last position a match may start at)
    let ilimit = end - 8;
    let mut ip = start + (start == 0) as usize;
    let mut last_stretch = Optimal::default();

    'stretch: while ip < ilimit {
        let mut cur;
        let mut last_pos;
        'forward: {
            // the first match of a stretch
            let litlen = (ip - anchor) as u32;
            let n = tree.all_matches::<MLS>(matches, ip, rep, litlen == 0, min_match);
            if n == 0 {
                ip += 1;
                continue 'stretch;
            }
            // From here on a position's entry is a match and the literals behind it; the
            // literals before the stretch cost the same on every way, but for their length.
            opt[0] = Optimal { price: stats.ll_price::<LVL>(litlen), off: 0, mlen: 0, litlen, rep: *rep };
            let longest = matches[n - 1];
            if longest.len as usize > sufficient_len {
                // long enough to be taken as it is
                last_stretch.litlen = 0;
                last_stretch.mlen = longest.len;
                last_stretch.off = longest.off;
                cur = 0;
                last_pos = longest.len as usize;
                break 'forward;
            }
            let mut pos = 1;
            while pos < min_match {
                opt[pos].price = MAX_PRICE;
                opt[pos].mlen = 0;
                opt[pos].litlen = litlen + pos as u32;
                pos += 1;
            }
            let base_price = opt[0].price + stats.ll_price::<LVL>(0);
            for m in &matches[..n] {
                while pos <= m.len as usize {
                    let o = &mut opt[pos];
                    o.mlen = pos as u32;
                    o.off = m.off;
                    o.litlen = 0;
                    o.price = base_price + stats.match_price::<LVL>(m.off, pos as u32);
                    pos += 1;
                }
            }
            last_pos = pos - 1;
            opt[pos].price = MAX_PRICE;

            // the positions the matches so far reach
            cur = 1;
            while cur <= last_pos {
                let inr = ip + cur;
                {
                    // one more literal, if that is cheaper than what ends here
                    let litlen = opt[cur - 1].litlen + 1;
                    let price = opt[cur - 1].price + stats.lit_price::<LVL>(s[inr - 1]) + stats.ll_inc_price::<LVL>(litlen);
                    if price <= opt[cur].price {
                        let prev_match = opt[cur];
                        opt[cur] = opt[cur - 1];
                        opt[cur].litlen = litlen;
                        opt[cur].price = price;
                        if LVL >= 1 && prev_match.litlen == 0 && stats.ll_inc_price::<LVL>(1) < 0 && inr < end {
                            // the match that ended here, with one literal behind it: cheaper
                            // at the next position?
                            let next_lit = stats.lit_price::<LVL>(s[inr]);
                            let with_1_literal = prev_match.price + next_lit + stats.ll_inc_price::<LVL>(1);
                            let with_more_literals = price + next_lit + stats.ll_inc_price::<LVL>(litlen + 1);
                            if with_1_literal < with_more_literals && with_1_literal < opt[cur + 1].price {
                                let prev = cur - prev_match.mlen as usize;
                                let reps = new_rep(opt[prev].rep, prev_match.off, opt[prev].litlen == 0);
                                opt[cur + 1] = Optimal { price: with_1_literal, litlen: 1, rep: reps, ..prev_match };
                                if last_pos < cur + 1 {
                                    last_pos = cur + 1;
                                }
                            }
                        }
                    }
                }
                if opt[cur].litlen == 0 {
                    // a match ends here: its offset joins the repeat offsets
                    let prev = cur - opt[cur].mlen as usize;
                    opt[cur].rep = new_rep(opt[prev].rep, opt[cur].off, opt[prev].litlen == 0);
                }
                if inr > ilimit {
                    cur += 1;
                    continue;
                }
                if cur == last_pos {
                    break;
                }
                if LVL == 0 && opt[cur + 1].price <= opt[cur].price + (BIT / 2) as i32 {
                    // the next position is as cheap: not worth a search (`btopt`)
                    cur += 1;
                    continue;
                }
                let ll0 = opt[cur].litlen == 0;
                let base_price = opt[cur].price + stats.ll_price::<LVL>(0);
                let reps = opt[cur].rep;
                let n = tree.all_matches::<MLS>(matches, inr, &reps, ll0, min_match);
                if n == 0 {
                    cur += 1;
                    continue;
                }
                let longest = matches[n - 1];
                let longest_len = longest.len as usize;
                if longest_len > sufficient_len || cur + longest_len >= OPT_NUM || inr + longest_len >= end {
                    last_stretch.mlen = longest.len;
                    last_stretch.off = longest.off;
                    last_stretch.litlen = 0;
                    last_pos = cur + longest_len;
                    break 'forward;
                }
                for i in 0..n {
                    let m = matches[i];
                    let start_len = if i > 0 { matches[i - 1].len + 1 } else { min_match as u32 };
                    let mut mlen = m.len;
                    while mlen >= start_len {
                        let pos = cur + mlen as usize;
                        let price = base_price + stats.match_price::<LVL>(m.off, mlen);
                        if pos > last_pos || price < opt[pos].price {
                            while last_pos < pos {
                                // (not the end of a match)
                                last_pos += 1;
                                opt[last_pos].price = MAX_PRICE;
                                opt[last_pos].litlen = 1;
                            }
                            let o = &mut opt[pos];
                            o.mlen = mlen;
                            o.off = m.off;
                            o.litlen = 0;
                            o.price = price;
                        } else if LVL == 0 {
                            // shorter ones of this match will not be cheaper either (`btopt`)
                            break;
                        }
                        mlen -= 1;
                    }
                }
                opt[last_pos + 1].price = MAX_PRICE;
                cur += 1;
            }
            last_stretch = opt[last_pos];
            cur = last_pos - last_stretch.mlen as usize;
        }

        // the cheapest way to `last_pos`: `last_stretch`, which starts at `cur`
        if last_stretch.mlen == 0 {
            // literals only
            ip += last_pos;
            continue;
        }
        if last_stretch.litlen == 0 {
            *rep = new_rep(opt[cur].rep, last_stretch.off, opt[cur].litlen == 0);
        } else {
            *rep = last_stretch.rep;
            cur -= last_stretch.litlen as usize;
        }
        // The way back through the entries, written into the table from `cur + 2` down as
        // sequences (literals, then a match) instead of matches and the literals behind them.
        let store_end = cur + 2;
        let mut store_start = store_end;
        let mut stretch_pos = cur;
        opt[store_end] = last_stretch;
        loop {
            let next = opt[stretch_pos];
            opt[store_start].litlen = next.litlen;
            if next.mlen == 0 {
                break;
            }
            store_start -= 1;
            opt[store_start] = next;
            stretch_pos -= (next.litlen + next.mlen) as usize;
        }
        for o in &opt[store_start..=store_end] {
            let (llen, mlen) = (o.litlen as usize, o.mlen as usize);
            if mlen == 0 {
                // literals only: they stay for the next stretch
                ip = anchor + llen;
                continue;
            }
            stats.update(&s[anchor..anchor + llen], o.off, o.mlen);
            store.store(s, anchor, llen, o.off, mlen);
            anchor += llen + mlen;
            ip = anchor;
        }
        stats.set_base_prices::<LVL>();
    }
    store.last_literals(&s[anchor..]);
}
