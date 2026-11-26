//! The binary tree match finders of the strategies `btlazy2`, `btopt`, `btultra` and
//! `btultra2`, after the reference implementation's `ZSTD_insertBt1`, `ZSTD_updateTree` and
//! `ZSTD_insertBtAndGetAllMatches` (the optimal parser's) and `ZSTD_updateDUBT` and
//! `ZSTD_DUBT_findBestMatch` (`btlazy2`'s).
//!
//! The positions of a hash are a binary tree sorted by what follows them in the data, the
//! latest position at its root: a search goes down from the root and takes the tree apart
//! into the positions smaller and larger than the searched one, which becomes the new root.
//! On the way it meets the longest match of every distance class, nearest first. The nodes
//! are in the chain table, two entries (the smaller and the larger child) per position, at
//! the position's index modulo half the table's length: a tree reaches back that far.
//!
//! Entries are indexes like those of the other match finders (see `Tables`): what is not
//! a position of the data at hand, before the one searched and within its window, ends a
//! walk, so entries of earlier frames or from before the window do no harm.

use super::hash::{count, hash_l};
use super::lazy::Finder;
use crate::mem::{highbit, rd32l};

/// The most matches a search gives: each is longer than the one before it, and one of more
/// than `OPT_NUM` bytes ends the search.
pub(crate) const MATCHES: usize = OPT_NUM + 3;

/// The longest stretch the optimal parser looks at as a whole.
pub(crate) const OPT_NUM: usize = 1 << 12;

/// In place of the child of a node whose place in the table may be another position's by now.
const NOWHERE: usize = usize::MAX;

/// The mark of a position of `btlazy2`'s tree that is not sorted in yet (in the place of its
/// larger child; its smaller child's place has the previous position of its hash). No index
/// has this value where a child's is looked at: position 0 of the data is no match there.
const UNSORTED: u32 = 1;

/// The hash of the 3 bytes at `s[p]`, of `log` bits (`lim4`: `s.len() - 4`, and `p` is at
/// most that).
#[inline(always)]
pub(crate) fn hash3(s: &[u8], lim4: usize, p: usize, log: u32) -> usize {
    ((rd32l(s, lim4, p) << 8).wrapping_mul(506832829) >> (32 - log)) as usize
}

/// A match as the optimal parser gets it: `off` as a sequence has it.
#[derive(Clone, Copy, Default)]
pub(crate) struct Match {
    pub off: u32,
    pub len: u32,
}

/// The tables of a tree match finder and the data of a block: `s[start..]` is the block,
/// `s[..start]` its history, `low_idx` the index of `s[0]`.
pub(crate) struct Tree<'a, 'b> {
    /// The root of each hash's tree.
    hash: &'a mut [u32],
    /// The nodes: `2 * (index & bt_mask)` is the place of a position's smaller child, the
    /// next one that of its larger child.
    bt: &'a mut [u32],
    /// The latest position of each hash of 3 bytes (strategies with matches of 3 bytes).
    hash3: &'a mut [u32],
    hash_log: u32,
    hash3_log: u32,
    bt_mask: usize,
    /// How many positions a search compares with, at most.
    compares: u32,
    /// The window's size: matches are at most this far back.
    window: usize,
    /// A match longer than this is taken at once.
    sufficient_len: usize,
    next_to_update: &'a mut u32,
    /// The first position not yet in the tree.
    next: usize,
    /// The first position not yet in `hash3`.
    next3: usize,
    s: &'b [u8],
    /// `s.len() - 8`: up to there 8 bytes can be read.
    lim: usize,
    low_idx: u32,
}

/// What a [`Tree`] is made of.
pub(crate) struct TreeTables<'a> {
    /// `1 << hash_log` entries.
    pub hash: &'a mut [u32],
    /// `1 << chain_log` entries: two per position.
    pub chain: &'a mut [u32],
    /// `1 << hash3_log` entries, or none.
    pub hash3: &'a mut [u32],
    pub hash_log: u32,
    pub hash3_log: u32,
    pub search_log: u32,
    pub window_log: u32,
    pub target_length: u32,
    /// The index of the first position not yet in the tables.
    pub next_to_update: &'a mut u32,
}

impl<'a, 'b> Tree<'a, 'b> {
    /// For the block `s[start..]` with the index `low_idx` of `s[0]`.
    pub fn new(t: TreeTables<'a>, s: &'b [u8], start: usize, low_idx: u32) -> Self {
        assert!(t.chain.len().is_power_of_two() && t.chain.len() >= 4 && t.hash.len() == 1 << t.hash_log);
        assert!(t.hash3.is_empty() || t.hash3.len() == 1 << t.hash3_log);
        // what the previous block left out; after a very long match only the end of it (the
        // reference implementation's limit of the update, in `ZSTD_buildSeqStore`)
        let mut next = t.next_to_update.wrapping_sub(low_idx) as usize;
        if next > start {
            next = start;
        }
        if start > next + 384 {
            next = start - (start - next - 384).min(192);
        }
        Tree {
            bt_mask: t.chain.len() / 2 - 1,
            hash: t.hash,
            bt: t.chain,
            hash3: t.hash3,
            hash_log: t.hash_log,
            hash3_log: t.hash3_log,
            compares: 1 << t.search_log,
            window: 1 << t.window_log,
            sufficient_len: (t.target_length as usize).min(OPT_NUM - 1),
            next_to_update: t.next_to_update,
            next,
            next3: next,
            s,
            lim: s.len().saturating_sub(8),
            low_idx,
        }
    }

    /// A match longer than this is taken at once.
    #[inline(always)]
    pub fn sufficient_len(&self) -> usize {
        self.sufficient_len
    }

    /// The place of the smaller child of the position of index `v`.
    #[inline(always)]
    fn node(&self, v: u32) -> usize {
        2 * (v as usize & self.bt_mask)
    }

    /// Sets a child's place unless it is `NOWHERE`.
    #[inline(always)]
    fn set(&mut self, place: usize, v: u32) {
        if place != NOWHERE {
            self.bt[place] = v;
        }
    }

    /// Puts the position `cur` into the tree of its hash (the reference implementation's
    /// `ZSTD_insertBt1`); `target` is the position the tree is being filled up to. Returns
    /// how many positions to go on by: more than one within long repeats, whose positions
    /// would make the trees deep for little.
    fn insert<const MLS: u32>(&mut self, cur: usize, target: usize) -> usize {
        let s = self.s;
        let end = s.len();
        let base = self.low_idx;
        let h = hash_l::<MLS>(s, self.lim, cur, self.hash_log);
        let cur_v = base.wrapping_add(cur as u32);
        let mut match_v = self.hash[h];
        self.hash[h] = cur_v;
        // (only what is in the window of the last position of the update is needed)
        let window_low = target.saturating_sub(self.window);
        let (mut common_smaller, mut common_larger) = (0usize, 0usize);
        let mut smaller = self.node(cur_v);
        let mut larger = smaller + 1;
        let mut match_end = cur + 8 + 1;
        let mut best = 8;
        let mut compares = self.compares;
        while compares > 0 {
            let m = match_v.wrapping_sub(base) as usize;
            if m >= cur || m < window_low {
                break;
            }
            let next = self.node(match_v);
            // (what both neighbours in the order have in common with `cur`, this one has too)
            let mut len = common_smaller.min(common_larger);
            len += count(s, cur + len, m + len, end);
            if len > best {
                best = len;
                if len > match_end - m {
                    match_end = m + len;
                }
            }
            if cur + len == end {
                // equal up to the end: smaller or larger is not known
                break;
            }
            if s[m + len] < s[cur + len] {
                self.bt[smaller] = match_v;
                common_smaller = len;
                if cur - m >= self.bt_mask {
                    // its node may be another position's soon
                    smaller = NOWHERE;
                    break;
                }
                smaller = next + 1;
                match_v = self.bt[next + 1];
            } else {
                self.bt[larger] = match_v;
                common_larger = len;
                if cur - m >= self.bt_mask {
                    larger = NOWHERE;
                    break;
                }
                larger = next;
                match_v = self.bt[next];
            }
            compares -= 1;
        }
        self.set(smaller, 0);
        self.set(larger, 0);
        let positions = if best > 384 { (best - 384).min(192) } else { 0 };
        positions.max(match_end - (cur + 8))
    }

    /// Puts the positions from the first one not yet in the tree up to `target` (not
    /// included) into it: the reference implementation's `ZSTD_updateTree`. `MLS` is the
    /// number of bytes hashed (3 counts as 4). `target` is at most `s.len() - 8`.
    pub fn update<const MLS: u32>(&mut self, target: usize) {
        let mut p = self.next;
        while p < target {
            p += self.insert::<MLS>(p, target);
        }
        self.next = self.next.max(target);
    }

    /// Puts the positions up to `cur` into `hash3` and returns the entry of `cur`'s hash.
    #[inline(always)]
    fn first_of_hash3(&mut self, cur: usize) -> u32 {
        let s = self.s;
        let lim4 = self.lim + 4;
        let log = self.hash3_log;
        let hash3 = |p: usize| hash3(s, lim4, p, log);
        for p in self.next3..cur {
            self.hash3[hash3(p)] = self.low_idx.wrapping_add(p as u32);
        }
        self.next3 = cur;
        self.hash3[hash3(cur)]
    }

    /// All matches of `cur` worth looking at into `matches`, from the shortest to the
    /// longest, each at the smallest distance found for its length; returns their number.
    /// First the repeat offsets `rep` (`ll0`: no literals before the match, which shifts
    /// them), then, with `MLS` 3, the latest position of the same 3 bytes, then the tree,
    /// into which `cur` goes. Matches have at least `min_match` bytes. `cur` is at most
    /// `s.len() - 8`. (The reference implementation's `ZSTD_btGetAllMatches`.)
    #[inline(always)]
    pub fn all_matches<const MLS: u32>(&mut self, matches: &mut [Match], cur: usize, rep: &[u32; 3], ll0: bool, min_match: usize) -> usize {
        if cur < self.next {
            // within a repeat that was skipped
            return 0;
        }
        self.update::<MLS>(cur);
        self.insert_and_get::<MLS>(matches, cur, rep, ll0, min_match)
    }

    #[inline(always)]
    fn insert_and_get<const MLS: u32>(&mut self, matches: &mut [Match], cur: usize, rep: &[u32; 3], ll0: bool, min_match: usize) -> usize {
        let s = self.s;
        let end = s.len();
        let lim4 = self.lim + 4;
        let base = self.low_idx;
        let sufficient_len = self.sufficient_len;
        let window_low = cur.saturating_sub(self.window);
        let mut best = min_match - 1;
        let mut n = 0;

        // the 3 or 4 first bytes at a position, to compare
        let first = |p: usize| {
            let v = rd32l(s, lim4, p);
            if min_match == 3 {
                v << 8
            } else {
                v
            }
        };
        let ll0 = ll0 as usize;
        for code in ll0..3 + ll0 {
            let offset = if code == 3 { rep[0].wrapping_sub(1) } else { rep[code] } as usize;
            if offset.wrapping_sub(1) < cur && cur - offset >= window_low && first(cur) == first(cur - offset) {
                let len = count(s, cur + min_match, cur + min_match - offset, end) + min_match;
                if len > best {
                    best = len;
                    matches[n] = Match { off: (code - ll0 + 1) as u32, len: len as u32 };
                    n += 1;
                    if len > sufficient_len || cur + len == end {
                        return n;
                    }
                }
            }
        }

        if MLS == 3 && best < 3 {
            let m = self.first_of_hash3(cur).wrapping_sub(base) as usize;
            // (further back, a match of 3 bytes costs more than it gains)
            if m < cur && m >= window_low && cur - m < 1 << 18 {
                let len = count(s, cur, m, end);
                if len >= 3 {
                    best = len;
                    matches[0] = Match { off: (cur - m) as u32 + 3, len: len as u32 };
                    n = 1;
                    if len > sufficient_len || cur + len == end {
                        // (not into the tree)
                        self.next = cur + 1;
                        return 1;
                    }
                }
            }
        }

        let h = hash_l::<MLS>(s, self.lim, cur, self.hash_log);
        let cur_v = base.wrapping_add(cur as u32);
        let mut match_v = self.hash[h];
        self.hash[h] = cur_v;
        let (mut common_smaller, mut common_larger) = (0usize, 0usize);
        let mut smaller = self.node(cur_v);
        let mut larger = smaller + 1;
        // the furthest end of a match: beyond the next 8 bytes within a repeat
        let mut match_end = cur + 8 + 1;
        let mut compares = self.compares;
        while compares > 0 {
            let m = match_v.wrapping_sub(base) as usize;
            if m >= cur || m < window_low {
                break;
            }
            let next = self.node(match_v);
            let mut len = common_smaller.min(common_larger);
            len += count(s, cur + len, m + len, end);
            if len > best {
                if len > match_end - m {
                    match_end = m + len;
                }
                best = len;
                matches[n] = Match { off: (cur - m) as u32 + 3, len: len as u32 };
                n += 1;
                if len > OPT_NUM || cur + len == end {
                    // (equal up to the end: smaller or larger is not known)
                    break;
                }
            }
            if s[m + len] < s[cur + len] {
                self.bt[smaller] = match_v;
                common_smaller = len;
                if cur - m >= self.bt_mask {
                    smaller = NOWHERE;
                    break;
                }
                smaller = next + 1;
                match_v = self.bt[next + 1];
            } else {
                self.bt[larger] = match_v;
                common_larger = len;
                if cur - m >= self.bt_mask {
                    larger = NOWHERE;
                    break;
                }
                larger = next;
                match_v = self.bt[next];
            }
            compares -= 1;
        }
        self.set(smaller, 0);
        self.set(larger, 0);
        // (the positions of a repeat are skipped)
        self.next = match_end - 8;
        n
    }
}

impl Drop for Tree<'_, '_> {
    fn drop(&mut self) {
        *self.next_to_update = self.low_idx.wrapping_add(self.next as u32);
    }
}

/// The match finder of `btlazy2` (the reference implementation's `ZSTD_BtFindBestMatch`):
/// positions go into the tree of their hash unsorted, as a chain; a search sorts those of
/// its hash in first. `MLS`: the number of bytes hashed, 4 to 6.
pub(crate) struct DubtFinder<'a, 'b, const MLS: u32> {
    t: Tree<'a, 'b>,
}

impl<'a, 'b, const MLS: u32> DubtFinder<'a, 'b, MLS> {
    /// For the block `s[start..]` with the index `low_idx` of `s[0]`.
    pub fn new(t: TreeTables<'a>, s: &'b [u8], start: usize, low_idx: u32) -> Self {
        DubtFinder { t: Tree::new(t, s, start, low_idx) }
    }

    /// Puts the positions from the first one not yet in the tables up to `target` (not
    /// included) into them, unsorted: the reference implementation's `ZSTD_updateDUBT`.
    /// `target` is at most `s.len() - 8`.
    pub fn update(&mut self, target: usize) {
        let t = &mut self.t;
        for p in t.next..target {
            let h = hash_l::<MLS>(t.s, t.lim, p, t.hash_log);
            let v = t.low_idx.wrapping_add(p as u32);
            let node = t.node(v);
            t.bt[node] = t.hash[h];
            t.bt[node + 1] = UNSORTED;
            t.hash[h] = v;
        }
        t.next = t.next.max(target);
    }

    /// Sorts the position of index `cur_v`, which is in the tables unsorted, into the tree
    /// below it (`ZSTD_insertDUBT1`). `unsort_limit`: see `find`.
    fn sort_in(&mut self, cur_v: u32, mut compares: u32, unsort_limit: usize) {
        let t = &mut self.t;
        let s = t.s;
        let end = s.len();
        let base = t.low_idx;
        let cur = cur_v.wrapping_sub(base) as usize;
        let window_low = cur.saturating_sub(t.window);
        let (mut common_smaller, mut common_larger) = (0usize, 0usize);
        let mut smaller = t.node(cur_v);
        let mut larger = smaller + 1;
        let mut match_v = t.bt[smaller];
        while compares > 0 {
            let m = match_v.wrapping_sub(base) as usize;
            if m >= cur || m <= window_low {
                break;
            }
            let next = t.node(match_v);
            let mut len = common_smaller.min(common_larger);
            len += count(s, cur + len, m + len, end);
            if cur + len == end {
                break;
            }
            if s[m + len] < s[cur + len] {
                t.bt[smaller] = match_v;
                common_smaller = len;
                if m <= unsort_limit {
                    smaller = NOWHERE;
                    break;
                }
                smaller = next + 1;
                match_v = t.bt[next + 1];
            } else {
                t.bt[larger] = match_v;
                common_larger = len;
                if m <= unsort_limit {
                    larger = NOWHERE;
                    break;
                }
                larger = next;
                match_v = t.bt[next];
            }
            compares -= 1;
        }
        t.set(smaller, 0);
        t.set(larger, 0);
    }
}

impl<const MLS: u32> Finder for DubtFinder<'_, '_, MLS> {
    const TAIL: usize = 8;

    /// (Every position goes into the tables: the tree has no gaps.)
    #[inline(always)]
    fn set_skipping(&mut self, _on: bool) {}

    fn find(&mut self, cur: usize, end: usize) -> (usize, usize) {
        if cur < self.t.next {
            // within a repeat that was skipped
            return (0, 0);
        }
        self.update(cur);
        let s = self.t.s;
        debug_assert!(end == s.len());
        let base = self.t.low_idx;
        let bt_mask = self.t.bt_mask;
        let h = hash_l::<MLS>(s, self.t.lim, cur, self.t.hash_log);
        let cur_v = base.wrapping_add(cur as u32);
        let window_low = cur.saturating_sub(self.t.window);
        // positions up to here are not sorted in: out of the window, or their nodes may be
        // other positions' soon
        let unsort_limit = cur.saturating_sub(bt_mask).max(window_low);
        let within = |v: u32| {
            let m = v.wrapping_sub(base) as usize;
            m < cur && m > unsort_limit
        };

        // the unsorted positions at the head of the hash's chain, turned into a chain back
        // to the latest through the places of their marks
        let mut match_v = self.t.hash[h];
        let mut candidates = self.t.compares;
        let mut previous = 0u32;
        while within(match_v) && self.t.bt[self.t.node(match_v) + 1] == UNSORTED && candidates > 1 {
            let node = self.t.node(match_v);
            self.t.bt[node + 1] = previous;
            previous = match_v;
            match_v = self.t.bt[node];
            candidates -= 1;
        }
        // (more of them than a search compares with: those beyond are dropped)
        if within(match_v) && self.t.bt[self.t.node(match_v) + 1] == UNSORTED {
            let node = self.t.node(match_v);
            self.t.bt[node] = 0;
            self.t.bt[node + 1] = 0;
        }
        // sorted in, the oldest first
        match_v = previous;
        while match_v != 0 {
            let next = self.t.bt[self.t.node(match_v) + 1];
            self.sort_in(match_v, candidates, unsort_limit);
            match_v = next;
            candidates += 1;
        }

        // the search, which makes `cur` the root
        let t = &mut self.t;
        let (mut common_smaller, mut common_larger) = (0usize, 0usize);
        let mut smaller = t.node(cur_v);
        let mut larger = smaller + 1;
        let mut match_end = cur + 8 + 1;
        let mut best = 0usize;
        // (as a sequence has it; the value of the reference implementation's caller before
        // a match is found)
        let mut off_base = 999_999_999u32;
        match_v = t.hash[h];
        t.hash[h] = cur_v;
        let mut compares = t.compares;
        while compares > 0 {
            let m = match_v.wrapping_sub(base) as usize;
            if m >= cur || m <= window_low {
                break;
            }
            let next = t.node(match_v);
            let mut len = common_smaller.min(common_larger);
            len += count(s, cur + len, m + len, end);
            if len > best {
                if len > match_end - m {
                    match_end = m + len;
                }
                // longer, and not too much further back for what it is longer by
                if 4 * (len - best) as i32 > highbit((cur - m) as u32 + 1) as i32 - highbit(off_base) as i32 {
                    best = len;
                    off_base = (cur - m) as u32 + 3;
                }
                if cur + len == end {
                    break;
                }
            }
            if s[m + len] < s[cur + len] {
                t.bt[smaller] = match_v;
                common_smaller = len;
                if cur - m >= bt_mask {
                    smaller = NOWHERE;
                    break;
                }
                smaller = next + 1;
                match_v = t.bt[next + 1];
            } else {
                t.bt[larger] = match_v;
                common_larger = len;
                if cur - m >= bt_mask {
                    larger = NOWHERE;
                    break;
                }
                larger = next;
                match_v = t.bt[next];
            }
            compares -= 1;
        }
        t.set(smaller, 0);
        t.set(larger, 0);
        t.next = match_end - 8;
        (best, off_base.wrapping_sub(3) as usize)
    }
}
