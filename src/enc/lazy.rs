//! The `greedy`, `lazy` and `lazy2` strategies (levels 5 to 12, by input size) after the
//! reference implementation's `ZSTD_compressBlock_lazy` with its row-based match finder:
//! the hash table is made of rows of 16, 32 or 64 positions, each with a byte of its
//! position's hash (the tag); a search compares the tags of a row at once and looks only
//! at the positions whose tag is the searched one, the latest first.

use super::hash::count;
use super::seq::{off_base, SeqStore, REP1};
use crate::mem::{highbit, prefetch, rd32l, rd64l};

pub(crate) const TAG_BITS: u32 = 8;

/// The match finder's tables and where it is.
pub(crate) struct Rows<'a> {
    /// Rows of `1 << ROW_LOG` indexes; the first of a row is not used.
    pub table: &'a mut [u32],
    /// The tags of the rows' positions; the first byte of a row is where its latest is.
    pub tags: &'a mut [u8],
    /// The number of bits that choose a row.
    pub row_hash_log: u32,
    pub search_log: u32,
    /// The index of the first position not yet in the table.
    pub next_to_update: &'a mut u32,
}

/// The hash of `bits` bits of the `MLS` (4 to 6) bytes at `s[p..]` (`lim`: see `rd32l`).
#[inline(always)]
pub(crate) fn hash<const MLS: u32>(s: &[u8], lim: usize, p: usize, bits: u32) -> u32 {
    match MLS {
        5 => ((rd64l(s, lim, p) << 24).wrapping_mul(889523592379) >> (64 - bits)) as u32,
        6 => ((rd64l(s, lim, p) << 16).wrapping_mul(227718039650203) >> (64 - bits)) as u32,
        _ => rd32l(s, lim, p).wrapping_mul(2654435761) >> (32 - bits),
    }
}

/// The places of a row whose tag is `tag`, as bits from the latest place on.
#[inline(always)]
fn tag_mask<const ROW_LOG: u32>(tags: &[u8], tag: u8, head: u32) -> u64 {
    let entries = 1u32 << ROW_LOG;
    let mut m = 0u64;
    for (c, chunk) in tags[..entries as usize].as_chunks::<16>().0.iter().enumerate() {
        m |= (eq_mask(chunk, tag) as u64) << (16 * c);
    }
    if ROW_LOG == 6 {
        m.rotate_right(head)
    } else {
        ((m >> head) | (m << (entries - head))) & ((1u64 << entries) - 1)
    }
}

/// The bytes of `chunk` that are `tag`, as bits: on x86-64 and with the feature `unsafe`,
/// with the comparison of 16 bytes and the instruction that takes their bits. (Written as a loop over the bytes, the
/// compiler made those of it only in some of the finders, and for rows of 16 in none; 8
/// bytes at a time in a word cost 3 to 4 % more time at levels 6 and 9.)
#[inline(always)]
fn eq_mask(chunk: &[u8; 16], tag: u8) -> u32 {
    #[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
    {
        use core::arch::x86_64::{__m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi8};
        // SAFETY: every x86-64 processor has SSE2, all the instructions ask for; the load
        // reads the 16 bytes of `chunk`, unaligned.
        unsafe { _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_loadu_si128(chunk.as_ptr() as *const __m128i), _mm_set1_epi8(tag as i8))) as u32 }
    }
    #[cfg(not(all(feature = "unsafe", target_arch = "x86_64")))]
    {
        let mut m = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            m |= ((b == tag) as u32) << i;
        }
        m
    }
}

/// The next place to fill in a row: places go round backwards, skipping the first.
#[inline(always)]
pub(crate) fn next_place(tag_row: &mut [u8], row_mask: u32) -> usize {
    let mut next = (tag_row[0] as u32).wrapping_sub(1) & row_mask;
    if next == 0 {
        next = row_mask;
    }
    tag_row[0] = next as u8;
    next as usize
}

/// What `block` asks of a match finder.
pub(crate) trait Finder {
    /// Searches start up to this many bytes before the end of the data.
    const TAIL: usize;
    /// The longest match for `ip` of more than 3 bytes among the positions the finder looks
    /// at: `(length, offset)`, or a length of 3 or less. `end` is the end of the data.
    fn find(&mut self, ip: usize, end: usize) -> (usize, usize);
    /// Whether only the positions searched go into the tables (in data that does not
    /// compress).
    fn set_skipping(&mut self, on: bool);
}

/// The tables of the hash chain match finder and where it is.
pub(crate) struct Chains<'a> {
    /// The latest position of each hash.
    pub hash: &'a mut [u32],
    /// By index modulo the length (a power of two): the previous position of the same hash.
    pub chain: &'a mut [u32],
    pub hash_log: u32,
    pub search_log: u32,
    /// The index of the first position not yet in the tables.
    pub next_to_update: &'a mut u32,
}

/// The match finder of small windows (the reference implementation's
/// `ZSTD_HcFindBestMatch`): the positions of a hash are a chain from the latest back.
pub(crate) struct ChainFinder<'a, 'b, const MLS: u32> {
    chains: Chains<'a>,
    s: &'b [u8],
    lim: usize,
    low_idx: u32,
    skipping: bool,
}

impl<'a, 'b, const MLS: u32> ChainFinder<'a, 'b, MLS> {
    /// For the block `s[start..]` with the index `low_idx` of `s[0]`.
    pub fn new(chains: Chains<'a>, s: &'b [u8], start: usize, low_idx: u32) -> Self {
        assert!(chains.chain.len().is_power_of_two() && chains.hash.len() == 1 << chains.hash_log);
        // what the previous block left out, or all of the history that is new to the tables
        if chains.next_to_update.wrapping_sub(low_idx) as usize > start {
            *chains.next_to_update = low_idx.wrapping_add(start as u32);
        }
        ChainFinder { chains, s, lim: s.len().saturating_sub(8), low_idx, skipping: false }
    }
}

impl<const MLS: u32> Finder for ChainFinder<'_, '_, MLS> {
    const TAIL: usize = 8;

    #[inline(always)]
    fn find(&mut self, ip: usize, end: usize) -> (usize, usize) {
        let s = self.s;
        let lim = self.lim;
        let lim4 = lim + 4;
        let low_idx = self.low_idx;
        let hash_log = self.chains.hash_log;
        let hash_table = &mut *self.chains.hash;
        let chain = &mut *self.chains.chain;
        let chain_size = chain.len();
        let chain_mask = chain_size - 1;
        let mut p = self.chains.next_to_update.wrapping_sub(low_idx) as usize;
        while p < ip {
            let h = hash::<MLS>(s, lim, p, hash_log) as usize;
            let idx = low_idx.wrapping_add(p as u32);
            chain[idx as usize & chain_mask] = hash_table[h];
            hash_table[h] = idx;
            p += 1;
            if self.skipping {
                break;
            }
        }
        *self.chains.next_to_update = low_idx.wrapping_add(ip as u32);
        let mut m = hash_table[hash::<MLS>(s, lim, ip, hash_log) as usize];
        let mut attempts = 1u32 << self.chains.search_log;
        let mut ml = 3;
        let mut offset = 0;
        loop {
            let pm = m.wrapping_sub(low_idx) as usize;
            // (not a position of this data: from before it, as are the older ones)
            if pm >= ip || attempts == 0 {
                break;
            }
            if rd32l(s, lim4, pm + ml - 3) == rd32l(s, lim4, ip + ml - 3) {
                let len = count(s, ip, pm, end);
                if len > ml {
                    ml = len;
                    offset = ip - pm;
                    if ip + len == end {
                        break;
                    }
                }
            }
            if ip - pm >= chain_size {
                // its place in the chain is that of a later position by now
                break;
            }
            m = chain[m as usize & chain_mask];
            attempts -= 1;
        }
        (ml, offset)
    }

    #[inline(always)]
    fn set_skipping(&mut self, on: bool) {
        self.skipping = on;
    }
}

/// The row-based match finder (the reference implementation's `ZSTD_RowFindBestMatch`).
pub(crate) struct RowFinder<'a, 'b, const MLS: u32, const ROW_LOG: u32> {
    rows: Rows<'a>,
    s: &'b [u8],
    /// `s.len() - 8`: up to there 8 bytes can be read.
    lim: usize,
    low_idx: u32,
    /// Only the positions searched go into the table (in data that does not compress).
    skipping: bool,
    /// The last position searched from.
    ilimit: usize,
    /// The hashes of the 8 positions from the first one not yet in the table on, by
    /// position modulo 8, unless `skipping`: their rows are on the way to the cache from
    /// the time the hashes are made.
    cache: [u32; 8],
    /// How many of a row's positions a search looks at, at most.
    attempts: u32,
    /// The positions a search found by their tags. (Kept here, not made on each search:
    /// an array of its own would be cleared each time.)
    candidates: [usize; 64],
}

impl<'a, 'b, const MLS: u32, const ROW_LOG: u32> RowFinder<'a, 'b, MLS, ROW_LOG> {
    /// For the block `s[start..]` with the index `low_idx` of `s[0]`.
    pub fn new(rows: Rows<'a>, s: &'b [u8], start: usize, low_idx: u32) -> Self {
        // what the previous block left out, or all of the history that is new to the table
        if rows.next_to_update.wrapping_sub(low_idx) as usize > start {
            *rows.next_to_update = low_idx.wrapping_add(start as u32);
        }
        let attempts = 1u32 << rows.search_log.min(ROW_LOG);
        let mut f = RowFinder { rows, s, lim: s.len().saturating_sub(8), low_idx, skipping: false, ilimit: s.len().saturating_sub(16), cache: [0; 8], attempts, candidates: [0; 64] };
        if s.len() >= 16 {
            f.fill_cache();
        }
        f
    }

    #[inline(always)]
    fn hash(&self, p: usize) -> u32 {
        hash::<MLS>(self.s, self.lim, p, self.rows.row_hash_log + TAG_BITS)
    }

    #[inline(always)]
    fn prefetch_row(&self, h: u32) {
        let row = ((h >> TAG_BITS) << ROW_LOG) as usize;
        prefetch(self.rows.table, row);
        if ROW_LOG >= 5 {
            prefetch(self.rows.table, row + 16);
        }
        prefetch(self.rows.tags, row);
        if ROW_LOG == 6 {
            prefetch(self.rows.tags, row + 32);
        }
    }

    /// Makes the hashes of the positions from `p` on that are searched from, 8 at most.
    #[inline(always)]
    fn fill_cache_from(&mut self, p: usize) {
        let n = if p > self.ilimit { 0 } else { (self.ilimit - p + 1).min(8) };
        for q in p..p + n {
            let h = self.hash(q);
            self.prefetch_row(h);
            self.cache[q & 7] = h;
        }
    }

    fn fill_cache(&mut self) {
        self.fill_cache_from(self.rows.next_to_update.wrapping_sub(self.low_idx) as usize);
    }

    /// The hash of `p`, the first position not yet in the table, from `cache`, where that
    /// of `p + 8` takes its place.
    #[inline(always)]
    fn next_hash(&mut self, p: usize) -> u32 {
        let new = self.hash(p + 8);
        self.prefetch_row(new);
        core::mem::replace(&mut self.cache[p & 7], new)
    }

    const ENTRIES: usize = 1 << ROW_LOG;
    const ROW_MASK: u32 = (1 << ROW_LOG) - 1;

    #[inline(always)]
    fn insert(&mut self, p: usize) {
        let h = self.next_hash(p);
        let row = ((h >> TAG_BITS) << ROW_LOG) as usize;
        let tag_row = &mut self.rows.tags[row..row + Self::ENTRIES];
        let place = next_place(tag_row, Self::ROW_MASK);
        tag_row[place] = h as u8;
        self.rows.table[row + place] = self.low_idx.wrapping_add(p as u32);
    }

    /// Puts the positions up to `ip` into the table; of a long stretch only its start and
    /// its end.
    #[inline(always)]
    fn update(&mut self, ip: usize) {
        let mut p = self.rows.next_to_update.wrapping_sub(self.low_idx) as usize;
        if ip - p > 384 {
            for q in p..p + 96 {
                self.insert(q);
            }
            p = ip - 32;
            self.fill_cache_from(p);
        }
        for q in p..ip {
            self.insert(q);
        }
    }

}

impl<const MLS: u32, const ROW_LOG: u32> Finder for RowFinder<'_, '_, MLS, ROW_LOG> {
    // (8 for the hash of a position and 8 for the hashes kept ahead)
    const TAIL: usize = 16;

    #[inline(always)]
    fn set_skipping(&mut self, on: bool) {
        if self.skipping && !on {
            self.fill_cache();
        }
        self.skipping = on;
    }

    /// (Among the latest positions of the row of `ip`.)
    #[inline(always)]
    fn find(&mut self, ip: usize, end: usize) -> (usize, usize) {
        let s = self.s;
        // (4 bytes can be read up to here)
        let lim4 = self.lim + 4;
        let h = if !self.skipping {
            self.update(ip);
            self.next_hash(ip)
        } else {
            self.hash(ip)
        };
        let row = ((h >> TAG_BITS) << ROW_LOG) as usize;
        let tag = h as u8;
        let tag_row = &mut self.rows.tags[row..row + Self::ENTRIES];
        let table_row = &mut self.rows.table[row..row + Self::ENTRIES];
        let head = tag_row[0] as u32 & Self::ROW_MASK;
        let mut matches = tag_mask::<ROW_LOG>(tag_row, tag, head);
        let mut attempts = self.attempts;
        let candidates = &mut self.candidates;
        let mut n = 0;
        while matches != 0 && attempts > 0 {
            let place = ((head + matches.trailing_zeros()) & Self::ROW_MASK) as usize;
            matches &= matches - 1;
            if place == 0 {
                continue;
            }
            let p = table_row[place].wrapping_sub(self.low_idx) as usize;
            if p >= ip {
                // from before this data: so are the older ones
                break;
            }
            prefetch(s, p);
            candidates[n & 63] = p;
            n += 1;
            attempts -= 1;
        }
        // the position itself, so that the next search does not have to
        let place = next_place(tag_row, Self::ROW_MASK);
        tag_row[place] = tag;
        table_row[place] = self.low_idx.wrapping_add(ip as u32);
        *self.rows.next_to_update = self.low_idx.wrapping_add(ip as u32 + 1);

        let mut ml = 3;
        let mut offset = 0;
        // (the 4 bytes up to the end of the longest match so far: a longer one has them)
        let mut last4 = rd32l(s, lim4, ip);
        for &p in &candidates[..n] {
            if rd32l(s, lim4, p + ml - 3) == last4 {
                let len = count(s, ip, p, end);
                if len > ml {
                    ml = len;
                    offset = ip - p;
                    if ip + len == end {
                        break;
                    }
                    last4 = rd32l(s, lim4, ip + ml - 3);
                }
            }
        }
        (ml, offset)
    }
}

/// Finds the sequences of the block `s[start..]` with the match finder `f` made for it;
/// `s[..start]` is its history. `DEPTH`: how many positions further a better match is looked
/// for before one is taken (0: greedy, 1: lazy, 2: lazy2).
pub(crate) fn block<F: Finder, const DEPTH: u32>(mut f: F, store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize) {
    let end = s.len();
    let mut anchor = start;
    if end - start < F::TAIL + 8 {
        store.last_literals(&s[anchor..]);
        return;
    }
    let ilimit = end - F::TAIL;
    let lim = end - 8;

    let mut ip = start + (start == 0) as usize;
    let (mut rep1, mut rep2) = (rep[0] as usize, rep[1] as usize);
    let (mut saved1, mut saved2) = (0, 0);
    if rep2 > ip {
        saved2 = rep2;
        rep2 = 0;
    }
    if rep1 > ip {
        saved1 = rep1;
        rep1 = 0;
    }
    // the gain of a match of `ml` bytes at an offset (as a sequence has it) in thirds or
    // quarters of bytes
    let gain = |ml: usize, off_base: usize, per_byte: i32| ml as i32 * per_byte - highbit(off_base as u32) as i32;

    while ip < ilimit {
        let mut ml = 0;
        let mut off = 0; // 0: the repeat offset
        let mut at = ip + 1;
        let mut have = false;
        if rep1 > 0 && rd32l(s, lim, ip + 1 - rep1) == rd32l(s, lim, ip + 1) {
            ml = count(s, ip + 5, ip + 5 - rep1, end) + 4;
            have = DEPTH == 0;
        }
        if !have {
            let (ml2, off2) = f.find(ip, end);
            if ml2 > ml {
                ml = ml2;
                at = ip;
                off = off2;
            }
            if ml < 4 {
                // faster through data without matches
                let step = ((ip - anchor) >> 8) + 1;
                ip += step;
                f.set_skipping(step > 8);
                continue;
            }
            // a better match one or two positions on?
            if DEPTH >= 1 {
                while ip < ilimit {
                    ip += 1;
                    let ofb = if off == 0 { 1 } else { off + 3 };
                    if rep1 > 0 && rd32l(s, lim, ip) == rd32l(s, lim, ip - rep1) {
                        let ml_rep = count(s, ip + 4, ip + 4 - rep1, end) + 4;
                        if ml_rep as i32 * 3 > gain(ml, ofb, 3) + 1 {
                            ml = ml_rep;
                            off = 0;
                            at = ip;
                        }
                    }
                    let ofb = if off == 0 { 1 } else { off + 3 };
                    let (ml2, off2) = f.find(ip, end);
                    if ml2 >= 4 && gain(ml2, off2 + 3, 4) > gain(ml, ofb, 4) + 4 {
                        ml = ml2;
                        off = off2;
                        at = ip;
                        continue;
                    }
                    if DEPTH == 2 && ip < ilimit {
                        ip += 1;
                        if rep1 > 0 && rd32l(s, lim, ip) == rd32l(s, lim, ip - rep1) {
                            let ml_rep = count(s, ip + 4, ip + 4 - rep1, end) + 4;
                            if ml_rep as i32 * 4 > gain(ml, ofb, 4) + 1 {
                                ml = ml_rep;
                                off = 0;
                                at = ip;
                            }
                        }
                        let ofb = if off == 0 { 1 } else { off + 3 };
                        let (ml2, off2) = f.find(ip, end);
                        if ml2 >= 4 && gain(ml2, off2 + 3, 4) > gain(ml, ofb, 4) + 7 {
                            ml = ml2;
                            off = off2;
                            at = ip;
                            continue;
                        }
                    }
                    break;
                }
            }
            if off != 0 {
                while at > anchor && at > off && s[at - 1] == s[at - off - 1] {
                    at -= 1;
                    ml += 1;
                }
                rep2 = rep1;
                rep1 = off;
            }
        }
        store.store(s, anchor, at - anchor, if off == 0 { REP1 } else { off_base(off as u32) }, ml);
        ip = at + ml;
        anchor = ip;
        f.set_skipping(false);
        while ip <= ilimit && rep2 > 0 && rd32l(s, lim, ip) == rd32l(s, lim, ip - rep2) {
            let rlen = count(s, ip + 4, ip + 4 - rep2, end) + 4;
            core::mem::swap(&mut rep1, &mut rep2);
            store.store(s, anchor, 0, REP1, rlen);
            ip += rlen;
            anchor = ip;
        }
    }

    let saved2 = if saved1 != 0 && rep1 != 0 { saved1 } else { saved2 };
    rep[0] = if rep1 != 0 { rep1 } else { saved1 } as u32;
    rep[1] = if rep2 != 0 { rep2 } else { saved2 } as u32;
    store.last_literals(&s[anchor..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The places of a tag in a row, as the bits from the latest place on: for every size
    /// of row, every head and rows with none, some and all places of the tag.
    #[test]
    fn tag_masks() {
        fn check<const ROW_LOG: u32>(x: &mut u64) {
            let row = 1usize << ROW_LOG;
            for round in 0..300 {
                let mut tags = vec![0u8; row];
                for t in tags.iter_mut() {
                    *x ^= *x << 13;
                    *x ^= *x >> 7;
                    *x ^= *x << 17;
                    // few tags, so that they repeat, and those with the high bit set
                    *t = [0x00, 0x7f, 0x80, 0xff, 0x01][(*x % 5) as usize];
                    if round % 7 == 0 {
                        *t = 0x80;
                    }
                }
                for tag in [0x00, 0x7f, 0x80, 0xff, 0x01, 0x42] {
                    for head in 0..row as u32 {
                        let mut want = 0u64;
                        for i in 0..row {
                            if tags[(i + head as usize) % row] == tag {
                                want |= 1 << i;
                            }
                        }
                        assert_eq!(tag_mask::<ROW_LOG>(&tags, tag, head), want, "rows of {row}, tag {tag:#x}, head {head}");
                    }
                }
            }
        }
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        check::<4>(&mut x);
        check::<5>(&mut x);
        check::<6>(&mut x);
    }
}
