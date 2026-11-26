//! The match finders' tables with a dictionary's content in them, after the reference
//! implementation's `ZSTD_loadDictionaryContent`, and how a compressor comes by them for
//! each of many small frames without making them each time.
//!
//! A dictionary's content is before a frame's data as if it were data of the frame: the
//! match finders find it through their tables as they find earlier data. The tables with
//! the content in them are made once for a dictionary and a set of parameters ([`Prepared`],
//! the reference implementation's `CDict`). A compressor works in a copy of them, and after
//! a frame takes back from the prepared tables every entry the frame's data may have
//! changed: the entries of the hashes of its positions. That costs by the size of the data,
//! not of the tables. (The reference implementation searches two sets of tables for small
//! data, its own and the dictionary's, and copies the dictionary's for larger data.)

use super::hash::hash_l;
use super::lazy;
use super::params::{Params, Strategy};
use super::bt;
use super::{aligned, row_params, use_trees, Tables};

/// The index of the first byte of a dictionary's content in the tables that are prepared
/// with it (0 is an entry that was never written).
pub(crate) const FIRST_IDX: u32 = 1;

/// The tables of the match finder of `p` with the positions of a dictionary's content.
pub(crate) struct Prepared {
    pub p: Params,
    hash: Vec<u32>,
    chain: Vec<u32>,
    tags: Vec<u8>,
}

/// The number of bytes the hash of `fast` is made of for `min_match` (as its search has it).
fn fast_mls(min_match: u32) -> u32 {
    min_match.clamp(4, 8)
}

/// The same for the short hash of `dfast`.
fn dfast_mls(min_match: u32) -> u32 {
    min_match.clamp(4, 7)
}

/// `hash_l` with the number of bytes as a value.
#[inline(always)]
fn hash_of(mls: u32, s: &[u8], lim: usize, p: usize, bits: u32) -> usize {
    match mls {
        5 => hash_l::<5>(s, lim, p, bits),
        6 => hash_l::<6>(s, lim, p, bits),
        7 => hash_l::<7>(s, lim, p, bits),
        8 => hash_l::<8>(s, lim, p, bits),
        _ => hash_l::<4>(s, lim, p, bits),
    }
}

/// The hash of the lazy match finders with the number of bytes as a value.
#[inline(always)]
fn lazy_hash(mls: u32, s: &[u8], lim: usize, p: usize, bits: u32) -> usize {
    (match mls {
        5 => lazy::hash::<5>(s, lim, p, bits),
        6 => lazy::hash::<6>(s, lim, p, bits),
        _ => lazy::hash::<4>(s, lim, p, bits),
    }) as usize
}

/// The parts of the tables the match finder of `p` uses: the hash table, the chain table (or
/// the table of the short hash), the tags; the row-based finder's start where a cache line
/// does.
pub(crate) fn parts<'a>(p: &Params, hash: &'a mut [u32], chain: &'a mut [u32], tags: &'a mut [u8]) -> (&'a mut [u32], &'a mut [u32], &'a mut [u8]) {
    if p.rows {
        let n = 1usize << row_params(p).1;
        (aligned(hash, n), &mut [], aligned(tags, n))
    } else {
        let chained = p.strategy != Strategy::Fast;
        (&mut hash[..1 << p.hash_log], if chained { &mut chain[..1 << p.chain_log] } else { &mut [] }, &mut [])
    }
}

/// Puts the positions of the dictionary content `s` into the tables of the match finder of
/// `p` (see `parts`); `low_idx` is the index of `s[0]`. `full`: for tables that are kept (as
/// the reference implementation fills those of a `CDict`: more positions for `fast` and
/// `dfast`, which then asks for tables without entries of other data).
pub(crate) fn load(p: &Params, hash: &mut [u32], chain: &mut [u32], tags: &mut [u8], s: &[u8], low_idx: u32, full: bool) {
    let n = s.len();
    if n <= 8 {
        return;
    }
    // of a dictionary larger than the tables can tell apart, the end only
    let most = 1usize << (p.hash_log + 3).max(p.chain_log + 1).min(31);
    let from = n.saturating_sub(most);
    // the last position whose 8 bytes can be read
    let lim = n - 8;
    let idx = |q: usize| low_idx.wrapping_add(q as u32);
    match p.strategy {
        Strategy::Fast => {
            let mls = fast_mls(p.min_match);
            let mut q = from;
            while q + 1 < lim {
                hash[hash_of(mls, s, lim, q, p.hash_log)] = idx(q);
                if full {
                    for q in q + 1..q + 3 {
                        let h = hash_of(mls, s, lim, q, p.hash_log);
                        if hash[h] == 0 {
                            hash[h] = idx(q);
                        }
                    }
                }
                q += 3;
            }
        }
        Strategy::DFast => {
            let mls = dfast_mls(p.min_match);
            let mut q = from;
            while q + 2 <= lim {
                for (i, q) in (q..q + 3).enumerate() {
                    let long = hash_of(8, s, lim, q, p.hash_log);
                    if i == 0 {
                        chain[hash_of(mls, s, lim, q, p.chain_log)] = idx(q);
                    }
                    if i == 0 || hash[long] == 0 {
                        hash[long] = idx(q);
                    }
                    if !full {
                        break;
                    }
                }
                q += 3;
            }
        }
        _ if use_trees(p) => {
            // (sorted in, also for `btlazy2`, whose mark of a position that is not sorted in
            // is the index 1: that position stays out)
            let from = from + (p.strategy == Strategy::BtLazy2 && idx(from) == 1) as usize;
            let mut next = idx(from);
            let tables = bt::TreeTables {
                hash,
                chain,
                hash3: &mut [],
                hash_log: p.hash_log,
                hash3_log: 0,
                search_log: p.search_log,
                window_log: usize::BITS - 1,
                target_length: p.target_length,
                next_to_update: &mut next,
            };
            let mut tree = bt::Tree::new(tables, &s[from..], 0, idx(from));
            let target = lim - from;
            match p.min_match {
                0..=4 => tree.update::<4>(target),
                5 => tree.update::<5>(target),
                _ => tree.update::<6>(target),
            }
        }
        _ if p.rows => {
            let (row_log, hash_log) = row_params(p);
            let mls = p.min_match.clamp(4, 6);
            let row_mask = (1u32 << row_log) - 1;
            for q in from..lim {
                let h = lazy_hash(mls, s, lim, q, hash_log - row_log + lazy::TAG_BITS);
                let row = (h >> lazy::TAG_BITS) << row_log;
                let tag_row = &mut tags[row..row + (1 << row_log)];
                let place = lazy::next_place(tag_row, row_mask);
                tag_row[place] = h as u8;
                hash[row + place] = idx(q);
            }
        }
        _ => {
            let mls = p.min_match.clamp(4, 6);
            let mask = chain.len() - 1;
            for q in from..lim {
                let h = lazy_hash(mls, s, lim, q, p.hash_log);
                chain[idx(q) as usize & mask] = hash[h];
                hash[h] = idx(q);
            }
        }
    }
}

impl Prepared {
    /// The tables of `p` with the positions of `content`.
    pub fn new(p: Params, content: &[u8]) -> Prepared {
        let (mut hash, mut chain, mut tags) = (Vec::new(), Vec::new(), Vec::new());
        if p.rows {
            let n = 1usize << row_params(&p).1;
            hash.resize(n, 0);
            tags.resize(n, 0);
        } else {
            hash.resize(1 << p.hash_log, 0);
            if p.strategy != Strategy::Fast {
                chain.resize(1 << p.chain_log, 0);
            }
        }
        load(&p, &mut hash, &mut chain, &mut tags, content, FIRST_IDX, true);
        Prepared { p, hash, chain, tags }
    }

    /// The size of the tables.
    pub fn bytes(&self) -> usize {
        4 * (self.hash.len() + self.chain.len()) + self.tags.len()
    }

    /// Makes `t` these tables, for a frame whose data follows `content_len` bytes of
    /// content.
    pub fn copy_to(&self, t: &mut Tables, content_len: usize) {
        t.prepare(&self.p);
        // (nothing of other frames stays, also where these tables do not reach: its indexes
        // would be those of this frame's data)
        if t.dirty_beyond {
            t.hash.fill(0);
            t.chain.fill(0);
            t.tags.fill(0);
            t.dirty_beyond = false;
        }
        t.was_kept = true;
        // (the latest positions of 3 bytes are those of a frame's data only)
        t.hash3.fill(0);
        let (hash, chain, tags) = parts(&self.p, &mut t.hash, &mut t.chain, &mut t.tags);
        hash.copy_from_slice(&self.hash);
        chain.copy_from_slice(&self.chain);
        tags.copy_from_slice(&self.tags);
        self.rewind(t, content_len);
    }

    /// The indexes of a frame's start behind `content_len` bytes of content.
    fn rewind(&self, t: &mut Tables, content_len: usize) {
        t.next_idx = FIRST_IDX.wrapping_add(content_len as u32);
        t.next_to_update = t.next_idx;
    }

    /// Whether `restore` is the cheaper way to these tables after a frame of `n` bytes,
    /// compared with `copy_to`. (An entry taken back costs about as much as 16 copied in a
    /// row, and a row of the row-based finder is 16 to 64 entries.)
    pub fn restores(&self, n: usize) -> bool {
        let per_byte = if self.p.rows { 5 << row_params(&self.p).0 } else { 64 };
        n.saturating_mul(per_byte) < self.bytes()
    }

    /// Makes `t`, which was these tables before the frame of the data `s[start..]` was
    /// compressed with them (`s[..start]` is the content), these tables again: every entry
    /// that a position of the data may have been written to is taken from here. (The
    /// entries are those of the hashes of the positions, whose 8 bytes are read up to the
    /// end of the data only, and for the chains those of the positions themselves; some
    /// positions before the data as well, which the searches put into the tables when a
    /// match starts at the data's first bytes.)
    ///
    /// A tree is changed along the ways to where the data's positions went into it: all
    /// nodes of the content's positions are taken back. `hash3_log`: the size of the table
    /// of the hashes of 3 bytes the frame had, if any; it has positions of the data only.
    pub fn restore(&self, t: &mut Tables, s: &[u8], start: usize, hash3_log: u32) {
        let p = &self.p;
        if hash3_log > 0 && s.len() >= 4 {
            let lim4 = s.len() - 4;
            for q in start.saturating_sub(8)..=lim4 {
                t.hash3[bt::hash3(s, lim4, q, hash3_log)] = 0;
            }
        }
        let (hash, chain, tags) = parts(p, &mut t.hash, &mut t.chain, &mut t.tags);
        if s.len() >= 8 {
            let lim = s.len() - 8;
            let first = start.saturating_sub(8);
            match p.strategy {
                Strategy::Fast => {
                    let mls = fast_mls(p.min_match);
                    for q in first..=lim {
                        let h = hash_of(mls, s, lim, q, p.hash_log);
                        hash[h] = self.hash[h];
                    }
                }
                Strategy::DFast => {
                    let mls = dfast_mls(p.min_match);
                    for q in first..=lim {
                        let h = hash_of(8, s, lim, q, p.hash_log);
                        hash[h] = self.hash[h];
                        let h = hash_of(mls, s, lim, q, p.chain_log);
                        chain[h] = self.chain[h];
                    }
                }
                _ if p.rows => {
                    let (row_log, hash_log) = row_params(p);
                    let mls = p.min_match.clamp(4, 6);
                    let mask = (1usize << row_log) - 1;
                    // A row's places are written one after the other, and its first byte
                    // says which one was last: each position of the data takes back the
                    // place written last in its row and makes the one written before it
                    // the last. (That is all places the data wrote, and others that were
                    // not written, which does no harm.)
                    for q in first..=lim {
                        let h = lazy_hash(mls, s, lim, q, hash_log - row_log + lazy::TAG_BITS);
                        let row = (h >> lazy::TAG_BITS) << row_log;
                        let last = (tags[row] as usize & mask).max(1);
                        hash[row + last] = self.hash[row + last];
                        tags[row + last] = self.tags[row + last];
                        tags[row] = if last == mask { 1 } else { last as u8 + 1 };
                    }
                    // (the rows' first bytes, when all places are back)
                    for q in first..=lim {
                        let h = lazy_hash(mls, s, lim, q, hash_log - row_log + lazy::TAG_BITS);
                        let row = (h >> lazy::TAG_BITS) << row_log;
                        tags[row] = self.tags[row];
                    }
                }
                _ if use_trees(p) => {
                    let mls = p.min_match.clamp(4, 6);
                    for q in first..=lim {
                        let h = hash_of(mls, s, lim, q, p.hash_log);
                        hash[h] = self.hash[h];
                    }
                    // (two entries per position, at its index within the table's size)
                    let nodes = 2 * FIRST_IDX as usize..2 * (FIRST_IDX as usize + start);
                    if nodes.end <= chain.len() {
                        chain[nodes.clone()].copy_from_slice(&self.chain[nodes]);
                    } else {
                        chain.copy_from_slice(&self.chain);
                    }
                }
                _ => {
                    let mls = p.min_match.clamp(4, 6);
                    let mask = chain.len() - 1;
                    for q in first..=lim {
                        let h = lazy_hash(mls, s, lim, q, p.hash_log);
                        hash[h] = self.hash[h];
                        let i = FIRST_IDX.wrapping_add(q as u32) as usize & mask;
                        chain[i] = self.chain[i];
                    }
                }
            }
        }
        self.rewind(t, start);
    }
}
