//! The `fast` strategy (level 1 and the negative levels) after the reference
//! implementation's `ZSTD_compressBlock_fast`: one hash table of the positions' first
//! `MLS` bytes, searched at two positions per round with the table lookups of the next
//! positions under way, and the repeat offset tried in between.

use super::hash::{count, Hasher, Table};
use super::seq::{off_base, SeqStore, REP1};
use crate::mem::{rd32l, rd64l};

/// Finds the sequences of the block `s[start..]`; `s[..start]` is its history. The index of
/// `s[0]` in `table` is `low_idx`.
pub(crate) fn block<const MLS: u32>(table: Table<0>, target_length: u32, store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize, low_idx: u32) {
    // The size of the table of level 1 for all but small inputs has a copy of the search of
    // its own: the hash's shift and the table's size are constants there, which leaves a
    // register to the loop and no check of an entry's place.
    if table.log() == 14 {
        let (table, hasher) = table.sized::<14, { 1 << 14 }>();
        search::<MLS>(table, hasher, target_length, store, rep, s, start, low_idx)
    } else {
        let hasher = table.hasher();
        search::<MLS>(table, hasher, target_length, store, rep, s, start, low_idx)
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn search<const MLS: u32>(mut table: Table<0>, hasher: Hasher<0>, target_length: u32, store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize, low_idx: u32) {
    let end = s.len();
    let mut anchor = start;
    if end - start < 16 {
        store.last_literals(&s[anchor..]);
        return;
    }
    let ilimit = end - 8;
    let lim = ilimit;
    let step_size = target_length as usize + (target_length == 0) as usize + 1;
    const STEP_INCR: usize = 1 << 7;
    let idx = |p: usize| low_idx.wrapping_add(p as u32);
    let h = |p: usize| hasher.slot::<MLS>(s, lim, p);

    let mut ip0 = start + (start == 0) as usize;
    let (mut rep1, mut rep2) = (rep[0] as usize, rep[1] as usize);
    let (mut saved1, mut saved2) = (0, 0);
    if rep2 > ip0 {
        saved2 = rep2;
        rep2 = 0;
    }
    if rep1 > ip0 {
        saved1 = rep1;
        rep1 = 0;
    }

    'block: loop {
        // (The two positions of a round are `ip0` and the one behind it; the one whose
        // bytes are read ahead is `ip2`, and the round after this one is about it and the
        // one behind it: only `ip0` and `ip2` are kept.)
        let mut step = step_size;
        let mut next_step = ip0 + STEP_INCR;
        let mut ip2 = ip0 + step;
        if ip2 + 1 >= ilimit {
            break;
        }
        // (the 8 bytes at `ip0` and behind it: a position's hash and what its candidate is
        // compared with are made of them, without another read)
        let mut v0 = rd64l(s, lim, ip0);
        let mut v1 = rd64l(s, lim, ip0 + 1);
        let mut hash0 = hasher.slot_of::<MLS>(v0);
        let mut hash1 = hasher.slot_of::<MLS>(v1);
        let mut match_idx = table.at(hash0);
        let cur0;

        // Whether `match_idx` is a position before `ip`, where the 8 bytes `v` are, with the
        // same 4 bytes. (What is read is that position or, where it is beyond the last one
        // that can be read, that last one; the bytes are compared first, and the index is
        // looked at only when they are the same, which `black_box` keeps the compiler from
        // turning around.)
        macro_rules! found {
            ($ip:expr, $v:expr) => {{
                let p = match_idx.wrapping_sub(low_idx) as usize;
                rd32l(s, lim, p.min(lim)) == $v as u32 && core::hint::black_box(p < $ip)
            }};
        }

        // a repeat found: its match and length so far
        let repeat = loop {
            // the repeat offset at ip2
            let v2 = rd64l(s, lim, ip2);
            let rval = rd32l(s, lim, ip2 - rep1);
            table.put(hash0, idx(ip0));
            if (v2 as u32 == rval) & (rep1 > 0) {
                cur0 = ip0;
                table.put(hash1, idx(ip0 + 1));
                ip0 = ip2;
                let m0 = ip0 - rep1;
                let back = (m0 > 0 && s[ip0 - 1] == s[m0 - 1]) as usize;
                ip0 -= back;
                break Some((m0 - back, back + 4));
            }
            if found!(ip0, v0) {
                cur0 = ip0;
                table.put(hash1, idx(ip0 + 1));
                break None;
            }
            // the position behind `ip0`
            match_idx = table.at(hash1);
            hash0 = hash1;
            hash1 = hasher.slot_of::<MLS>(v2);
            table.put(hash0, idx(ip0 + 1));
            if found!(ip0 + 1, v1) {
                ip0 += 1;
                cur0 = ip0;
                if step <= 4 {
                    table.put(hash1, idx(ip2));
                }
                break None;
            }
            match_idx = table.at(hash1);
            hash0 = hash1;
            ip0 = ip2;
            ip2 += step;
            if ip2 >= next_step {
                step += 1;
                next_step += STEP_INCR;
            }
            if ip2 + 1 >= ilimit {
                break 'block;
            }
            v0 = v2;
            v1 = rd64l(s, lim, ip0 + 1);
            hash1 = hasher.slot_of::<MLS>(v1);
        };
        let (m0, mut mlen, offcode) = match repeat {
            Some((m0, mlen)) => (m0, mlen, REP1),
            None => {
                let mut m0 = match_idx.wrapping_sub(low_idx) as usize;
                rep2 = rep1;
                rep1 = ip0 - m0;
                let mut mlen = 4;
                while ip0 > anchor && m0 > 0 && s[ip0 - 1] == s[m0 - 1] {
                    ip0 -= 1;
                    m0 -= 1;
                    mlen += 1;
                }
                (m0, mlen, off_base(rep1 as u32))
            }
        };
        mlen += count(s, ip0 + mlen, m0 + mlen, end);
        store.store(s, anchor, ip0 - anchor, offcode, mlen);
        ip0 += mlen;
        anchor = ip0;
        if ip0 <= ilimit {
            table.put(h(cur0 + 2), idx(cur0 + 2));
            table.put(h(ip0 - 2), idx(ip0 - 2));
            if rep2 > 0 {
                while ip0 <= ilimit && rd32l(s, lim, ip0) == rd32l(s, lim, ip0 - rep2) {
                    let rlen = count(s, ip0 + 4, ip0 + 4 - rep2, end) + 4;
                    core::mem::swap(&mut rep1, &mut rep2);
                    table.put(h(ip0), idx(ip0));
                    ip0 += rlen;
                    store.store(s, anchor, 0, REP1, rlen);
                    anchor = ip0;
                }
            }
        }
    }

    // offsets that were beyond the block's history are those of the next block again
    let saved2 = if saved1 != 0 && rep1 != 0 { saved1 } else { saved2 };
    rep[0] = if rep1 != 0 { rep1 } else { saved1 } as u32;
    rep[1] = if rep2 != 0 { rep2 } else { saved2 } as u32;
    store.last_literals(&s[anchor..]);
}

/// `block` for data behind the content of a dictionary, after the reference
/// implementation's `ZSTD_compressBlock_fast_dictMatchState`: one position per round, up to
/// the last one that can be hashed, and the repeat offset tried at the position after it.
/// Small inputs, which a dictionary is for, are searched to their end this way. (Here the
/// content's positions are in the one table: there is no second table to look into.)
pub(crate) fn block_behind_content<const MLS: u32>(mut table: Table<0>, target_length: u32, store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize, low_idx: u32) {
    let end = s.len();
    let mut anchor = start;
    if end - start < 9 {
        store.last_literals(&s[anchor..]);
        return;
    }
    let ilimit = end - 8;
    let lim = ilimit;
    let hasher = table.hasher();
    let step_size = target_length as usize + (target_length == 0) as usize;
    const STEP_INCR: usize = 1 << 8;
    let idx = |p: usize| low_idx.wrapping_add(p as u32);
    let h = |p: usize| hasher.slot::<MLS>(s, lim, p);
    // (offsets reach into the content, never before it)
    let (mut rep1, mut rep2) = (rep[0] as usize, rep[1] as usize);
    let (mut saved1, mut saved2) = (0, 0);
    if rep2 > start {
        saved2 = rep2;
        rep2 = 0;
    }
    if rep1 > start {
        saved1 = rep1;
        rep1 = 0;
    }

    let mut ip0 = start + (start == 0) as usize;
    let mut ip1 = ip0 + step_size;
    'block: while ip1 <= ilimit {
        let mut hash0 = h(ip0);
        let mut match_idx = table.at(hash0);
        let mut step = step_size;
        let mut next_step = ip0 + STEP_INCR;
        let cur;
        let mut mlen;
        loop {
            let hash1 = h(ip1);
            table.put(hash0, idx(ip0));
            // (`ip0 + 1 <= ilimit`: 4 bytes are there to read)
            if rep1 > 0 && rd32l(s, lim, ip0 + 1 - rep1) == rd32l(s, lim, ip0 + 1) {
                mlen = count(s, ip0 + 5, ip0 + 5 - rep1, end) + 4;
                cur = ip0;
                ip0 += 1;
                store.store(s, anchor, ip0 - anchor, REP1, mlen);
                break;
            }
            let m = match_idx.wrapping_sub(low_idx) as usize;
            if m < ip0 && rd32l(s, lim, m) == rd32l(s, lim, ip0) {
                let mut m = m;
                cur = ip0;
                mlen = count(s, ip0 + 4, m + 4, end) + 4;
                while ip0 > anchor && m > 0 && s[ip0 - 1] == s[m - 1] {
                    ip0 -= 1;
                    m -= 1;
                    mlen += 1;
                }
                rep2 = rep1;
                rep1 = ip0 - m;
                store.store(s, anchor, ip0 - anchor, off_base(rep1 as u32), mlen);
                break;
            }
            match_idx = table.at(hash1);
            if ip1 >= next_step {
                step += 1;
                next_step += STEP_INCR;
            }
            ip0 = ip1;
            ip1 += step;
            if ip1 > ilimit {
                break 'block;
            }
            hash0 = hash1;
        }
        ip0 += mlen;
        anchor = ip0;
        if ip0 <= ilimit {
            if cur + 2 <= lim {
                table.put(h(cur + 2), idx(cur + 2));
            }
            table.put(h(ip0 - 2), idx(ip0 - 2));
            while ip0 <= ilimit && rep2 > 0 && rd32l(s, lim, ip0) == rd32l(s, lim, ip0 - rep2) {
                let rlen = count(s, ip0 + 4, ip0 + 4 - rep2, end) + 4;
                core::mem::swap(&mut rep1, &mut rep2);
                store.store(s, anchor, 0, REP1, rlen);
                table.put(h(ip0), idx(ip0));
                ip0 += rlen;
                anchor = ip0;
            }
        }
        ip1 = ip0 + step_size;
    }

    // offsets that were beyond the block's history are those of the next block again
    let saved2 = if saved1 != 0 && rep1 != 0 { saved1 } else { saved2 };
    rep[0] = if rep1 != 0 { rep1 } else { saved1 } as u32;
    rep[1] = if rep2 != 0 { rep2 } else { saved2 } as u32;
    store.last_literals(&s[anchor..]);
}
