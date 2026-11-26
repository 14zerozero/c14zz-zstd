//! The `double fast` strategy (levels 2 to 4, by input size) after the reference
//! implementation's `ZSTD_compressBlock_doubleFast`: a table of the positions' first 8
//! bytes for long matches and one of their first `MLS` bytes for short ones.

use super::hash::{count, Hasher, Table};
use super::seq::{off_base, SeqStore, REP1};
use crate::mem::{rd32l, rd64l};

/// Finds the sequences of the block `s[start..]`; `s[..start]` is its history. The index of
/// `s[0]` in the tables is `low_idx`.
pub(crate) fn block<const MLS: u32>(long: Table<0>, small: Table<1>, store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize, low_idx: u32) {
    // The sizes of the tables of level 3 for inputs of more than 256 KB and for streams have
    // a copy of the search of their own: the hashes' shifts are constants there, which
    // leaves two registers to the loop. (Without the feature `unsafe` the tables' sizes are
    // constants there as well, for a search without checks of the entries' places: 4 %
    // faster. With the feature, where there are no such checks, that was 2 % slower.)
    if long.log() == 17 && small.log() == 16 {
        #[cfg(not(feature = "unsafe"))]
        let ((long, long_hasher), (small, small_hasher)) = (long.sized::<17, { 1 << 17 }>(), small.sized::<16, { 1 << 16 }>());
        #[cfg(feature = "unsafe")]
        let (long_hasher, small_hasher) = (long.hasher_of::<17>(), small.hasher_of::<16>());
        search::<MLS>(long, small, (long_hasher, small_hasher), store, rep, s, start, low_idx)
    } else {
        let hashers = (long.hasher(), small.hasher());
        search::<MLS>(long, small, hashers, store, rep, s, start, low_idx)
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn search<const MLS: u32>(mut long: Table<0>, mut small: Table<1>, hashers: (Hasher<0>, Hasher<1>), store: &mut SeqStore, rep: &mut [u32; 3], s: &[u8], start: usize, low_idx: u32) {
    let end = s.len();
    let mut anchor = start;
    if end - start < 16 {
        store.last_literals(&s[anchor..]);
        return;
    }
    let ilimit = end - 8;
    let lim = ilimit;
    const STEP_INCR: usize = 1 << 8;
    let idx = |p: usize| low_idx.wrapping_add(p as u32);
    let pos = |i: u32| i.wrapping_sub(low_idx) as usize;
    let (long_hasher, small_hasher) = hashers;
    let hl = |p: usize| long_hasher.slot::<8>(s, lim, p);
    let hs = |p: usize| small_hasher.slot::<MLS>(s, lim, p);

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

    'block: loop {
        let mut step = 1;
        let mut next_step = ip + STEP_INCR;
        let mut ip1 = ip + step;
        if ip1 > ilimit {
            break;
        }
        // (the 8 bytes at `ip`: the position's two hashes and what its candidates are compared
        // with are made of them, without another read)
        let mut v0 = rd64l(s, lim, ip);
        let mut hl0 = long_hasher.slot_of::<8>(v0);
        let mut idxl0 = long.at(hl0);
        let cur;
        let mut mlen;
        // a match found: `Some(offset)`; a repeat, stored already: `None`
        let found = loop {
            let hs0 = small_hasher.slot_of::<MLS>(v0);
            let idxs0 = small.at(hs0);
            let c = idx(ip);
            long.put(hl0, c);
            small.put(hs0, c);
            if rep1 > 0 && rd32l(s, lim, ip + 1 - rep1) == (v0 >> 8) as u32 {
                mlen = count(s, ip + 5, ip + 5 - rep1, end) + 4;
                cur = ip;
                ip += 1;
                store.store(s, anchor, ip - anchor, REP1, mlen);
                break None;
            }
            let v1 = rd64l(s, lim, ip1);
            let hl1 = long_hasher.slot_of::<8>(v1);
            let pl0 = pos(idxl0);
            // (Whether an index is one of this data is hard to predict where the tables have
            // many of earlier data, and a match is rare: so there is no branch on it before
            // the read. What is read is the position of the index or, where that is beyond
            // the last one that can be read, that last one; the bytes are compared first,
            // and the index is looked at only when they are the same. `black_box` keeps the
            // compiler from turning that around.)
            if rd64l(s, lim, pl0.min(lim)) == v0 && core::hint::black_box(pl0 < ip) {
                let mut m = pl0;
                mlen = count(s, ip + 8, m + 8, end) + 8;
                let offset = ip - m;
                cur = ip;
                while ip > anchor && m > 0 && s[ip - 1] == s[m - 1] {
                    ip -= 1;
                    m -= 1;
                    mlen += 1;
                }
                break Some((offset, hl1));
            }
            let idxl1 = long.at(hl1);
            let ps0 = pos(idxs0);
            if rd32l(s, lim, ps0.min(lim)) == v0 as u32 && core::hint::black_box(ps0 < ip) {
                // a short match: is there a long one at the next position?
                let mut m = ps0;
                mlen = count(s, ip + 4, m + 4, end) + 4;
                let mut offset = ip - m;
                cur = ip;
                let pl1 = pos(idxl1);
                if pl1 < ip1 && rd64l(s, lim, pl1) == v1 {
                    let len1 = count(s, ip1 + 8, pl1 + 8, end) + 8;
                    if len1 > mlen {
                        ip = ip1;
                        mlen = len1;
                        offset = ip - pl1;
                        m = pl1;
                    }
                }
                while ip > anchor && m > 0 && s[ip - 1] == s[m - 1] {
                    ip -= 1;
                    m -= 1;
                    mlen += 1;
                }
                break Some((offset, hl1));
            }
            if ip1 >= next_step {
                step += 1;
                next_step += STEP_INCR;
            }
            ip = ip1;
            ip1 += step;
            hl0 = hl1;
            idxl0 = idxl1;
            v0 = v1;
            if ip1 > ilimit {
                break 'block;
            }
        };
        if let Some((offset, hl1)) = found {
            rep2 = rep1;
            rep1 = offset;
            if step < 4 {
                long.put(hl1, idx(ip1));
            }
            store.store(s, anchor, ip - anchor, off_base(offset as u32), mlen);
        }
        ip += mlen;
        anchor = ip;
        if ip <= ilimit {
            let ins = cur + 2;
            long.put(hl(ins), idx(ins));
            long.put(hl(ip - 2), idx(ip - 2));
            small.put(hs(ins), idx(ins));
            small.put(hs(ip - 1), idx(ip - 1));
            while ip <= ilimit && rep2 > 0 && rd32l(s, lim, ip) == rd32l(s, lim, ip - rep2) {
                let rlen = count(s, ip + 4, ip + 4 - rep2, end) + 4;
                core::mem::swap(&mut rep1, &mut rep2);
                small.put(hs(ip), idx(ip));
                long.put(hl(ip), idx(ip));
                store.store(s, anchor, 0, REP1, rlen);
                ip += rlen;
                anchor = ip;
            }
        }
    }

    let saved2 = if saved1 != 0 && rep1 != 0 { saved1 } else { saved2 };
    rep[0] = if rep1 != 0 { rep1 } else { saved1 } as u32;
    rep[1] = if rep2 != 0 { rep2 } else { saved2 } as u32;
    store.last_literals(&s[anchor..]);
}
