//! The hashes of the match finders' tables, and the length of a match.

use crate::mem::{rd32l, rd64l};

const PRIME4: u32 = 2654435761;
const PRIME5: u64 = 889523592379;
const PRIME6: u64 = 227718039650203;
const PRIME7: u64 = 58295818150454627;
const PRIME8: u64 = 0xCF1BBCDCB7A56463;

/// (`lim`: see `rd32l`.) The hash of `hlog` bits of the `MLS` (4 to 8) bytes at `s[p..]`; 8 bytes are read for
/// more than 4.
#[inline(always)]
pub(crate) fn hash_l<const MLS: u32>(s: &[u8], lim: usize, p: usize, hlog: u32) -> usize {
    match MLS {
        5 => ((rd64l(s, lim, p) << 24).wrapping_mul(PRIME5) >> (64 - hlog)) as usize,
        6 => ((rd64l(s, lim, p) << 16).wrapping_mul(PRIME6) >> (64 - hlog)) as usize,
        7 => ((rd64l(s, lim, p) << 8).wrapping_mul(PRIME7) >> (64 - hlog)) as usize,
        8 => (rd64l(s, lim, p).wrapping_mul(PRIME8) >> (64 - hlog)) as usize,
        _ => (rd32l(s, lim, p).wrapping_mul(PRIME4) >> (32 - hlog)) as usize,
    }
}

/// The hash of `hlog` bits of the first `MLS` (4 to 8) bytes of `v`, the 8 bytes at a position
/// read as a little-endian word: what `hash_l` gives for that position.
#[inline(always)]
pub(crate) fn hash_v<const MLS: u32>(v: u64, hlog: u32) -> usize {
    match MLS {
        5 => ((v << 24).wrapping_mul(PRIME5) >> (64 - hlog)) as usize,
        6 => ((v << 16).wrapping_mul(PRIME6) >> (64 - hlog)) as usize,
        7 => ((v << 8).wrapping_mul(PRIME7) >> (64 - hlog)) as usize,
        8 => (v.wrapping_mul(PRIME8) >> (64 - hlog)) as usize,
        _ => ((v as u32).wrapping_mul(PRIME4) >> (32 - hlog)) as usize,
    }
}

/// A hash table of `fast` or `dfast` with the bounds of its entries known from how their
/// places are made: a [`Slot`] is a hash of the table's `log` bits, the table has `1 << log`
/// entries. `ID` tells the tables of one match finder apart, so that the slot of one is not
/// taken for the other's.
pub(crate) struct Table<'a, const ID: u8> {
    t: &'a mut [u32],
    log: u32,
}

/// The place of an entry in the [`Table`] of the same `ID`: made by its [`Hasher`] only.
#[derive(Clone, Copy)]
pub(crate) struct Slot<const ID: u8>(usize);

/// Makes the [`Slot`]s of a [`Table`].
#[derive(Clone, Copy)]
pub(crate) struct Hasher<const ID: u8> {
    log: u32,
}

impl<const ID: u8> Hasher<ID> {
    /// The slot of the `MLS` bytes at `s[p..]` (`lim`: see `rd32l`).
    #[inline(always)]
    pub fn slot<const MLS: u32>(self, s: &[u8], lim: usize, p: usize) -> Slot<ID> {
        Slot(hash_l::<MLS>(s, lim, p, self.log))
    }

    /// The slot of a position by the 8 bytes `v` read there (see `hash_v`).
    #[inline(always)]
    pub fn slot_of<const MLS: u32>(self, v: u64) -> Slot<ID> {
        Slot(hash_v::<MLS>(v, self.log))
    }
}

impl<'a, const ID: u8> Table<'a, ID> {
    /// The first `1 << log` entries of `t` as a table (`log`: 1 to 31).
    pub fn new(t: &'a mut [u32], log: u32) -> Self {
        assert!((1..32).contains(&log));
        Table { t: &mut t[..1 << log], log }
    }

    pub fn hasher(&self) -> Hasher<ID> {
        Hasher { log: self.log }
    }

    /// The number of bits of the table's slots.
    pub fn log(&self) -> u32 {
        self.log
    }

    /// `hasher()` of a table of `1 << LOG` entries, which this one must be: the hashes are
    /// then made with a number of bits the compiler knows. (For the search of `double fast`
    /// with the feature `unsafe`; the other searches have `sized`.)
    #[cfg(feature = "unsafe")]
    pub fn hasher_of<const LOG: u32>(&self) -> Hasher<ID> {
        assert!(self.log == LOG);
        Hasher { log: LOG }
    }

    /// This table, which must be one of `N` entries, `1 << LOG`, and its hasher, with the size
    /// in their types' place: the compiler then knows the number of bits of a hash and that a
    /// slot is within the table, which leaves the search without the check of an entry's
    /// place and with a register more.
    pub fn sized<const LOG: u32, const N: usize>(self) -> (Self, Hasher<ID>) {
        assert!(self.log == LOG && N == 1 << LOG);
        let t: &mut [u32; N] = self.t.try_into().unwrap();
        (Table { t, log: LOG }, Hasher { log: LOG })
    }

    #[inline(always)]
    pub fn at(&self, h: Slot<ID>) -> u32 {
        debug_assert!(h.0 < self.t.len());
        #[cfg(feature = "unsafe")]
        {
            // SAFETY: a slot is a hash of `log` bits, 1 to 31 (`hash_l` shifts a 32 or 64 bit
            // product right by all but `log`), so less than `1 << log`, the table's length. It
            // is this table's `log`: slots are made by `hasher()` only, and a match finder has
            // one table of an `ID`.
            unsafe { *self.t.get_unchecked(h.0) }
        }
        #[cfg(not(feature = "unsafe"))]
        {
            self.t[h.0]
        }
    }

    #[inline(always)]
    pub fn put(&mut self, h: Slot<ID>, v: u32) {
        debug_assert!(h.0 < self.t.len());
        #[cfg(feature = "unsafe")]
        {
            // SAFETY: as in `at`.
            unsafe { *self.t.get_unchecked_mut(h.0) = v }
        }
        #[cfg(not(feature = "unsafe"))]
        {
            self.t[h.0] = v
        }
    }
}

/// How many bytes `s[a..end]` and `s[b..]` have in common at their starts (`b < a`).
#[inline(always)]
pub(crate) fn count(s: &[u8], a: usize, b: usize, end: usize) -> usize {
    let x = &s[a..end];
    let y = &s[b..];
    let mut n = 0;
    for (cx, cy) in x.as_chunks::<8>().0.iter().zip(y.as_chunks::<8>().0) {
        let d = u64::from_le_bytes(*cx) ^ u64::from_le_bytes(*cy);
        if d != 0 {
            return n + (d.trailing_zeros() >> 3) as usize;
        }
        n += 8;
    }
    while n < x.len() && x[n] == y[n] {
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slots of a table are within it, whatever the bytes hashed and for every size of
    /// table and of hashed bytes; what is put at one is found there.
    #[test]
    fn slots_within_the_table() {
        let mut s = [0u8; 64];
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for log in 1..=if cfg!(miri) { 9 } else { 20 } {
            let mut v = vec![0u32; (1 << log) + 3];
            let mut table = Table::<0>::new(&mut v, log);
            let hasher = table.hasher();
            for round in 0..200u32 {
                for b in s.iter_mut() {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *b = match round % 4 {
                        0 => 0xFF,
                        1 => 0,
                        _ => x as u8,
                    };
                }
                let lim = s.len() - 8;
                for p in [0, 1, lim] {
                    let slots = [
                        hasher.slot::<4>(&s, lim, p),
                        hasher.slot::<5>(&s, lim, p),
                        hasher.slot::<6>(&s, lim, p),
                        hasher.slot::<7>(&s, lim, p),
                        hasher.slot::<8>(&s, lim, p),
                    ];
                    let v = rd64l(&s, lim, p);
                    let of = [hasher.slot_of::<4>(v), hasher.slot_of::<5>(v), hasher.slot_of::<6>(v), hasher.slot_of::<7>(v), hasher.slot_of::<8>(v)];
                    for (slot, of) in slots.into_iter().zip(of) {
                        assert_eq!(slot.0, of.0);
                        assert!(slot.0 < 1 << log);
                        table.put(slot, round + 1);
                        assert_eq!(table.at(slot), round + 1);
                    }
                }
            }
            // (nothing was written beyond the table)
            assert_eq!(v[1 << log..], [0, 0, 0]);
        }
    }
}
