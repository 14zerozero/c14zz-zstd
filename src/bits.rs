//! The bit streams of the format: written forwards, low bits first, ended by a 1 bit, and
//! read backwards from that bit.

use crate::error::{Error, Result};
use crate::mem::rd64;

/// A backward bit reader after the reference implementation's `BIT_DStream_t`: `cont` holds
/// the 8 bytes at `pos`, of which the top `used` bits are consumed.
#[derive(Clone)]
pub(crate) struct BitR<'a> {
    src: &'a [u8],
    pub pos: usize,
    pub cont: u64,
    pub used: u32,
}

impl<'a> BitR<'a> {
    /// Starts at the end of `src`, behind the final 1 bit.
    #[inline]
    pub fn new(src: &'a [u8]) -> Result<Self> {
        let n = src.len();
        let Some(&last) = src.last() else {
            return Err(Error::Corrupt("empty bit stream"));
        };
        if last == 0 {
            return Err(Error::Corrupt("bit stream without end mark"));
        }
        let mark = last.leading_zeros() + 1;
        if n >= 8 {
            Ok(BitR { src, pos: n - 8, cont: rd64(src, n - 8), used: mark })
        } else {
            let mut cont = 0u64;
            for (i, &b) in src.iter().enumerate() {
                cont |= (b as u64) << (8 * i);
            }
            Ok(BitR { src, pos: 0, cont, used: mark + (8 - n as u32) * 8 })
        }
    }

    /// A reader of `src` that has the 8 bytes at `pos` loaded and used `used` bits of them.
    #[inline]
    pub fn resume(src: &'a [u8], pos: usize, used: u32) -> Self {
        BitR { src, pos, cont: rd64(src, pos), used }
    }

    /// The next `n` bits (`n` < 64, may be 0) without consuming them.
    #[inline(always)]
    pub fn peek(&self, n: u32) -> u64 {
        (self.cont.wrapping_shl(self.used) >> 1) >> (63 - n)
    }

    /// The next `n` bits, `1 <= n < 64`.
    #[inline(always)]
    pub fn peek_fast(&self, n: u32) -> u64 {
        self.cont.wrapping_shl(self.used) >> (64 - n)
    }

    #[inline(always)]
    pub fn skip(&mut self, n: u32) {
        self.used += n;
    }

    /// Reads `n` bits (`n` < 64, may be 0). Past the start of the stream the bits read are
    /// arbitrary and the stream is `overflown`.
    #[inline(always)]
    pub fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.used += n;
        v
    }

    /// Makes at least 56 bits available as long as the stream has them. (All of it inline,
    /// without a call that takes the reader's address: it is to live in registers. And the
    /// branch is one that goes the same way until the stream's last bytes: one on the number
    /// of bits used does not.)
    #[inline(always)]
    pub fn refill(&mut self) {
        if self.pos >= 8 {
            self.pos -= (self.used >> 3) as usize;
            self.used &= 7;
            self.cont = rd64(self.src, self.pos);
        } else {
            // whole bytes used, as far as the stream goes back; a stream of less than 8 bytes
            // is loaded as a whole from the start (`pos` is 0)
            let bytes = ((self.used >> 3) as usize).min(self.pos);
            if bytes != 0 {
                self.pos -= bytes;
                self.used -= 8 * bytes as u32;
                self.cont = rd64(self.src, self.pos);
            }
        }
    }

    /// More bits were read than the stream has.
    #[inline(always)]
    pub fn overflown(&self) -> bool {
        self.used > 64
    }

    /// All bits were read, and no more.
    #[inline(always)]
    pub fn finished(&self) -> bool {
        self.pos == 0 && self.used == 64
    }
}

/// The backward bit reader of the sequences: as `BitR`, but it counts the bits of `cont`
/// that are left (`64 - used`), which makes a read one subtraction and one shift, and its
/// reads leave the bits above the ones asked for in place, for the caller to drop with the
/// instruction for that where there is one.
pub(crate) struct SeqBits<'a> {
    /// The stream up to the 8 bytes that `cont` was loaded from, those included (all of a
    /// stream of less than 8 bytes, which is loaded as a whole).
    rest: &'a [u8],
    cont: u64,
    /// Beyond 64 (the count went below 0): more bits were read than the stream has.
    left: u32,
}

impl<'a> SeqBits<'a> {
    /// Starts at the end of `src`, behind the final 1 bit.
    #[inline]
    pub fn new(src: &'a [u8]) -> Result<Self> {
        let r = BitR::new(src)?;
        Ok(SeqBits { rest: src, cont: r.cont, left: 64u32.wrapping_sub(r.used) })
    }

    /// Reads `n` bits (0 to 32): they are the low `n` bits of the result, with other bits
    /// of the stream above them. Past the start of the stream they are arbitrary.
    #[inline(always)]
    pub fn take(&mut self, n: u32) -> u64 {
        self.left = self.left.wrapping_sub(n);
        self.cont.wrapping_shr(self.left)
    }

    /// Makes at least 56 bits available as long as the stream has them (see `BitR::refill`).
    /// (The stream is kept as a slice that ends where `cont` does, and gets shorter: that
    /// the 8 bytes at its end are there is then seen from its length alone. Away from the
    /// start of the stream the bytes to go back by are taken to be 15 at most, which leaves
    /// 8 of 24; they are 8 at most unless more bits were read than there were.)
    #[inline(always)]
    pub fn refill(&mut self) {
        let used = 64u32.wrapping_sub(self.left);
        let len = self.rest.len();
        if len >= 24 {
            let bytes = (used >> 3) as usize & 15;
            self.left = self.left.wrapping_add(8 * bytes as u32);
            self.rest = &self.rest[..len - bytes];
            self.cont = u64::from_le_bytes(*self.rest.last_chunk::<8>().unwrap());
        } else if len > 8 {
            let bytes = ((used >> 3) as usize).min(len - 8);
            if bytes != 0 {
                self.left = self.left.wrapping_add(8 * bytes as u32);
                self.rest = &self.rest[..len - bytes];
                self.cont = u64::from_le_bytes(*self.rest.last_chunk::<8>().unwrap());
            }
        }
    }

    /// All bits were read, and no more.
    #[inline(always)]
    pub fn finished(&self) -> bool {
        self.rest.len() <= 8 && self.left == 0
    }
}

/// A forward bit writer over a slice: bits collect in a 64-bit accumulator, low bits first;
/// `flush` stores its whole bytes. What does not fit the slice is dropped, and `close` then
/// says so (as the reference implementation's `BIT_CStream_t`): what is written this way
/// is given up for a plainer form when it gets larger than its source.
pub(crate) struct BitW<'a> {
    buf: &'a mut [u8],
    pos: usize,
    /// The last position 8 bytes can be stored at; `pos` does not go beyond it, and a stream
    /// that gets there did not fit.
    last: usize,
    acc: u64,
    nbits: u32,
}

impl<'a> BitW<'a> {
    /// Writes into `buf` from its start. `flush` stores 8 bytes at a time, so the last 8
    /// bytes of `buf` take no data but those of the final flush.
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let last = buf.len().saturating_sub(8);
        BitW { buf, pos: 0, last, acc: 0, nbits: 0 }
    }

    /// Adds the low `n` bits of `v`. At most 57 bits between two flushes.
    #[inline(always)]
    pub fn add(&mut self, v: u64, n: u32) {
        debug_assert!(n + self.nbits < 64);
        self.acc |= (v & ((1u64 << n) - 1)) << self.nbits;
        self.nbits += n;
    }

    /// Like `add` for a `v` without bits above its low `n`.
    #[inline(always)]
    pub fn add_clean(&mut self, v: u64, n: u32) {
        debug_assert!(n + self.nbits < 64);
        debug_assert!(v >> n == 0);
        self.acc |= v << self.nbits;
        self.nbits += n;
    }

    /// Stores the whole bytes collected; up to 7 bits stay.
    #[inline(always)]
    pub fn flush(&mut self) {
        if let Some(to) = self.buf.get_mut(self.pos..self.pos + 8) {
            to.copy_from_slice(&self.acc.to_le_bytes());
        }
        let bytes = self.nbits >> 3;
        // (as the reference implementation's writer: the position stops at the last one,
        // which is what tells `close` that the stream did not fit; no flag to keep)
        self.pos = (self.pos + bytes as usize).min(self.last);
        self.acc >>= bytes * 8;
        self.nbits &= 7;
    }

    /// Ends the stream with its 1 bit; the number of bytes written, 0 if they did not fit.
    #[inline]
    pub fn close(mut self) -> usize {
        self.flush();
        self.add_clean(1, 1);
        self.flush();
        if self.pos >= self.last {
            return 0;
        }
        self.pos + (self.nbits > 0) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is written is read back last in, first out; what does not fit is no stream.
    /// The reader of the sequences reads what `BitR` reads, whatever the sizes of the reads
    /// and wherever the refills are; past the start of the stream it does not panic.
    #[test]
    fn seq_reader_as_reader() {
        let mut x = 0x9E3779B97F4A7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for len in 1..40usize {
            let mut src: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            *src.last_mut().unwrap() |= 1 << (next() % 8);
            let mut a = BitR::new(&src).unwrap();
            let mut b = SeqBits::new(&src).unwrap();
            let total = 8 * len as u32 + if len < 8 { 8 * (8 - len as u32) } else { 0 } - a.used;
            let mut read = 0;
            let mut since = 0;
            while read <= total + 200 {
                let k = (next() % 33) as u32;
                let va = a.read(k);
                let vb = b.take(k) & ((1u64 << k) - 1);
                read += k;
                since += k;
                if read <= total {
                    assert_eq!(va, vb, "len {len} after {read} bits");
                }
                // (as the decoder does: no more than 56 bits between refills)
                if since >= 24 {
                    since = 0;
                    a.refill();
                    b.refill();
                    assert_eq!(a.finished(), b.finished());
                    assert_eq!(a.overflown(), b.left > 64);
                }
            }
        }
    }

    #[test]
    fn writer_and_reader() {
        let mut buf = [0u8; 64];
        let mut w = BitW::new(&mut buf);
        for i in 0..40u64 {
            w.add(i * 37, 9);
            w.flush();
        }
        let n = w.close();
        assert_eq!(n, (40 * 9 + 1usize).div_ceil(8));
        let mut r = BitR::new(&buf[..n]).unwrap();
        for i in (0..40u64).rev() {
            r.refill();
            assert_eq!(r.read(9), (i * 37) & 511);
        }
        r.refill();
        assert!(r.finished());
        for size in 0..53 {
            let mut small = vec![0u8; size];
            let mut w = BitW::new(&mut small);
            for i in 0..40u64 {
                w.add(i * 37, 9);
                w.flush();
            }
            assert_eq!(w.close(), 0, "{size}");
        }
    }
}
