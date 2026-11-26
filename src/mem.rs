//! Little-endian reads and writes at a byte position of a slice.

#[inline(always)]
pub(crate) fn rd16(s: &[u8], i: usize) -> u32 {
    u16::from_le_bytes(s[i..i + 2].try_into().unwrap()) as u32
}

#[inline(always)]
pub(crate) fn rd24(s: &[u8], i: usize) -> u32 {
    rd16(s, i) | (s[i + 2] as u32) << 16
}

#[inline(always)]
pub(crate) fn rd32(s: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(s[i..i + 4].try_into().unwrap())
}

#[inline(always)]
pub(crate) fn rd64(s: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(s[i..i + 8].try_into().unwrap())
}

/// The position of the highest bit set (`v` is not 0).
#[inline(always)]
pub(crate) fn highbit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

#[cold]
#[inline(never)]
fn beyond() -> ! {
    panic!("read beyond the data")
}

/// `rd32` for the match finders, with a `lim` they have at hand anyway (the last position
/// they read at): one comparison instead of the two of a slice. Positions beyond `lim` panic.
/// (Without the feature `unsafe` the 4 bytes are taken as the first ones of what is left of
/// `s` at `i`: that there are as many follows from the comparisons before, which the
/// compiler sees in this form, and not in that of a slice from `i` to `i + 4`.)
#[inline(always)]
pub(crate) fn rd32l(s: &[u8], lim: usize, i: usize) -> u32 {
    if i > lim || lim > s.len().wrapping_sub(4) || s.len() < 4 {
        beyond()
    }
    #[cfg(feature = "unsafe")]
    {
        // SAFETY: `i <= lim <= s.len() - 4` was just checked, so the 4 bytes at `i` are in `s`.
        unsafe { (s.as_ptr().add(i) as *const u32).read_unaligned() }.to_le()
    }
    #[cfg(not(feature = "unsafe"))]
    {
        match s[i..].first_chunk::<4>() {
            Some(bytes) => u32::from_le_bytes(*bytes),
            None => beyond(),
        }
    }
}

/// `rd64` like `rd32l`.
#[inline(always)]
pub(crate) fn rd64l(s: &[u8], lim: usize, i: usize) -> u64 {
    if i > lim || lim > s.len().wrapping_sub(8) || s.len() < 8 {
        beyond()
    }
    #[cfg(feature = "unsafe")]
    {
        // SAFETY: `i <= lim <= s.len() - 8` was just checked, so the 8 bytes at `i` are in `s`.
        unsafe { (s.as_ptr().add(i) as *const u64).read_unaligned() }.to_le()
    }
    #[cfg(not(feature = "unsafe"))]
    {
        match s[i..].first_chunk::<8>() {
            Some(bytes) => u64::from_le_bytes(*bytes),
            None => beyond(),
        }
    }
}

/// Asks the processor to bring the cache line of `s[i]` near; `i` may be anywhere. (With the
/// feature `unsafe` only: safe Rust has no way to say it.)
#[inline(always)]
pub(crate) fn prefetch<T>(s: &[T], i: usize) {
    #[cfg(all(feature = "unsafe", target_arch = "x86_64"))]
    {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
        // SAFETY: every x86-64 processor has SSE, which is all the call asks for; the
        // instruction reads nothing and does not fault on any address, and the address is
        // made without the promise of being in bounds (`wrapping_add`).
        unsafe { _mm_prefetch::<_MM_HINT_T0>(s.as_ptr().wrapping_add(i) as *const i8) }
    }
    #[cfg(not(all(feature = "unsafe", target_arch = "x86_64")))]
    {
        let _ = (s, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_reads() {
        let s: Vec<u8> = (1..=12).collect();
        for i in 0..=8 {
            assert_eq!(rd32l(&s, 8, i), rd32(&s, i));
        }
        for i in 0..=4 {
            assert_eq!(rd64l(&s, 4, i), rd64(&s, i));
        }
        assert_eq!(rd32l(&s[..4], 0, 0), 0x04030201);
        assert_eq!(rd64l(&s[..8], 0, 0), 0x0807060504030201);
    }

    /// A prefetch is nothing that can be seen, whatever the position.
    #[test]
    fn prefetch_anywhere() {
        let s = [1u32, 2, 3];
        for i in [0, 2, 3, 1000, usize::MAX / 8, usize::MAX] {
            prefetch(&s, i);
        }
        prefetch::<u8>(&[], 5);
        assert_eq!(s, [1, 2, 3]);
    }

    /// What must not be read: a position beyond the limit, a limit beyond the data.
    #[test]
    fn limited_reads_refuse() {
        let s: Vec<u8> = (1..=12).collect();
        let refused = |f: &dyn Fn()| std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err();
        assert!(refused(&|| {
            std::hint::black_box(rd32l(&s, 8, 9));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd32l(&s, 9, 9));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd32l(&s, usize::MAX, 9));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd32l(&s[..3], 0, 0));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd32l(&[], 0, 0));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd64l(&s, 4, 5));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd64l(&s, 5, 5));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd64l(&s, usize::MAX, 0));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd64l(&s[..7], 0, 0));
        }));
        assert!(refused(&|| {
            std::hint::black_box(rd64l(&[], usize::MAX - 7, 0));
        }));
    }
}
