//! Where a block of 128 KB is better ended early, after the reference implementation's
//! `ZSTD_splitBlock`: data whose statistics change within the block compresses better in
//! two blocks, each with its own tables. Cheap looks at the bytes decide: the stronger the
//! strategy, the closer the look.

use super::params::Strategy;

/// Counts of the events (bytes, or hashes of two bytes) of a piece of data.
struct Fingerprint {
    events: [u32; 1024],
    n: u64,
}

impl Fingerprint {
    fn new() -> Self {
        Fingerprint { events: [0; 1024], n: 0 }
    }

    /// The fingerprint of `src`: every `rate`-th position's event of `log` bits.
    fn record(&mut self, src: &[u8], rate: usize, log: u32) {
        self.events[..1 << log].fill(0);
        let limit = src.len() - 1;
        if log == 8 {
            for &b in src[..limit].iter().step_by(rate) {
                self.events[b as usize] += 1;
            }
        } else {
            for pair in src.windows(2).step_by(rate) {
                let h = (u16::from_le_bytes([pair[0], pair[1]]) as u32).wrapping_mul(0x9e3779b9) >> (32 - log);
                self.events[h as usize & 1023] += 1;
            }
        }
        self.n = (limit / rate) as u64;
    }

    /// The fingerprint of the bytes of `src`.
    fn bytes(src: &[u8]) -> Self {
        let mut f = Fingerprint::new();
        for &b in src {
            f.events[b as usize] += 1;
        }
        f.n = src.len() as u64;
        f
    }

    /// How far apart two fingerprints are, in events of `log` bits.
    fn distance(&self, other: &Fingerprint, log: u32) -> u64 {
        let mut d = 0u64;
        for (&a, &b) in self.events[..1 << log].iter().zip(&other.events[..1 << log]) {
            d += (a as i64 * other.n as i64 - b as i64 * self.n as i64).unsigned_abs();
        }
        d
    }

    /// Whether `new` is too different from `self` to be in one block with it.
    fn differs(&self, new: &Fingerprint, penalty: u64, log: u32) -> bool {
        self.distance(new, log) >= self.n * new.n * (14 + penalty) / 16
    }
}

/// How many bytes of `block` (128 KB) are to be its block, by the strategy's look at it.
pub(crate) fn block_size(block: &[u8], strategy: Strategy) -> usize {
    match strategy {
        Strategy::Fast => from_borders(block),
        Strategy::DFast => by_chunks(block, 43, 8),
        Strategy::Greedy | Strategy::Lazy => by_chunks(block, 11, 9),
        Strategy::Lazy2 | Strategy::BtLazy2 => by_chunks(block, 5, 10),
        _ => by_chunks(block, 1, 10),
    }
}

/// The block's chunks of 8 KB one after the other against all before them: the block ends
/// where one is too different.
fn by_chunks(block: &[u8], rate: usize, log: u32) -> usize {
    const CHUNK: usize = 8 << 10;
    let mut past = Fingerprint::new();
    let mut new = Fingerprint::new();
    past.record(&block[..CHUNK], rate, log);
    let mut penalty = 3;
    let mut pos = CHUNK;
    while pos + CHUNK <= block.len() {
        new.record(&block[pos..pos + CHUNK], rate, log);
        if past.differs(&new, penalty, log) {
            return pos;
        }
        for (a, &b) in past.events.iter_mut().zip(&new.events) {
            *a += b;
        }
        past.n += new.n;
        penalty = penalty.saturating_sub(1);
        pos += CHUNK;
    }
    block.len()
}

/// The fastest look: 512 bytes of the start, of the end and, if these differ, of the middle,
/// which is then on one side or between.
fn from_borders(block: &[u8]) -> usize {
    const SEGMENT: usize = 512;
    let n = block.len();
    let start = Fingerprint::bytes(&block[..SEGMENT]);
    let end = Fingerprint::bytes(&block[n - SEGMENT..]);
    if !start.differs(&end, 0, 8) {
        return n;
    }
    let middle = Fingerprint::bytes(&block[n / 2 - SEGMENT / 2..n / 2 + SEGMENT / 2]);
    let from_start = start.distance(&middle, 8);
    let from_end = end.distance(&middle, 8);
    if from_start.abs_diff(from_end) < (SEGMENT * SEGMENT / 3) as u64 {
        n / 2
    } else if from_start > from_end {
        n / 4
    } else {
        n / 4 * 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                b"etaoin shrdlu"[(x >> 24) as usize % 13]
            })
            .collect()
    }

    fn noise(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect()
    }

    /// Data of one kind is one block; where its kind changes, the block ends, at the
    /// change as closely as the strategy looks.
    #[test]
    fn splits_where_the_data_changes() {
        const N: usize = 128 << 10;
        let same = text(N, 1);
        for s in [Strategy::Fast, Strategy::DFast, Strategy::Lazy, Strategy::Lazy2, Strategy::BtOpt] {
            assert_eq!(block_size(&same, s), N, "{s:?}");
        }
        for change in [24 << 10, 40 << 10, 64 << 10, 104 << 10] {
            let mut data = text(change, 2);
            data.extend(noise(N - change, 3));
            for s in [Strategy::DFast, Strategy::Lazy, Strategy::Lazy2, Strategy::BtOpt] {
                assert_eq!(block_size(&data, s), change, "{s:?} {change}");
            }
            let size = block_size(&data, Strategy::Fast);
            assert!([N / 4, N / 2, N / 4 * 3].contains(&size) && size.abs_diff(change) <= N / 4, "{change}: {size}");
        }
    }
}
