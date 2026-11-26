//! XXH64, the hash of the frame checksum (its low 32 bits).

const P1: u64 = 0x9E3779B185EBCA87;
const P2: u64 = 0xC2B2AE3D27D4EB4F;
const P3: u64 = 0x165667B19E3779F9;
const P4: u64 = 0x85EBCA77C2B2AE63;
const P5: u64 = 0x27D4EB2F165667C5;

#[inline(always)]
fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

#[inline(always)]
fn merge(h: u64, v: u64) -> u64 {
    (h ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

/// A running XXH64 with seed 0.
#[derive(Clone)]
pub struct Xxh64 {
    v: [u64; 4],
    total: u64,
    buf: [u8; 32],
    buffered: usize,
}

impl Default for Xxh64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Xxh64 {
    /// A hash of nothing yet.
    pub fn new() -> Self {
        Xxh64 { v: [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)], total: 0, buf: [0; 32], buffered: 0 }
    }

    #[inline(always)]
    fn stripes(v: &mut [u64; 4], data: &[u8]) {
        let [mut a, mut b, mut c, mut d] = *v;
        for s in data.as_chunks::<32>().0 {
            a = round(a, u64::from_le_bytes(s[0..8].try_into().unwrap()));
            b = round(b, u64::from_le_bytes(s[8..16].try_into().unwrap()));
            c = round(c, u64::from_le_bytes(s[16..24].try_into().unwrap()));
            d = round(d, u64::from_le_bytes(s[24..32].try_into().unwrap()));
        }
        *v = [a, b, c, d];
    }

    /// Adds `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buffered > 0 {
            let take = (32 - self.buffered).min(data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 32 {
                return;
            }
            let buf = self.buf;
            Self::stripes(&mut self.v, &buf);
            self.buffered = 0;
        }
        let whole = data.len() & !31;
        Self::stripes(&mut self.v, &data[..whole]);
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// The hash of all that was added.
    pub fn digest(&self) -> u64 {
        let mut h = if self.total >= 32 {
            let [a, b, c, d] = self.v;
            let h = a.rotate_left(1).wrapping_add(b.rotate_left(7)).wrapping_add(c.rotate_left(12)).wrapping_add(d.rotate_left(18));
            merge(merge(merge(merge(h, a), b), c), d)
        } else {
            self.v[2].wrapping_add(P5)
        };
        h = h.wrapping_add(self.total);
        let mut rest = &self.buf[..self.buffered];
        while rest.len() >= 8 {
            h = (h ^ round(0, u64::from_le_bytes(rest[..8].try_into().unwrap()))).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            h = (h ^ (u32::from_le_bytes(rest[..4].try_into().unwrap()) as u64).wrapping_mul(P1)).rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
            rest = &rest[4..];
        }
        for &b in rest {
            h = (h ^ (b as u64).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^ (h >> 32)
    }
}

/// XXH64 of `data` with seed 0.
pub fn xxh64(data: &[u8]) -> u64 {
    let mut h = Xxh64::new();
    h.update(data);
    h.digest()
}
