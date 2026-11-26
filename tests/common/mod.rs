//! Test data: deterministic generators.
#![allow(dead_code)]

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Text-like data: words of a small vocabulary, some numbers.
pub fn text(len: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    let words: Vec<String> = (0..300).map(|i| {
        let n = 2 + r.below(9) as usize;
        (0..n).map(|k| (b'a' + ((i * 7 + k * 13 + r.below(5) as usize) % 26) as u8) as char).collect()
    }).collect();
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        if r.below(10) == 0 {
            out.extend_from_slice(r.below(100000).to_string().as_bytes());
        } else {
            let z = (r.below(300) * r.below(300) / 300) as usize;
            out.extend_from_slice(words[z].as_bytes());
        }
        out.push(b' ');
    }
    out.truncate(len);
    out
}

/// Records like a database reply: field names, small integers, ids, strings.
pub fn records(len: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    let mut out = Vec::with_capacity(len + 256);
    let mut id = r.next();
    while out.len() < len {
        out.extend_from_slice(&[0x07]);
        out.extend_from_slice(b"_id\0");
        id += 1 + r.below(3);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(r.next() as u32).to_le_bytes());
        out.extend_from_slice(b"\x10count\0");
        out.extend_from_slice(&(r.below(1000) as u32).to_le_bytes());
        out.extend_from_slice(b"\x02name\0");
        let n = 5 + r.below(20) as usize;
        out.extend_from_slice(&(n as u32 + 1).to_le_bytes());
        for _ in 0..n {
            out.push(b'a' + r.below(16) as u8);
        }
        out.push(0);
        out.extend_from_slice(b"\x01score\0");
        out.extend_from_slice(&((r.below(10000) as f64) / 7.0).to_le_bytes());
        out.extend_from_slice(b"\x08active\0");
        out.push(r.below(2) as u8);
    }
    out.truncate(len);
    out
}

pub fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    (0..len).map(|_| r.next() as u8).collect()
}

/// Data of varying kinds: runs, repeats at long and short distances, random stretches.
pub fn mixed(len: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    let mut out: Vec<u8> = Vec::with_capacity(len + 70000);
    while out.len() < len {
        match r.below(6) {
            0 => {
                let big = r.below(8) == 0;
                let n = 1 + r.below(if big { 70000 } else { 300 }) as usize;
                let b = r.next() as u8;
                out.extend(std::iter::repeat_n(b, n));
            }
            1 | 2 if !out.is_empty() => {
                let big = r.below(10) == 0;
                let n = 3 + r.below(if big { 70000 } else { 200 }) as usize;
                let far = r.below(4) == 0;
                let dist = 1 + r.below(out.len().min(if far { 4_000_000 } else { 5000 }) as u64) as usize;
                let from = out.len() - dist;
                for i in 0..n {
                    out.push(out[from + i]);
                }
            }
            3 => {
                let n = 1 + r.below(100) as usize;
                for _ in 0..n {
                    out.push(r.next() as u8);
                }
            }
            _ => {
                let n = 1 + r.below(400) as usize;
                for _ in 0..n {
                    out.push(b"etaoin shrdlu\n"[r.below(14) as usize]);
                }
            }
        }
    }
    out.truncate(len);
    out
}

/// The inputs of the round trip tests: `(name, data)`.
pub fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = Vec::new();
    v.push(("empty".into(), vec![]));
    v.push(("one".into(), vec![42]));
    for n in [2usize, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1000] {
        v.push((format!("text-{n}"), text(n, n as u64)));
        v.push((format!("random-{n}"), random(n, n as u64)));
        v.push((format!("zeros-{n}"), vec![0; n]));
    }
    for n in [5000usize, 65535, 65536, 131071, 131072, 131073, 262144, 300000, 1 << 20, 3_000_000] {
        v.push((format!("text-{n}"), text(n, n as u64)));
        v.push((format!("records-{n}"), records(n, n as u64)));
        v.push((format!("mixed-{n}"), mixed(n, n as u64)));
    }
    v.push(("random-200000".into(), random(200000, 9)));
    v.push(("zeros-200000".into(), vec![0; 200000]));
    v.push(("zeros-5000000".into(), vec![0; 5_000_000]));
    v.push(("run-then-text".into(), [vec![7u8; 140000], text(50000, 3)].concat()));
    v.push(("mixed-9000000".into(), mixed(9_000_000, 77)));
    // a repeat further back than a 128 KB block, and than a small window
    let t = text(40000, 5);
    v.push(("far-repeat".into(), [t.clone(), random(600000, 6), t.clone(), random(3_000_000, 8), t].concat()));
    v
}

/// Small messages of one kind, as a dictionary is made for: `n` of them, of 100 bytes to
/// 2 KB.
pub fn messages(n: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut r = Rng(seed | 1);
    (0..n).map(|i| {
        let len = 100 + r.below(1900) as usize;
        if i % 3 == 0 { text(len, r.next()) } else { records(len, r.next()) }
    }).collect()
}

/// A dictionary of the C library's trainer for `messages`, of `size` bytes at most.
pub fn trained(size: usize) -> Vec<u8> {
    let samples = messages(3000, 0xD1C7);
    zstd::dict::from_samples(&samples, size).unwrap()
}
