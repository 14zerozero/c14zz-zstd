//! Damaged and cut frames: decoding must end, with an error or with data, and never panic.

mod common;

use std::io::Read;

fn try_all(frame: &[u8], limit: usize) {
    let mut d = c14zz_zstd::Decompressor::new();
    d.set_limit(limit);
    let mut out = Vec::new();
    let _ = d.decompress_to_vec(frame, &mut out);
    assert!(out.len() <= limit);
    let mut into = vec![0u8; limit.min(70000)];
    let _ = d.decompress_into(frame, &mut into);
    let mut s = c14zz_zstd::stream::Decoder::new(frame);
    s.set_window_limit(8 << 20);
    let mut buf = vec![0u8; 65536];
    let mut total = 0;
    while let Ok(n) = s.read(&mut buf) {
        total += n;
        if n == 0 || total > 4 * limit {
            break;
        }
    }
}

#[test]
fn damaged_frames() {
    let mut rng = common::Rng(0x1234_5678_9abc_def1);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for (_, data) in common::inputs() {
        if data.len() > 300_000 {
            continue;
        }
        for level in [1, 3, 9, 19] {
            frames.push(zstd::bulk::compress(&data, level).unwrap());
        }
        frames.push(c14zz_zstd::compress(&data, 3));
    }
    for frame in &frames {
        let limit = 2 << 20;
        // cut
        for _ in 0..20 {
            let at = rng.below(frame.len() as u64 + 1) as usize;
            try_all(&frame[..at], limit);
        }
        // bytes changed, mostly near the start where the headers and tables are
        for round in 0..150 {
            let mut bad = frame.clone();
            for _ in 0..1 + rng.below(3) {
                let span = if round % 3 == 0 { bad.len() } else { bad.len().min(200) };
                let at = rng.below(span as u64) as usize;
                bad[at] = match rng.below(3) {
                    0 => bad[at] ^ (1 << rng.below(8)),
                    1 => rng.next() as u8,
                    _ => bad[at].wrapping_add(1),
                };
            }
            try_all(&bad, limit);
        }
        // a piece removed, a piece doubled
        if frame.len() > 30 {
            let at = 6 + rng.below(frame.len() as u64 - 20) as usize;
            let n = 1 + rng.below(8) as usize;
            let mut bad = frame.clone();
            bad.drain(at..at + n);
            try_all(&bad, limit);
            let mut bad = frame.clone();
            let piece = bad[at..at + n].to_vec();
            bad.splice(at..at, piece);
            try_all(&bad, limit);
        }
    }
    // noise behind a frame header
    for _ in 0..2000 {
        let mut bad = vec![0x28, 0xb5, 0x2f, 0xfd];
        let n = rng.below(300) as usize;
        for _ in 0..n {
            bad.push(rng.next() as u8);
        }
        try_all(&bad, 1 << 20);
    }
}
