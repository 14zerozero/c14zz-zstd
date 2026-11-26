//! The decoder's copy kernel on small frames made here: small enough to run under Miri
//! (`cargo +nightly miri test --test kernel`), which checks every read and write of it.

mod common;

fn patterns() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    let mut r = common::Rng(99);
    // repeats at every small distance, with literals of all small lengths between
    // (under Miri: a few of them, it runs some thousand times slower)
    let dists: &[usize] = if cfg!(miri) { &[1, 2, 3, 7, 8, 15, 16, 17] } else { &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20] };
    for &dist in dists {
        let mut d: Vec<u8> = (0..dist).map(|i| (i * 7 + dist) as u8).collect();
        for round in 0..if cfg!(miri) { 5 } else { 12 } {
            let n = 3 + (round * 5) % 40;
            for _ in 0..n {
                d.push(d[d.len() - dist]);
            }
            for _ in 0..round * 2 {
                d.push(r.next() as u8);
            }
        }
        v.push(d);
    }
    let scale = if cfg!(miri) { 5 } else { 1 };
    v.push(common::text(3000 / scale, 1));
    v.push(common::records(2500 / scale, 2));
    v.push(common::mixed(4000 / scale, 3));
    v.push(vec![5u8; 700]);
    v
}

#[test]
fn small_frames() {
    let mut d = c14zz_zstd::Decompressor::new();
    for data in patterns() {
        let levels: &[i32] = if cfg!(miri) { &[1] } else { &[1, 3, 6] };
        for &level in levels {
            let frame = c14zz_zstd::compress(&data, level);
            // into a slice of the exact size: the last sequences take the careful path
            let mut exact = vec![0u8; data.len()];
            assert_eq!(d.decompress_into(&frame, &mut exact), Ok(data.len()));
            assert!(exact == data);
            // into a vector: room behind the data
            let mut out = Vec::new();
            d.decompress_to_vec(&frame, &mut out).unwrap();
            assert!(out == data);
            // cut and changed
            for cut in [frame.len() - 1, frame.len() / 2, 7] {
                let _ = d.decompress_to_vec(&frame[..cut.min(frame.len())], &mut out);
            }
            let mut bad = frame.clone();
            for at in (6..bad.len()).step_by(bad.len() / 6 + 1) {
                bad[at] ^= 0x41;
                let _ = d.decompress_to_vec(&bad, &mut out);
            }
        }
    }
}

#[test]
fn found_by_fuzzing() {
    // raw literals with less than 16 bytes of input behind them, and a sequence without
    // literals: the fast path read behind the input
    let frame = include_bytes!("data/fuzz-short-raw-literals.zst");
    assert!(c14zz_zstd::decompress(frame).is_err());
}
