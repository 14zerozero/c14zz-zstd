//! Levels 13 to 22, the strategies `btlazy2`, `btopt`, `btultra` and `btultra2` (which the
//! parameters of small inputs have from level 9 on): frames decode with the C library and
//! here, are about as small as the C library's, and do not depend on what the compressor
//! did before.

mod common;

use std::io::{Read, Write};

/// Inputs of every size class of the parameter tables (up to 16 KB, 128 KB, 256 KB, more).
fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = Vec::new();
    for n in [0usize, 1, 6, 7, 8, 9, 12, 16, 17, 40, 300, 2000, 16 << 10, (16 << 10) + 1, 50_000, 128 << 10, (128 << 10) + 1, 200_000, 256 << 10, (256 << 10) + 1, 600_000] {
        v.push((format!("text-{n}"), common::text(n, n as u64 + 3)));
        v.push((format!("records-{n}"), common::records(n, n as u64 + 4)));
        v.push((format!("mixed-{n}"), common::mixed(n, n as u64 + 5)));
    }
    for n in [7usize, 100, 20_000, 140_000] {
        v.push((format!("zeros-{n}"), vec![0; n]));
        v.push((format!("random-{n}"), common::random(n, n as u64)));
    }
    v.push(("run-then-text".into(), [vec![7u8; 140000], common::text(50000, 3)].concat()));
    // (text, then data that does not compress, then the text again: blocks of several kinds)
    let t = common::text(150_000, 5);
    v.push(("far-repeat".into(), [t.clone(), common::random(300_000, 6), t].concat()));
    v
}

/// How much larger than the C library's a frame of the input `name` may be. The sequences
/// are the C library's wherever they were compared; the sizes differ by what the block
/// encoders differ by, which is most on the literals of `mixed` (up to 3 % at any level).
fn tolerance(name: &str) -> f64 {
    if name.starts_with("mixed") { 1.04 } else { 1.005 }
}

#[test]
fn frames_decode_and_are_near_c() {
    let mut d = c14zz_zstd::Decompressor::new();
    let mut back = Vec::new();
    for level in 9..=22 {
        let mut c = c14zz_zstd::Compressor::new(level);
        for (name, data) in inputs() {
            let frame = c.compress(&data);
            assert!(frame.len() <= c14zz_zstd::compress_bound(data.len()), "{name} level {level}: larger than the bound");
            let by_c = zstd::bulk::decompress(&frame, data.len()).unwrap_or_else(|e| panic!("{name} level {level}: C: {e}"));
            assert!(by_c == data, "{name} level {level}: C decodes to other data");
            d.decompress_to_vec(&frame, &mut back).unwrap_or_else(|e| panic!("{name} level {level}: {e}"));
            assert!(back == data, "{name} level {level}: other data");
            let by_c = zstd::bulk::compress(&data, level).unwrap().len();
            assert!(frame.len() as f64 <= by_c as f64 * tolerance(&name) + 16.0, "{name} level {level}: {} bytes, C {by_c}", frame.len());
        }
    }
}

/// Larger inputs, with windows that end within them at the levels below 20.
#[test]
fn large_inputs() {
    let data = common::mixed(9_500_000, 21);
    let text = common::text(5_000_000, 22);
    for (level, data, tolerance) in [(13, &data, 1.04), (16, &data, 1.04), (17, &text, 1.005), (19, &text[..2_500_000].to_vec(), 1.005), (22, &text[..1_500_000].to_vec(), 1.005)] {
        let frame = c14zz_zstd::compress(data, level);
        assert!(zstd::bulk::decompress(&frame, data.len()).unwrap() == *data, "level {level}: C");
        assert!(c14zz_zstd::decompress(&frame).unwrap() == *data, "level {level}");
        let by_c = zstd::bulk::compress(data, level).unwrap().len();
        assert!(frame.len() as f64 <= by_c as f64 * tolerance + 16.0, "level {level}: {} bytes, C {by_c}", frame.len());
    }
}

/// What a compressor has compressed before, at these levels or others, makes no difference
/// to the frames it writes.
#[test]
fn compressors_used_before_write_the_same_frames() {
    let inputs: Vec<Vec<u8>> = [0usize, 9, 100, 3000, 20_000, 70_000, 200_000, 300_000, 700_000]
        .iter()
        .enumerate()
        .flat_map(|(i, &n)| [common::text(n, i as u64 + 1), common::mixed(n, i as u64 + 50)])
        .collect();
    let mut kept = c14zz_zstd::Compressor::new(1);
    // (two rounds: in the second, every table has entries of the first; the levels between
    // leave entries of the other match finders in the same tables)
    for round in 0..2 {
        for level in [13, 3, 14, 15, 6, 16, 17, 1, 18, 19, 12, 20, 21, 22, 9, 11] {
            kept.set_level(level);
            for data in &inputs {
                let fresh = c14zz_zstd::Compressor::new(level).compress(data);
                assert!(kept.compress(data) == fresh, "level {level}, {} bytes, round {round}", data.len());
                if level >= 13 {
                    assert!(c14zz_zstd::decompress(&fresh).unwrap() == *data);
                }
            }
        }
    }
}

/// Streams in pieces, with and without flushes, of unknown size (the parameters of large
/// inputs, whatever the size) and of a size said before: decoded by the C library's stream
/// and this crate's, and about as small as the C library's.
#[test]
fn streams() {
    for (name, data) in inputs() {
        for (level, chunk, flush, pledge) in [(13, 1000, false, false), (15, 70_001, true, false), (16, 300_000, false, true), (18, 4097, true, false), (19, 99_999, false, false), (22, 131_072, false, false)] {
            let mut e = c14zz_zstd::stream::Encoder::new(Vec::new(), level);
            e.set_checksum(true);
            if pledge {
                e.set_pledged_size(data.len() as u64);
            }
            for c in data.chunks(chunk) {
                e.write_all(c).unwrap();
                if flush {
                    e.flush().unwrap();
                }
            }
            let frame = e.finish().unwrap();
            let what = format!("{name} level {level}");
            let by_c = zstd::stream::decode_all(&frame[..]).unwrap_or_else(|e| panic!("{what}: C: {e}"));
            assert!(by_c == data, "{what}: C decodes to other data");
            let mut back = Vec::new();
            c14zz_zstd::stream::Decoder::new(&frame[..]).read_to_end(&mut back).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(back == data, "{what}: the stream decodes to other data");
            if !flush {
                // (unknown size: the parameters of large inputs; C's stream has them too)
                let by_c = zstd::stream::encode_all(&data[..], level).unwrap().len();
                assert!(frame.len() as f64 <= by_c as f64 * tolerance(&name) + 64.0, "{what}: {} bytes, C's stream {by_c}", frame.len());
            }
        }
    }
}

/// A stream longer than twice its window and a block: the encoder's buffer moves, and
/// positions leave the window.
#[test]
fn stream_beyond_the_window() {
    let data = common::mixed(10_000_000, 31);
    for (level, chunk) in [(13, 100_000), (16, 131_072)] {
        let mut e = c14zz_zstd::stream::Encoder::new(Vec::new(), level);
        for c in data.chunks(chunk) {
            e.write_all(c).unwrap();
        }
        let frame = e.finish().unwrap();
        assert!(zstd::stream::decode_all(&frame[..]).unwrap() == data, "level {level}: C");
        assert!(c14zz_zstd::decompress(&frame).unwrap() == data, "level {level}");
        let by_c = zstd::stream::encode_all(&data[..], level).unwrap().len();
        assert!(frame.len() as f64 <= by_c as f64 * 1.04 + 64.0, "level {level}: {} bytes, C's stream {by_c}", frame.len());
    }
}
