//! Frames made here: decoded by the C library and here.

mod common;

const LEVELS: [i32; 13] = [-5, 1, 2, 3, 4, 5, 6, 7, 9, 12, 15, 19, 22];

#[test]
fn frames_decode_with_c_and_here() {
    let mut d = c14zz_zstd::Decompressor::new();
    let mut back = Vec::new();
    for &level in &LEVELS {
        // one compressor for all inputs: its tables go from input to input
        let mut c = c14zz_zstd::Compressor::new(level);
        for (name, data) in common::inputs() {
            if data.len() > 1_000_000 && level > 9 {
                continue;
            }
            let frame = c.compress(&data);
            assert!(frame.len() <= c14zz_zstd::compress_bound(data.len()), "{name} level {level}: larger than the bound");
            let by_c = zstd::bulk::decompress(&frame, data.len()).unwrap_or_else(|e| panic!("{name} level {level}: C: {e}"));
            assert!(by_c == data, "{name} level {level}: C decodes to other data");
            d.decompress_to_vec(&frame, &mut back).unwrap_or_else(|e| panic!("{name} level {level}: {e}"));
            assert!(back == data, "{name} level {level}: other data");
            assert_eq!(c14zz_zstd::content_size(&frame), Ok(Some(data.len() as u64)));
            let mut into = vec![0u8; c14zz_zstd::compress_bound(data.len())];
            let n = c.compress_into(&data, &mut into).unwrap();
            assert!(zstd::bulk::decompress(&into[..n], data.len()).unwrap() == data, "{name} level {level}: into");
            if frame.len() > 1 {
                assert_eq!(c.compress_into(&data, &mut into[..frame.len() - 1]), Err(c14zz_zstd::Error::OutputTooSmall));
            }
        }
    }
}

#[test]
fn checksum_and_no_content_size() {
    let mut c = c14zz_zstd::Compressor::new(3);
    c.set_checksum(true);
    c.set_content_size(false);
    for (name, data) in common::inputs() {
        let frame = c.compress(&data);
        assert_eq!(c14zz_zstd::content_size(&frame), Ok(None));
        let by_c = zstd::stream::decode_all(&frame[..]).unwrap_or_else(|e| panic!("{name}: C: {e}"));
        assert!(by_c == data, "{name}: C decodes to other data");
        assert!(c14zz_zstd::decompress(&frame).unwrap() == data, "{name}");
        let mut bad = frame.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x10;
        assert_eq!(c14zz_zstd::decompress(&bad), Err(c14zz_zstd::Error::Checksum), "{name}");
    }
}

#[test]
fn ratio_near_c() {
    // not a benchmark: a guard against a match finder that stops finding
    for level in [1, 3, 6, 9] {
        for (name, data) in common::inputs() {
            if data.len() < 5000 {
                continue;
            }
            let here = c14zz_zstd::compress(&data, level).len();
            let c = zstd::bulk::compress(&data, level).unwrap().len();
            assert!(here as f64 <= c as f64 * 1.08 + 64.0, "{name} level {level}: {here} bytes, C {c}");
        }
    }
}
