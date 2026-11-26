//! Frames of the C library, decoded here.

mod common;

#[test]
fn c_frames_decode() {
    let mut d = c14zz_zstd::Decompressor::new();
    for (name, data) in common::inputs() {
        for level in [1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 16, 19] {
            if data.len() > 1_000_000 && level > 9 {
                continue;
            }
            let frame = zstd::bulk::compress(&data, level).unwrap();
            let back = c14zz_zstd::decompress(&frame).unwrap_or_else(|e| panic!("{name} level {level}: {e}"));
            assert!(back == data, "{name} level {level}: other data");
            let mut out = vec![0u8; data.len()];
            let n = d.decompress_into(&frame, &mut out).unwrap_or_else(|e| panic!("{name} level {level} into: {e}"));
            assert!(n == data.len() && out == data, "{name} level {level}: other data (into)");
            if !data.is_empty() {
                assert_eq!(d.decompress_into(&frame, &mut out[..data.len() - 1]), Err(c14zz_zstd::Error::OutputTooSmall), "{name}");
            }
        }
    }
}

#[test]
fn c_stream_frames_decode() {
    use std::io::Write;
    // without content size, with checksum, small and large windows
    for (name, data) in common::inputs() {
        for (level, wlog) in [(1, 0), (3, 10), (3, 17), (6, 0), (19, 0)] {
            if data.len() > 1_000_000 && level > 9 {
                continue;
            }
            let mut e = zstd::stream::Encoder::new(Vec::new(), level).unwrap();
            e.include_checksum(true).unwrap();
            if wlog > 0 {
                e.window_log(wlog).unwrap();
            }
            for chunk in data.chunks(77777) {
                e.write_all(chunk).unwrap();
                e.flush().unwrap();
            }
            let frame = e.finish().unwrap();
            let back = c14zz_zstd::decompress(&frame).unwrap_or_else(|e| panic!("{name} level {level}: {e}"));
            assert!(back == data, "{name} level {level}: other data");
            // two frames and a skippable one
            let mut two = frame.clone();
            two.extend_from_slice(&[0x53, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3]);
            two.extend_from_slice(&frame);
            let back = c14zz_zstd::decompress(&two).unwrap();
            assert!(back.len() == 2 * data.len() && back[data.len()..] == data[..], "{name}: two frames");
            if !frame.is_empty() {
                let mut bad = frame.clone();
                let n = bad.len();
                bad[n - 1] ^= 1;
                assert!(c14zz_zstd::decompress(&bad).is_err(), "{name}: checksum");
            }
        }
    }
}
