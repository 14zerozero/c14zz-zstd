//! The streams, against the C library's and the one-call functions.

mod common;

use std::io::{Read, Write};

#[test]
fn encoder_frames_decode() {
    for (name, data) in common::inputs() {
        for (level, chunk, flush, pledge, checksum) in [(1, 1000, false, false, false), (3, 77777, true, false, true), (6, 300000, false, true, true), (9, 5, false, true, false)] {
            if chunk < 100 && data.len() > 300000 {
                continue;
            }
            let mut e = c14zz_zstd::stream::Encoder::new(Vec::new(), level);
            e.set_checksum(checksum);
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
            assert_eq!(c14zz_zstd::content_size(&frame).unwrap(), pledge.then_some(data.len() as u64), "{what}");
            let by_c = zstd::stream::decode_all(&frame[..]).unwrap_or_else(|e| panic!("{what}: C: {e}"));
            assert!(by_c == data, "{what}: C decodes to other data");
            assert!(c14zz_zstd::decompress(&frame).unwrap() == data, "{what}");
            let mut back = Vec::new();
            c14zz_zstd::stream::Decoder::new(&frame[..]).read_to_end(&mut back).unwrap_or_else(|e| panic!("{what}: stream: {e}"));
            assert!(back == data, "{what}: the stream decodes to other data");
        }
    }
}

/// A reader that gives a few bytes at a time.
struct Trickle<'a>(&'a [u8], usize);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.1.min(buf.len()).min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[test]
fn decoder_reads_c_frames() {
    for (name, data) in common::inputs() {
        for (level, wlog, checksum) in [(1, 0, false), (3, 10, true), (5, 17, true), (9, 0, true), (19, 0, false)] {
            if data.len() > 1_000_000 && level > 9 {
                continue;
            }
            let mut e = zstd::stream::Encoder::new(Vec::new(), level).unwrap();
            e.include_checksum(checksum).unwrap();
            if wlog > 0 {
                e.window_log(wlog).unwrap();
            }
            e.write_all(&data).unwrap();
            let mut frames = e.finish().unwrap();
            // a second frame with its size, and a skippable one between
            frames.extend_from_slice(&[0x5a, 0x2a, 0x4d, 0x18, 2, 0, 0, 0, 9, 9]);
            frames.extend_from_slice(&zstd::bulk::compress(&data, level).unwrap());
            let what = format!("{name} level {level}");
            for step in [usize::MAX, 4096, 7] {
                if step == 7 && data.len() > 300000 {
                    continue;
                }
                let mut d = c14zz_zstd::stream::Decoder::new(Trickle(&frames, step));
                let mut back = Vec::new();
                d.read_to_end(&mut back).unwrap_or_else(|e| panic!("{what}: {e}"));
                assert!(back.len() == 2 * data.len() && back[..data.len()] == data[..] && back[data.len()..] == data[..], "{what}: other data");
            }
            if checksum && !data.is_empty() {
                let cut = &frames[..frames.len() / 3];
                let mut back = Vec::new();
                assert!(c14zz_zstd::stream::Decoder::new(cut).read_to_end(&mut back).is_err(), "{what}: cut");
            }
        }
    }
}
