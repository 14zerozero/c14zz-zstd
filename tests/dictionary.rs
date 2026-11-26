//! Dictionaries: frames of the C library that were made with one, decoded here with it;
//! frames made here with one, decoded by the C library and here.

mod common;

use c14zz_zstd::{Compressor, Decompressor, Dictionary, Error};
use std::io::{Read, Write};

const LEVELS: [i32; 9] = [-3, 1, 2, 3, 5, 7, 12, 16, 19];

/// A frame of the C library for `data` with the dictionary `dict`.
fn c_frame(data: &[u8], level: i32, dict: &[u8]) -> Vec<u8> {
    zstd::bulk::Compressor::with_dictionary(level, dict).unwrap().compress(data).unwrap()
}

/// A stream of the C library: no content size, a checksum, flushed in pieces.
fn c_stream(data: &[u8], level: i32, dict: &[u8], window_log: u32) -> Vec<u8> {
    let mut e = zstd::stream::Encoder::with_dictionary(Vec::new(), level, dict).unwrap();
    e.include_checksum(true).unwrap();
    if window_log > 0 {
        e.window_log(window_log).unwrap();
    }
    for chunk in data.chunks(50_001) {
        e.write_all(chunk).unwrap();
        e.flush().unwrap();
    }
    e.finish().unwrap()
}

/// Decodes `frame` in all the ways there are and compares with `data`.
fn decodes(d: &mut Decompressor, dictionary: &Dictionary, frame: &[u8], data: &[u8], what: &str) {
    d.set_dictionary(dictionary);
    let mut out = Vec::new();
    d.decompress_to_vec(frame, &mut out).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(out == data, "{what}: other data");
    let mut room = vec![0u8; data.len()];
    let n = d.decompress_into(frame, &mut room).unwrap_or_else(|e| panic!("{what}, into: {e}"));
    assert!(n == data.len() && room == data, "{what}: other data (into)");
    if !data.is_empty() {
        assert_eq!(d.decompress_into(frame, &mut room[..data.len() - 1]), Err(Error::OutputTooSmall), "{what}");
        d.set_limit(data.len() - 1);
        assert_eq!(d.decompress_to_vec(frame, &mut out), Err(Error::OutputTooSmall), "{what}");
        d.set_limit(usize::MAX);
    }
    assert!(c14zz_zstd::decompress_with_dictionary(frame, dictionary).unwrap() == data, "{what}: other data (one call)");
    let mut s = c14zz_zstd::stream::Decoder::new(frame);
    s.set_dictionary(dictionary);
    out.clear();
    s.read_to_end(&mut out).unwrap_or_else(|e| panic!("{what}, stream: {e}"));
    assert!(out == data, "{what}: other data (stream)");
}

#[test]
fn small_messages() {
    let trained = common::trained(16 << 10);
    let raw = common::messages(40, 77).concat();
    let mut d = Decompressor::new();
    for (kind, bytes) in [("trained", &trained), ("raw", &raw)] {
        let dictionary = Dictionary::new(bytes).unwrap();
        assert_eq!(dictionary.id() != 0, kind == "trained");
        assert_eq!(dictionary.id(), zstd::zstd_safe::get_dict_id_from_dict(bytes).map_or(0, |id| id.get()));
        for level in LEVELS {
            let mut c = zstd::bulk::Compressor::with_dictionary(level, bytes).unwrap();
            for (i, m) in common::messages(60, 5).iter().enumerate() {
                let frame = c.compress(m).unwrap();
                decodes(&mut d, &dictionary, &frame, m, &format!("{kind} level {level} message {i}"));
            }
        }
    }
}

#[test]
fn all_inputs() {
    let trained = common::trained(100 << 10);
    let raw = [common::text(70_000, 1), common::mixed(200_000, 2)].concat();
    let mut d = Decompressor::new();
    for (kind, bytes) in [("trained", &trained), ("raw", &raw)] {
        let dictionary = Dictionary::new(bytes).unwrap();
        for (name, data) in common::inputs() {
            for level in [1, 3, 6, 13, 19] {
                if data.len() > 1_000_000 && level > 6 {
                    continue;
                }
                decodes(&mut d, &dictionary, &c_frame(&data, level, bytes), &data, &format!("{kind} {name} level {level}"));
            }
            // streams, with windows smaller than the dictionary and than the data
            for (level, window_log) in [(1, 0), (3, 10), (5, 15), (19, 0)] {
                if data.len() > 1_000_000 && level > 6 {
                    continue;
                }
                decodes(&mut d, &dictionary, &c_stream(&data, level, bytes, window_log), &data, &format!("{kind} {name} stream level {level}"));
            }
        }
    }
}

/// Frames in a row; a decompressor that goes from one dictionary to another and to none.
#[test]
fn several_frames_and_dictionaries() {
    let a_bytes = common::trained(8 << 10);
    let b_bytes = zstd::dict::from_samples(&common::messages(2000, 99), 12 << 10).unwrap();
    let (a, b) = (Dictionary::new(&a_bytes).unwrap(), Dictionary::new(&b_bytes).unwrap());
    assert_ne!(a.id(), b.id());
    let messages = common::messages(30, 11);
    let mut d = Decompressor::new();
    let mut s_all = Vec::new();
    let mut all = Vec::new();
    for (i, m) in messages.iter().enumerate() {
        let (fa, fb, plain) = (c_frame(m, 1 + (i % 7) as i32, &a_bytes), c_frame(m, 3, &b_bytes), zstd::bulk::compress(m, 3).unwrap());
        d.set_dictionary(&a);
        assert!(d.decompress(&fa, m.len()).unwrap() == *m);
        assert_eq!(d.decompress(&fb, m.len()), Err(Error::WrongDictionary));
        // a frame that names no dictionary is read with any
        assert!(d.decompress(&plain, m.len()).unwrap() == *m);
        d.set_dictionary(&b);
        assert!(d.decompress(&fb, m.len()).unwrap() == *m);
        assert_eq!(d.decompress(&fa, m.len()), Err(Error::WrongDictionary));
        d.clear_dictionary();
        assert_eq!(d.decompress(&fa, m.len()), Err(Error::DictionaryNeeded));
        assert_eq!(c14zz_zstd::decompress(&fa), Err(Error::DictionaryNeeded));
        assert!(d.decompress(&plain, m.len()).unwrap() == *m);
        assert_eq!(c14zz_zstd::FrameHeader::read(&fa).unwrap().dictionary_id, a.id());
        // in a row: with the dictionary, a skippable frame, without, with
        s_all.extend_from_slice(&fa);
        s_all.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 2, 0, 0, 0, 9, 9]);
        s_all.extend_from_slice(&plain);
        all.extend_from_slice(m);
        all.extend_from_slice(m);
    }
    d.set_dictionary(&a);
    assert!(d.decompress(&s_all, all.len()).unwrap() == all);
    let mut s = c14zz_zstd::stream::Decoder::new(&s_all[..]);
    s.set_dictionary(&a);
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    assert!(out == all);
    let mut s = c14zz_zstd::stream::Decoder::new(&s_all[..]);
    let e = s.read_to_end(&mut out).unwrap_err();
    assert_eq!(e.get_ref().and_then(|e| e.downcast_ref::<Error>()), Some(&Error::DictionaryNeeded));
    s = c14zz_zstd::stream::Decoder::new(&s_all[..]);
    s.set_dictionary(&b);
    let e = s.read_to_end(&mut out).unwrap_err();
    assert_eq!(e.get_ref().and_then(|e| e.downcast_ref::<Error>()), Some(&Error::WrongDictionary));
}

/// Bytes that start as a dictionary and are not one: an error, or a dictionary the C
/// library takes as well; and no panic when frames are read with what was taken.
#[test]
fn damaged_dictionaries() {
    let bytes = common::trained(4 << 10);
    let message = &common::messages(1, 3)[0];
    let frame = c_frame(message, 3, &bytes);
    let mut rng = common::Rng(0xD1C7_0000_1234_5679);
    let mut d = Decompressor::new();
    d.set_limit(1 << 20);
    let mut try_one = |bad: &[u8]| {
        let c_out = zstd::bulk::Decompressor::with_dictionary(bad).and_then(|mut c| c.decompress(&frame, 1 << 20));
        match Dictionary::new(bad) {
            Ok(dictionary) => {
                d.set_dictionary(&dictionary);
                let mut out = Vec::new();
                let here = d.decompress_to_vec(&frame, &mut out);
                if let (Ok(()), Ok(c_out)) = (&here, &c_out) {
                    assert!(out == *c_out, "other data than the C library with a damaged dictionary");
                }
                // (the C library does not say that a dictionary is not one before it is used)
                assert_eq!(here.is_ok(), c_out.is_ok(), "{here:?} here, {:?} there", c_out.as_ref().map(|o| o.len()));
            }
            Err(e) => {
                assert!(matches!(e, Error::BadDictionary(_)), "{e}");
                // (the C library takes Huffman codes of 12 bits, one more than the format has)
                assert!(c_out.is_err() || e == Error::BadDictionary("Huffman table too deep"), "refused, but the C library takes it: {e}");
            }
        }
    };
    for cut in 0..bytes.len().min(600) {
        try_one(&bytes[..cut]);
    }
    for _ in 0..3000 {
        let mut bad = bytes.clone();
        // most of the damage in the tables, some in the content
        let at = if rng.below(4) > 0 { rng.below(300.min(bad.len() as u64)) } else { rng.below(bad.len() as u64) } as usize;
        match rng.below(3) {
            0 => bad[at] ^= 1 << rng.below(8),
            1 => bad[at] = rng.next() as u8,
            _ => {
                bad.remove(at);
            }
        }
        try_one(&bad);
    }
}

const ALL_LEVELS: [i32; 25] = [-20, -3, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];

/// Checks that `frame`, made here with the dictionary of `bytes`, is `data` for the C
/// library and here.
fn c_decodes(frame: &[u8], data: &[u8], bytes: &[u8], dictionary: &Dictionary, what: &str) {
    let by_c = zstd::bulk::Decompressor::with_dictionary(bytes).unwrap().decompress(frame, data.len()).unwrap_or_else(|e| panic!("{what}: the C library: {e}"));
    assert!(by_c == data, "{what}: other data for the C library");
    let mut by_stream = Vec::new();
    zstd::stream::Decoder::with_dictionary(frame, bytes).unwrap().read_to_end(&mut by_stream).unwrap_or_else(|e| panic!("{what}: the C library's stream: {e}"));
    assert!(by_stream == data, "{what}: other data for the C library's stream");
    assert!(c14zz_zstd::decompress_with_dictionary(frame, dictionary).unwrap_or_else(|e| panic!("{what}: {e}")) == data, "{what}: other data");
    let mut s = c14zz_zstd::stream::Decoder::new(frame);
    s.set_dictionary(dictionary);
    by_stream.clear();
    s.read_to_end(&mut by_stream).unwrap_or_else(|e| panic!("{what}, stream: {e}"));
    assert!(by_stream == data, "{what}: other data (stream)");
}

/// Small messages at every level, with a compressor that is kept: read by the C library,
/// about as small as its frames, and the same frames as from a compressor that is new.
#[test]
fn small_messages_compressed() {
    let trained = common::trained(16 << 10);
    let raw = common::messages(40, 77).concat();
    let messages = common::messages(120, 5);
    for (kind, bytes) in [("trained", &trained), ("raw", &raw)] {
        let dictionary = Dictionary::new(bytes).unwrap();
        let mut kept = Compressor::new(1);
        kept.set_dictionary(&dictionary);
        let mut plain_total = 0;
        for level in ALL_LEVELS {
            kept.set_level(level);
            let mut c = zstd::bulk::Compressor::with_dictionary(level, bytes).unwrap();
            let (mut here_total, mut c_total) = (0, 0);
            for (i, m) in messages.iter().enumerate() {
                let frame = kept.compress(m);
                let what = format!("{kind} level {level} message {i}");
                assert_eq!(c14zz_zstd::FrameHeader::read(&frame).unwrap().dictionary_id, dictionary.id(), "{what}");
                c_decodes(&frame, m, bytes, &dictionary, &what);
                if i % 8 == 0 {
                    let mut fresh = Compressor::new(level);
                    fresh.set_dictionary(&dictionary);
                    assert!(fresh.compress(m) == frame, "{what}: a new compressor writes another frame");
                    assert!(c14zz_zstd::compress_with_dictionary(m, level, &dictionary) == frame, "{what}: the one call writes another frame");
                }
                here_total += frame.len();
                c_total += c.compress(m).unwrap().len();
                if level == 3 {
                    plain_total += c14zz_zstd::compress(m, 3).len();
                }
            }
            // (not the same search as the C library's for small data with a dictionary:
            // somewhat larger or smaller frames)
            assert!(here_total as f64 <= c_total as f64 * 1.03, "{kind} level {level}: {here_total} bytes here, {c_total} with the C library");
            if level == 3 {
                assert!(here_total < plain_total, "{kind}: {here_total} bytes with the dictionary, {plain_total} without");
            }
        }
    }
}

/// A compressor that has compressed other data, with other dictionaries and without one,
/// in frames small and large, writes the frames a new one writes.
#[test]
fn compressor_used_before_writes_the_same_frames() {
    let a_bytes = common::trained(40 << 10);
    let b_bytes = common::text(3000, 9);
    let (a, b) = (Dictionary::new(&a_bytes).unwrap(), Dictionary::raw(&b_bytes));
    let mut inputs = common::messages(12, 31);
    for (i, n) in [0usize, 1, 7, 8, 9, 20, 3000, 20_000, 130_000, 140_000, 300_000, 700_000].into_iter().enumerate() {
        inputs.push(common::records(n, i as u64 + 1));
        inputs.push(common::mixed(n, i as u64 + 50));
    }
    let mut kept = Compressor::new(1);
    for round in 0..2 {
        for level in [1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 16, 19, 22, -3] {
            kept.set_level(level);
            for (i, data) in inputs.iter().enumerate() {
                for (name, dictionary) in [("a", &a), ("b", &b)] {
                    let mut fresh = Compressor::new(level);
                    fresh.set_dictionary(dictionary);
                    let fresh = fresh.compress(data);
                    kept.set_dictionary(dictionary);
                    let what = format!("dictionary {name}, level {level}, input {i} of {} bytes, round {round}", data.len());
                    assert!(kept.compress(data) == fresh, "{what}: kept compressor");
                    // a frame that does not fit leaves nothing behind either
                    let mut small = vec![0u8; fresh.len() / 2];
                    assert_eq!(kept.compress_into(data, &mut small), Err(Error::OutputTooSmall), "{what}");
                    let mut room = vec![0u8; c14zz_zstd::compress_bound(data.len()) + 16];
                    let n = kept.compress_into(data, &mut room).unwrap();
                    assert!(room[..n] == fresh[..], "{what}: kept compressor, into");
                    assert!(c14zz_zstd::compress_with_dictionary(data, level, dictionary) == fresh, "{what}: one call");
                    assert!(c14zz_zstd::decompress_with_dictionary(&fresh, dictionary).unwrap() == *data, "{what}");
                }
                if i % 3 == round {
                    kept.clear_dictionary();
                    assert!(kept.compress(data) == c14zz_zstd::Compressor::new(level).compress(data), "level {level}, input {i}: without dictionary");
                    assert!(c14zz_zstd::compress(data, level) == kept.compress(data));
                }
            }
        }
    }
}

/// All inputs, with dictionaries smaller and larger than them and than the windows: frames
/// and streams made here are read by the C library.
#[test]
fn all_inputs_compressed() {
    let trained = common::trained(100 << 10);
    let raw = [common::text(70_000, 1), common::mixed(200_000, 2)].concat();
    let tiny = b"tiny".to_vec();
    for (kind, bytes) in [("trained", &trained), ("raw", &raw), ("tiny", &tiny)] {
        let dictionary = Dictionary::new(bytes).unwrap();
        let mut c = Compressor::new(1);
        c.set_dictionary(&dictionary);
        for (name, data) in common::inputs() {
            for level in [-5, 1, 2, 3, 4, 5, 6, 8, 12, 13, 16, 19, 22] {
                if data.len() > 1_000_000 && level > 6 {
                    continue;
                }
                c.set_level(level);
                c.set_checksum(level % 2 == 0);
                c.set_content_size(level % 3 != 0);
                let frame = c.compress(&data);
                assert!(frame.len() <= c14zz_zstd::compress_bound(data.len()) + 8, "{kind} {name} level {level}: {} bytes", frame.len());
                c_decodes(&frame, &data, bytes, &dictionary, &format!("{kind} {name} level {level}"));
                // the stream, in pieces, flushed now and then, with and without its size
                let mut e = c14zz_zstd::stream::Encoder::new(Vec::new(), level);
                e.set_dictionary(&dictionary);
                e.set_checksum(true);
                if level % 2 == 0 {
                    e.set_pledged_size(data.len() as u64);
                }
                for (i, piece) in data.chunks(33_333).enumerate() {
                    e.write_all(piece).unwrap();
                    if i % 5 == 4 {
                        e.flush().unwrap();
                    }
                }
                c_decodes(&e.finish().unwrap(), &data, bytes, &dictionary, &format!("{kind} {name} stream level {level}"));
            }
        }
    }
}

/// Writes inputs for the fuzz targets `dictionary` and `with_dictionary` to start from:
/// small dictionaries of the trainer and of content only, each with a frame made with it,
/// or with a message to make one of.
#[test]
#[ignore = "writes files into fuzz/corpus"]
fn fuzz_seeds() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/dictionary");
    std::fs::create_dir_all(&dir).unwrap();
    let messages = common::messages(8, 21);
    let trained = zstd::dict::from_samples(&common::messages(3000, 0xD1C7), 1500).unwrap();
    let raw = messages[7][..700].to_vec();
    for (kind, dict) in [("trained", &trained), ("raw", &raw)] {
        for (i, m) in messages.iter().enumerate() {
            let level = [1, 3, 6, 19][i % 4];
            let frame = if i % 2 == 0 { c_frame(&m[..m.len().min(600)], level, dict) } else { c_stream(m, level, dict, 10) };
            let mut seed = (dict.len() as u16).to_le_bytes().to_vec();
            seed.extend_from_slice(dict);
            seed.extend_from_slice(&frame);
            std::fs::write(dir.join(format!("{kind}-{i}")), seed).unwrap();
            // for the target `with_dictionary`: a level, the dictionary, a message
            let mut seed = vec![(i * 5) as u8];
            seed.extend_from_slice(&(dict.len() as u16).to_le_bytes());
            seed.extend_from_slice(dict);
            seed.extend_from_slice(m);
            let dir = dir.with_file_name("with_dictionary");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{kind}-{i}")), seed).unwrap();
        }
    }
}
