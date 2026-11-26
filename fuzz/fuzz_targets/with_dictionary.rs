//! Any bytes compressed with any bytes as their dictionary, at a level given by the first
//! byte: the frame must decode to them with the dictionary, here and with the C library,
//! and a compressor that is kept from input to input must write the frame a new one
//! writes. The second and third bytes are the size of the dictionary, which follows; the
//! rest is the data. (`cargo test --test dictionary -- --ignored` writes inputs to start
//! from into `fuzz/corpus/with_dictionary`.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::io::{Read, Write};

thread_local! {
    static KEPT: RefCell<c14zz_zstd::Compressor> = RefCell::new(c14zz_zstd::Compressor::new(1));
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let first = data[0];
    let level = (first % 26) as i32 - 3;
    let size = u16::from_le_bytes([data[1], data[2]]) as usize;
    let rest = &data[3..];
    let (dict, data) = rest.split_at(size.min(rest.len()));
    // (bytes that start as a dictionary of the trainer and are not one: nothing to do)
    let Ok(dictionary) = c14zz_zstd::Dictionary::new(dict) else { return };
    let mut fresh = c14zz_zstd::Compressor::new(level);
    fresh.set_dictionary(&dictionary);
    let frame = fresh.compress(data);
    assert!(frame.len() <= c14zz_zstd::compress_bound(data.len()) + 4);
    assert!(c14zz_zstd::FrameHeader::read(&frame).unwrap().dictionary_id == dictionary.id());
    KEPT.with_borrow_mut(|kept| {
        kept.set_level(level);
        kept.set_dictionary(&dictionary);
        assert!(kept.compress(data) == frame, "a compressor used before writes another frame");
        if first & 0x40 != 0 {
            // a frame without dictionary in between
            kept.clear_dictionary();
            assert!(kept.compress(data) == c14zz_zstd::compress(data, level));
        }
    });
    assert!(c14zz_zstd::decompress_with_dictionary(&frame, &dictionary).unwrap() == data);
    // (the C library may refuse to make a dictionary of what is one here: see the target
    // `dictionary`)
    let c = zstd::bulk::Decompressor::with_dictionary(dict);
    if let Ok(mut c) = c {
        assert!(c.decompress(&frame, data.len()).unwrap() == data);
    }
    // the stream, in pieces
    let mut e = c14zz_zstd::stream::Encoder::new(Vec::new(), level);
    e.set_dictionary(&dictionary);
    e.set_checksum(true);
    let piece = 1 + (first as usize * 37) % 5000;
    for c in data.chunks(piece) {
        e.write_all(c).unwrap();
        if first & 0x80 != 0 {
            e.flush().unwrap();
        }
    }
    let frame = e.finish().unwrap();
    let mut s = c14zz_zstd::stream::Decoder::new(&frame[..]);
    s.set_dictionary(&dictionary);
    let mut back = Vec::new();
    s.read_to_end(&mut back).unwrap();
    assert!(back == data);
    if let Ok(mut c) = zstd::stream::Decoder::with_dictionary(&frame[..], dict) {
        back.clear();
        c.read_to_end(&mut back).unwrap();
        assert!(back == data);
    }
});
