//! Any bytes compressed at a level given by the first byte: the frame must decode to them,
//! here and with the C library.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Some((&first, data)) = data.split_first() else { return };
    // (-2 to 22: every strategy, the tree and optimal ones from level 9 on for inputs this small)
    let level = (first % 25) as i32 - 2;
    let frame = c14zz_zstd::compress(data, level);
    assert!(frame.len() <= c14zz_zstd::compress_bound(data.len()));
    assert!(c14zz_zstd::decompress(&frame).unwrap() == data);
    assert!(zstd::bulk::decompress(&frame, data.len()).unwrap() == data);
    // the stream, in pieces, with a checksum
    let mut e = c14zz_zstd::stream::Encoder::new(Vec::new(), level);
    e.set_checksum(true);
    let piece = 1 + (first as usize * 37) % 5000;
    for c in data.chunks(piece) {
        e.write_all(c).unwrap();
        if first & 0x80 != 0 {
            e.flush().unwrap();
        }
    }
    let frame = e.finish().unwrap();
    assert!(c14zz_zstd::decompress(&frame).unwrap() == data);
    assert!(zstd::stream::decode_all(&frame[..]).unwrap() == data);
});
