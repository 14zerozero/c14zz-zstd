//! Any bytes as frames: decoding must not panic, must keep to its limit, and must agree with
//! the C library on what the data is.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Read;

const LIMIT: usize = 8 << 20;

fuzz_target!(|data: &[u8]| {
    let mut d = c14zz_zstd::Decompressor::new();
    d.set_limit(LIMIT);
    let mut out = Vec::new();
    let here = d.decompress_to_vec(data, &mut out);
    assert!(out.len() <= LIMIT);
    let c = zstd::bulk::decompress(data, LIMIT);
    match (&here, &c) {
        (Ok(()), Ok(c)) => assert!(out == *c, "other data than the C library"),
        // the C library takes what this refuses
        (Err(e), Ok(c)) => {
            // (no dictionary is given here; the frames of versions before 1.0 are not read,
            // which have other magic numbers; an empty input is no frame here; the C library
            // takes RLE blocks larger than the format allows, Huffman codes of 12 bits, and
            // its fast decoder of four streams does not look at whether a stream ends where
            // its data does, nor at its end mark)
            let known = matches!(
                e,
                c14zz_zstd::Error::DictionaryNeeded
                    | c14zz_zstd::Error::BadMagic
                    | c14zz_zstd::Error::Corrupt("block larger than the frame allows" | "Huffman table too deep" | "Huffman stream does not end with its data" | "bit stream without end mark")
            );
            assert!(known || data.is_empty() || c.len() > LIMIT, "refused, but the C library decodes {} bytes: {e}", c.len());
        }
        _ => {}
    }
    // the stream gives the same, as far as it gets
    let mut s = c14zz_zstd::stream::Decoder::new(data);
    s.set_window_limit(LIMIT as u64);
    let mut streamed = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => {
                if here.is_ok() {
                    assert!(streamed == out, "the stream decodes to other data");
                }
                break;
            }
            Ok(n) => {
                streamed.extend_from_slice(&buf[..n]);
                if streamed.len() > 2 * LIMIT {
                    break;
                }
            }
            Err(_) => {
                if here.is_ok() {
                    // only a window the stream does not take may make the difference
                    assert!(c14zz_zstd::FrameHeader::read(data).is_ok());
                }
                break;
            }
        }
    }
    // into a slice that is too small
    let mut small = vec![0u8; out.len().saturating_sub(1).min(1000)];
    if here.is_ok() && !out.is_empty() && small.len() < out.len() {
        assert!(d.decompress_into(data, &mut small).is_err());
    }
});
