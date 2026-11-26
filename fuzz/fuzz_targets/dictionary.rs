//! Any bytes as a dictionary and frames to decode with it: neither making the dictionary
//! nor decoding may panic, decoding must keep to its limit, and must agree with the C
//! library on what the data is. The first two bytes are the size of the dictionary, which
//! follows; the rest are the frames. (`cargo test --test dictionary -- --ignored` writes
//! inputs to start from into `fuzz/corpus/dictionary`.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Read;

const LIMIT: usize = 4 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let size = u16::from_le_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    let (dict, frames) = rest.split_at(size.min(rest.len()));
    let c = zstd::bulk::Decompressor::with_dictionary(dict).and_then(|mut c| c.decompress(frames, LIMIT));
    // content only, whatever the bytes are: no panic, and the stream agrees
    decode(&c14zz_zstd::Dictionary::raw(dict), frames);
    let dictionary = match c14zz_zstd::Dictionary::new(dict) {
        Ok(d) => d,
        Err(e) => {
            assert!(matches!(e, c14zz_zstd::Error::BadDictionary(_)));
            // (the C library takes Huffman codes of 12 bits, one more than the format has)
            let known = e == c14zz_zstd::Error::BadDictionary("Huffman table too deep");
            assert!(c.is_err() || known, "the dictionary is refused, but the C library decodes with it: {e}");
            return;
        }
    };
    let here = decode(&dictionary, frames);
    match (&here, &c) {
        (Ok(out), Ok(c)) => assert!(out == c, "other data than the C library"),
        (Err(e), Ok(c)) => {
            // (as in the target `decode`; and the C library takes Huffman codes of 12 bits, and
            // its fast decoder of four streams does not look at whether a stream ends where
            // its data does, nor at its end mark)
            let known = matches!(
                e,
                c14zz_zstd::Error::BadMagic | c14zz_zstd::Error::Corrupt("block larger than the frame allows" | "Huffman table too deep" | "Huffman stream does not end with its data" | "bit stream without end mark")
            );
            assert!(known || frames.is_empty() || c.len() > LIMIT, "refused, but the C library decodes {} bytes: {e}", c.len());
        }
        _ => {}
    }
});

/// Decodes at once and as a stream, which must give the same as far as it gets.
fn decode(dictionary: &c14zz_zstd::Dictionary, frames: &[u8]) -> Result<Vec<u8>, c14zz_zstd::Error> {
    let mut d = c14zz_zstd::Decompressor::new();
    d.set_limit(LIMIT);
    d.set_dictionary(dictionary);
    let mut out = Vec::new();
    let here = d.decompress_to_vec(frames, &mut out);
    assert!(out.len() <= LIMIT);
    let mut s = c14zz_zstd::stream::Decoder::new(frames);
    s.set_window_limit(LIMIT as u64);
    s.set_dictionary(dictionary);
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
                    assert!(c14zz_zstd::FrameHeader::read(frames).is_ok());
                }
                break;
            }
        }
    }
    // into a slice that is too small
    let mut small = vec![0u8; out.len().saturating_sub(1).min(1000)];
    if here.is_ok() && !out.is_empty() && small.len() < out.len() {
        assert!(d.decompress_into(frames, &mut small).is_err());
    }
    here.map(|()| out)
}
