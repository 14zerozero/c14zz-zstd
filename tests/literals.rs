//! Literals whose Huffman tree is deeper than the codes may be long: the frames are to be
//! as small as the C library's.

/// Records of binary fields and hexadecimal text that does not repeat: 16 frequent bytes
/// and many rare ones.
fn records(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let mut out = Vec::with_capacity(len + 256);
    let mut i = 0u64;
    while out.len() < len {
        out.extend_from_slice(&i.to_be_bytes());
        out.extend_from_slice(b"\x02name\x00\x10\x00\x00\x00");
        out.extend_from_slice(format!("user-{i:010}\0\x02pad\0").as_bytes());
        for _ in 0..7 {
            out.extend_from_slice(format!("{:016x}", next()).as_bytes());
        }
        out.extend_from_slice(&(next() as u32).to_le_bytes());
        out.push(0);
        i += 1;
    }
    out.truncate(len);
    out
}

#[test]
fn deep_trees_as_small_as_c() {
    for len in [2 << 10, 8 << 10, 32 << 10, 200 << 10] {
        for level in [1, 3, 6] {
            let (mut ours, mut c) = (0, 0);
            for seed in 0..20 {
                let data = records(len, 77 + seed);
                let frame = c14zz_zstd::compress(&data, level);
                assert!(zstd::bulk::decompress(&frame, data.len()).unwrap() == data);
                ours += frame.len();
                c += zstd::bulk::compress(&data, level).unwrap().len();
            }
            // (within 0.2 %)
            assert!(ours * 500 <= c * 501, "{len} bytes, level {level}: {ours} bytes, C {c}");
        }
    }
}
