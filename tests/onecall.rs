//! What a context has compressed or decompressed before makes no difference: the one-call
//! functions, which keep a context per thread, and a `Compressor` used again write the frames
//! a new one writes.

mod common;

#[test]
fn contexts_used_before_write_the_same_frames() {
    let inputs: Vec<Vec<u8>> = [0usize, 1, 100, 3000, 20_000, 70_000, 300_000, 700_000]
        .iter()
        .enumerate()
        .flat_map(|(i, &n)| [common::text(n, i as u64 + 1), common::mixed(n, i as u64 + 50)])
        .collect();
    let mut kept = c14zz_zstd::Compressor::new(1);
    // (two rounds: in the second, every table has entries of the first)
    for round in 0..2 {
        for level in [1, 3, 5, 6, 9, 12, 19, -3] {
            kept.set_level(level);
            for data in &inputs {
                let fresh = c14zz_zstd::Compressor::new(level).compress(data);
                assert!(kept.compress(data) == fresh, "kept compressor, level {level}, {} bytes, round {round}", data.len());
                assert!(c14zz_zstd::compress(data, level) == fresh, "one call, level {level}, {} bytes, round {round}", data.len());
                let mut into = vec![0u8; c14zz_zstd::compress_bound(data.len())];
                let n = c14zz_zstd::compress_into(data, &mut into, level).unwrap();
                assert!(into[..n] == fresh[..]);
                assert!(c14zz_zstd::decompress(&fresh).unwrap() == *data);
                let mut back = vec![0u8; data.len()];
                assert_eq!(c14zz_zstd::decompress_into(&fresh, &mut back).unwrap(), data.len());
                assert!(back == *data);
            }
        }
    }
}

/// The one-call functions work in a thread's last moments too, when its kept context is gone.
#[test]
fn one_call_while_a_thread_ends() {
    struct AtEnd;
    impl Drop for AtEnd {
        fn drop(&mut self) {
            let data = common::text(5000, 9);
            let frame = c14zz_zstd::compress(&data, 3);
            assert!(c14zz_zstd::decompress(&frame).unwrap() == data);
        }
    }
    thread_local!(static AT_END: AtEnd = const { AtEnd });
    std::thread::spawn(|| {
        let data = common::text(5000, 9);
        assert!(c14zz_zstd::decompress(&c14zz_zstd::compress(&data, 3)).unwrap() == data);
        AT_END.with(|_| ());
    })
    .join()
    .unwrap();
}
