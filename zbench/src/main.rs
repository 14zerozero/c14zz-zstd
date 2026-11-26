//! c14zz-zstd and the C library (`zstd` crate) side by side: compression and decompression, speed
//! and ratio. Every frame is checked to decode with both.
//!
//! `zbench [--time MS] [--levels 1,3,6,9] [--input FILTER] [--chunk BYTES] [--no-bson]
//! [--only c|z] [--no-dec] [--no-comp] [--fresh] [--frames] [--once] [FILES...]`
//!
//! One line per input and level: sizes relative to the input (C, this crate), the median time of a
//! call in µs (C, this crate) and c14zz-zstd's time relative to C's, for compression with a kept context
//! and for decompression of C's frame of that level. With `--fresh`, the calls that make
//! their context themselves, for both. With `--frames`, no times: the sizes of both frames in
//! bytes and a hash of c14zz-zstd's, to compare the output of two builds. With `--once`, the
//! compression times are those of one call each, the first of a new context (for levels
//! at which a call takes seconds), and nothing else is measured.
//!
//! `zbench --dict BYTES [--time MS] [--levels ..]`: small BSON messages with a dictionary of
//! at most `BYTES` that the C library's trainer makes of other such messages. One line per
//! kind of message and level: the sizes of all frames relative to the messages (C, this
//! crate, and this crate without the dictionary), the time per message in ns to compress
//! with a kept context (C, this crate, relative) and to decompress C's frames.

mod gen;

use std::time::{Duration, Instant};

/// Median time of one call in ns, running for at least `time`.
fn measure(time: Duration, mut f: impl FnMut()) -> f64 {
    f();
    let mut samples = Vec::new();
    let start = Instant::now();
    while samples.len() < 3 || (start.elapsed() < time && samples.len() < 200_000) {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_nanos() as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

/// With the feature `prof`: the shares of three stages (from `first`) in `total`, in percent;
/// with the compressor, the last one has the one before it in it.
fn shares(to: &mut String, total: Duration, first: usize) {
    let ns = c14zz_zstd::prof::take();
    if ns.iter().all(|&n| n == 0) {
        return;
    }
    let pct = |n: u64| 100.0 * n as f64 / total.as_nanos() as f64;
    let last = if first == 3 { ns[5] - ns[4] } else { ns[2] };
    to.push_str(&format!(" | {} {:.0} {} {:.0} {} {:.0}", c14zz_zstd::prof::STAGES[first], pct(ns[first]), c14zz_zstd::prof::STAGES[first + 1], pct(ns[first + 1]), c14zz_zstd::prof::STAGES[first + 2], pct(last)));
}

fn main() {
    let mut time = Duration::from_millis(300);
    let mut levels = vec![1, 3, 6, 9];
    let mut input_filter: Option<String> = None;
    let mut chunks: Vec<usize> = Vec::new();
    let mut bson = true;
    let mut only: Option<String> = None;
    let (mut dec, mut comp, mut fresh, mut streams, mut frames, mut once) = (true, true, false, false, false, false);
    let mut files = Vec::new();
    let mut dict_size = 0usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--time" => time = Duration::from_millis(args.next().unwrap().parse().unwrap()),
            "--levels" => levels = args.next().unwrap().split(',').map(|l| l.parse().unwrap()).collect(),
            "--input" => input_filter = args.next(),
            "--chunk" => chunks.push(args.next().unwrap().parse().unwrap()),
            "--no-bson" => bson = false,
            "--only" => only = args.next(),
            "--no-dec" => dec = false,
            "--no-comp" => comp = false,
            "--fresh" => fresh = true,
            "--streams" => streams = true,
            "--frames" => frames = true,
            "--once" => once = true,
            "--dict" => dict_size = args.next().unwrap().parse().unwrap(),
            _ => files.push(a),
        }
    }
    if dict_size > 0 {
        return with_dictionary(dict_size, &levels, time);
    }
    let run_c = only.as_deref() != Some("z");
    let run_z = only.as_deref() != Some("c");

    let mut inputs: Vec<(String, Vec<u8>)> = Vec::new();
    if bson {
        inputs.push(("bson-cmd".into(), gen::small_command(1)));
        for docs in [1u32, 4, 16, 100, 400, 1000, 4000, 20000] {
            inputs.push((format!("bson-{docs}"), gen::find_reply(docs, docs as u64)));
        }
    }
    for f in &files {
        let data = std::fs::read(f).unwrap();
        let name = std::path::Path::new(f).file_name().unwrap().to_string_lossy().into_owned();
        for &c in &chunks {
            if data.len() > c {
                // from the middle: file starts are often headers
                let at = (data.len() - c) / 2;
                inputs.push((format!("{name}@{}k", c / 1024), data[at..at + c].to_vec()));
            }
        }
        inputs.push((name, data));
    }
    // a filter is a list of substrings, or of whole names after `=`
    let pass = |name: &str| input_filter.as_ref().is_none_or(|f| f.split(',').any(|f| f.strip_prefix('=').map_or(name.contains(f), |f| name == f)));

    println!("{:<14} {:>9} {:>3} | {:>6} {:>6} | {:>10} {:>10} {:>5} | {:>10} {:>10} {:>5}", "input", "bytes", "lvl", "c", "rust", "c µs", "rust µs", "r/c", "dec c µs", "rust µs", "z/c");
    let mut zd = c14zz_zstd::Decompressor::new();
    let mut cd = zstd::bulk::Decompressor::new().unwrap();
    for (name, data) in inputs.iter().filter(|i| pass(&i.0)) {
        for &level in &levels {
            let mut cc = zstd::bulk::Compressor::new(level).unwrap();
            let mut zc = c14zz_zstd::Compressor::new(level);
            let mut c_frame = Vec::with_capacity(zstd::zstd_safe::compress_bound(data.len()));
            let t = Instant::now();
            cc.compress_to_buffer(data, &mut c_frame).unwrap();
            let once_c = t.elapsed().as_nanos() as f64;
            let t = Instant::now();
            let z_frame = zc.compress(data);
            let once_z = t.elapsed().as_nanos() as f64;
            // each frame must be read back by both
            let mut back = Vec::new();
            zd.decompress_to_vec(&c_frame, &mut back).unwrap_or_else(|e| panic!("{name} level {level}: c14zz-zstd cannot decode C's frame: {e}"));
            assert!(back == *data, "{name} level {level}: c14zz-zstd decodes C's frame to other data");
            zd.decompress_to_vec(&z_frame, &mut back).unwrap_or_else(|e| panic!("{name} level {level}: c14zz-zstd cannot decode its frame: {e}"));
            assert!(back == *data, "{name} level {level}: c14zz-zstd decodes its frame to other data");
            let by_c = zstd::bulk::decompress(&z_frame, data.len()).unwrap_or_else(|e| panic!("{name} level {level}: C cannot decode c14zz-zstd's frame: {e}"));
            assert!(by_c == *data, "{name} level {level}: C decodes c14zz-zstd's frame to other data");
            if streams {
                // the same through the streams, in pieces, with a checksum; C's stream has no content size
                use std::io::{Read, Write};
                let mut e = c14zz_zstd::stream::Encoder::new(Vec::new(), level);
                e.set_checksum(true);
                for piece in data.chunks(70_001) {
                    e.write_all(piece).unwrap();
                }
                let frame = e.finish().unwrap();
                assert!(zstd::stream::decode_all(&frame[..]).unwrap_or_else(|e| panic!("{name} level {level}: C cannot decode c14zz-zstd's stream: {e}")) == *data);
                let c_stream = zstd::stream::encode_all(&data[..], level).unwrap();
                let mut read = Vec::new();
                c14zz_zstd::stream::Decoder::new(&c_stream[..]).read_to_end(&mut read).unwrap_or_else(|e| panic!("{name} level {level}: c14zz-zstd cannot decode C's stream: {e}"));
                assert!(read == *data, "{name} level {level}: c14zz-zstd decodes C's stream to other data");
            }

            if frames {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                z_frame.hash(&mut h);
                println!("{:<14} {:>9} {:>3} | {:>9} {:>9} {:>+7} | {:016x}", name, data.len(), level, c_frame.len(), z_frame.len(), z_frame.len() as i64 - c_frame.len() as i64, h.finish());
                continue;
            }

            let mut prof = String::new();
            let (mut tc, mut tz, mut dc, mut dz) = (f64::NAN, f64::NAN, f64::NAN, f64::NAN);
            if once {
                (tc, tz) = (once_c, once_z);
                (comp, dec) = (false, false);
            }
            let mut out = Vec::with_capacity(zstd::zstd_safe::compress_bound(data.len()));
            if comp && run_c {
                tc = if fresh {
                    measure(time, || {
                        std::hint::black_box(zstd::bulk::compress(data, level).unwrap());
                    })
                } else {
                    measure(time, || {
                        out.clear();
                        cc.compress_to_buffer(data, &mut out).unwrap();
                    })
                };
            }
            if comp && run_z {
                tz = if fresh {
                    measure(time, || {
                        std::hint::black_box(c14zz_zstd::compress(data, level));
                    })
                } else {
                    c14zz_zstd::prof::take();
                    let t0 = std::time::Instant::now();
                    let t = measure(time, || {
                        out.clear();
                        zc.compress_to_vec(data, &mut out);
                    });
                    shares(&mut prof, t0.elapsed(), 3);
                    t
                };
            }
            let mut out = Vec::with_capacity(data.len());
            if dec && run_c {
                dc = if fresh {
                    measure(time, || {
                        std::hint::black_box(zstd::bulk::decompress(&c_frame, data.len()).unwrap());
                    })
                } else {
                    measure(time, || {
                        out.clear();
                        cd.decompress_to_buffer(&c_frame, &mut out).unwrap();
                    })
                };
            }
            if dec && run_z {
                dz = if fresh {
                    measure(time, || {
                        std::hint::black_box(c14zz_zstd::decompress(&c_frame).unwrap());
                    })
                } else {
                    c14zz_zstd::prof::take();
                    let t0 = std::time::Instant::now();
                    let t = measure(time, || {
                        zd.decompress_to_vec(&c_frame, &mut out).unwrap();
                    });
                    shares(&mut prof, t0.elapsed(), 0);
                    t
                };
            }
            let n = data.len() as f64;
            println!(
                "{:<14} {:>9} {:>3} | {:>6.4} {:>6.4} | {:>10.1} {:>10.1} {:>5.2} | {:>10.1} {:>10.1} {:>5.2}{}",
                name,
                data.len(),
                level,
                c_frame.len() as f64 / n,
                z_frame.len() as f64 / n,
                tc / 1e3,
                tz / 1e3,
                tz / tc,
                dc / 1e3,
                dz / 1e3,
                dz / dc,
                prof
            );
        }
    }
}

/// Small messages with a trained dictionary (see the top of the file).
fn with_dictionary(dict_size: usize, levels: &[i32], time: Duration) {
    // kinds of messages: commands of about 100 bytes, replies of one and of four documents
    type Kind = (&'static str, fn(u64) -> Vec<u8>);
    let kinds: [Kind; 3] = [("bson-cmd", gen::small_command), ("bson-1", |seed| gen::find_reply(1, seed)), ("bson-4", |seed| gen::find_reply(4, seed))];
    println!("{:<10} {:>6} {:>3} | {:>6} {:>6} {:>6} | {:>8} {:>8} {:>5} | {:>8} {:>8} {:>5}", "input", "bytes", "lvl", "c", "rust", "plain", "c ns", "rust ns", "r/c", "dec c ns", "rust ns", "r/c");
    for (name, make) in kinds {
        let samples: Vec<Vec<u8>> = (0..4000u64).map(|i| make(1_000_000 + i)).collect();
        let dict = zstd::dict::from_samples(&samples, dict_size).unwrap();
        let dictionary = c14zz_zstd::Dictionary::new(&dict).unwrap();
        let messages: Vec<Vec<u8>> = (0..1000u64).map(make).collect();
        let total: usize = messages.iter().map(|m| m.len()).sum();
        let mut zd = c14zz_zstd::Decompressor::new();
        zd.set_dictionary(&dictionary);
        let mut cd = zstd::bulk::Decompressor::with_dictionary(&dict).unwrap();
        for &level in levels {
            let mut cc = zstd::bulk::Compressor::with_dictionary(level, &dict).unwrap();
            let mut zc = c14zz_zstd::Compressor::new(level);
            zc.set_dictionary(&dictionary);
            let c_frames: Vec<Vec<u8>> = messages.iter().map(|m| cc.compress(m).unwrap()).collect();
            let z_frames: Vec<Vec<u8>> = messages.iter().map(|m| zc.compress(m)).collect();
            let plain: usize = messages.iter().map(|m| c14zz_zstd::compress(m, level).len()).sum();
            // each frame must be read back by both
            let mut back = Vec::new();
            for ((m, c_frame), z_frame) in messages.iter().zip(&c_frames).zip(&z_frames) {
                zd.decompress_to_vec(c_frame, &mut back).unwrap_or_else(|e| panic!("{name} level {level}: c14zz-zstd cannot decode C's frame: {e}"));
                assert!(back == *m, "{name} level {level}: c14zz-zstd decodes C's frame to other data");
                zd.decompress_to_vec(z_frame, &mut back).unwrap_or_else(|e| panic!("{name} level {level}: c14zz-zstd cannot decode its frame: {e}"));
                assert!(back == *m, "{name} level {level}: c14zz-zstd decodes its frame to other data");
                let by_c = cd.decompress(z_frame, m.len()).unwrap_or_else(|e| panic!("{name} level {level}: C cannot decode c14zz-zstd's frame: {e}"));
                assert!(by_c == *m, "{name} level {level}: C decodes c14zz-zstd's frame to other data");
            }
            let size = |frames: &[Vec<u8>]| frames.iter().map(|f| f.len()).sum::<usize>() as f64 / total as f64;
            let n = messages.len() as f64;
            let mut out = Vec::with_capacity(1 << 16);
            let tc = measure(time, || {
                for m in &messages {
                    out.clear();
                    cc.compress_to_buffer(m, &mut out).unwrap();
                }
            }) / n;
            let tz = measure(time, || {
                for m in &messages {
                    out.clear();
                    zc.compress_to_vec(m, &mut out);
                }
            }) / n;
            let dc = measure(time, || {
                for f in &c_frames {
                    out.clear();
                    cd.decompress_to_buffer(f, &mut out).unwrap();
                }
            }) / n;
            let dz = measure(time, || {
                for f in &c_frames {
                    zd.decompress_to_vec(f, &mut out).unwrap();
                }
            }) / n;
            println!(
                "{:<10} {:>6} {:>3} | {:>6.4} {:>6.4} {:>6.4} | {:>8.0} {:>8.0} {:>5.2} | {:>8.0} {:>8.0} {:>5.2}",
                name,
                total / messages.len(),
                level,
                size(&c_frames),
                size(&z_frames),
                plain as f64 / total as f64,
                tc,
                tz,
                tz / tc,
                dc,
                dz,
                dz / dc
            );
        }
    }
}
