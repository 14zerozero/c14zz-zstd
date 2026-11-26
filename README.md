# c14zz-zstd

[![ci](https://github.com/14zerozero/c14zz-zstd/actions/workflows/ci.yml/badge.svg)](https://github.com/14zerozero/c14zz-zstd/actions/workflows/ci.yml)

Zstandard (RFC 8878) compression and decompression in Rust, after the design of the
reference implementation ([facebook/zstd](https://github.com/facebook/zstd)): its match
finders (`fast`, `double fast`, `greedy`/`lazy`/`lazy2` over rows of tagged positions or,
for windows of up to 16 KB, hash chains), its parameters by level and input size, its
choice of where a block ends, its block encoder's choices, its decoder's table layouts.

- No dependencies.
- No `unsafe` code by default; a feature trades that for speed.
- With the feature, within a few percent of the C library 1.6.0 at decompression and at
  level 3 (see [Performance](#performance)).
- Frames are standard: the C library decodes them, and its frames are decoded here.

## Use

```toml
[dependencies]
c14zz-zstd = "0.1"
# or, with the unsafe blocks:
# c14zz-zstd = { version = "0.1", features = ["unsafe"] }
```

One call:

```rust
let frame = c14zz_zstd::compress(b"some data, some data, some data", 3);
assert_eq!(c14zz_zstd::decompress(&frame).unwrap(), b"some data, some data, some data");
```

Contexts to keep, for many messages (no allocation per call once warm):

```rust
let mut compressor = c14zz_zstd::Compressor::new(3);
let mut decompressor = c14zz_zstd::Decompressor::new();
decompressor.set_limit(16 << 20); // data from elsewhere: how large it may get

let mut frame = Vec::new();
compressor.compress_to_vec(b"some data", &mut frame);
let mut data = Vec::new();
decompressor.decompress_to_vec(&frame, &mut data).unwrap();
```

Small messages of one kind, with a dictionary that both sides have (made by the reference
implementation's trainer, `zstd --train`, or any bytes that are like the messages):

```rust
let dictionary = c14zz_zstd::Dictionary::new(b"{\"name\": \"\", \"count\": 0, \"active\": false}").unwrap();
let mut compressor = c14zz_zstd::Compressor::new(3);
compressor.set_dictionary(&dictionary);
let mut decompressor = c14zz_zstd::Decompressor::new();
decompressor.set_dictionary(&dictionary);

let frame = compressor.compress(b"{\"name\": \"ab\", \"count\": 1, \"active\": true}");
let message = decompressor.decompress(&frame, 1 << 16).unwrap();
```

Streams, for data that is not in memory at once:

```rust
use std::io::{Read, Write};

let mut encoder = c14zz_zstd::stream::Encoder::new(Vec::new(), 3);
encoder.write_all(b"written in pieces").unwrap();
let frame = encoder.finish().unwrap();

let mut text = String::new();
c14zz_zstd::stream::Decoder::new(&frame[..]).read_to_string(&mut text).unwrap();
```

| | |
|---|---|
| One call | `compress`, `compress_into`, `decompress`, `decompress_into`, `compress_with_dictionary`, `decompress_with_dictionary`, `compress_bound`, `content_size`. A thread keeps the context of these functions (tables of up to 4 MB) for its next call. |
| Contexts | `Compressor` (level, checksum, content size, dictionary), `Decompressor` (size limit, dictionary) |
| Streams | `stream::Encoder` (a `Write`, dictionary), `stream::Decoder` (a `Read`, window limit, dictionary) |
| Dictionaries | `Dictionary` (of the reference implementation's trainer, or any bytes as content) |
| Other | `FrameHeader::read`, `xxh64` (the checksum's hash) |

The documentation of the crate (`cargo doc --open`, or docs.rs) has an example for each.

## Levels

The reference implementation's: 1 to 22, 0 for its default (3), negative ones for faster
than 1, with its parameters for the size of the input.

| level | strategy | compared with the C library |
|---|---|---|
| negative, 1, 2 | `fast` | the same search; frames of the same size or close to it (mostly within 0.1 %) |
| 3, 4 | `dfast` | the same |
| 5 to 12 | `greedy`, `lazy`, `lazy2` | the same |
| 13 to 22 | `btlazy2`, `btopt`, `btultra`, `btultra2` | the same search and the same parse; small inputs have these strategies from level 9 on |

## What is and is not there

- Frames are standard, with or without content size and checksum; several frames in a row
  and skippable frames are read. Both directions are tested against the C library for all
  levels on generated data, and fuzzed (`fuzz/`).
- The decoder refuses what the format does not allow; it does not panic on any input and
  keeps to the limits it is given (`Decompressor::set_limit`, the slice of
  `decompress_into`, `stream::Decoder::set_window_limit`). The one-call `decompress` has
  no limit.
- Dictionaries (`Dictionary`): one in the format of the reference implementation's
  trainer, or any bytes as content. Frames are made and read with one, at all levels, with
  the reference implementation's parameters for the size of the dictionary and of the
  input; both directions are tested against the C library. The tables for a dictionary's
  content are made once per level and kept with it; a compressor that has them
  compresses a small message at a cost by the message's size. A dictionary is checked when
  it is made, and a frame that names another one is refused. Dictionaries are not trained
  here: the reference implementation does that.
- No multithreaded compression and no long-distance matching.
- Rust 1.88 or newer.

## The feature `unsafe`

None by default: without the feature `unsafe` the crate is `#![forbid(unsafe_code)]`. Every
read and write is then a checked one, no instruction is asked for by name (the tags of a row
are compared in a loop, there is no prefetch), and the block decoder and encoder are
compiled once, for the processor the crate is built for.

```toml
c14zz-zstd = { version = "0.1", features = ["unsafe"] }
```

The feature `unsafe` puts ten `unsafe` blocks in the place of their safe forms, for speed;
everything else is the same code, and the frames are the same. (A feature of a crate is on
for a whole build as soon as one crate of it asks for it.)

The blocks:

- `src/dec/block.rs`, one block: the copies of a sequence's literals and match onto the
  output, 16 bytes at a time and past the end of what is needed, after one check of the
  room. `tests/kernel.rs` covers its edges (also under Miri), the `decode` fuzz target
  the rest.
- `src/huf.rs`, one block: the stores of the Huffman decoder that decodes two symbols at a
  time, 2 bytes at a place that moves on by 1 or 2, five times for each of the four streams
  after one check that each stream's part of the output has 11 bytes left. (With a checked
  store per lookup the decoder was 4 to 5 % of the whole decompression slower on text, and
  slower than the decoder of single symbols on other data.) A unit test in the same file
  compares it with the decoder of single symbols, also on streams that are cut short.
- `src/mem.rs`, two blocks: the 4- and 8-byte reads of the match finders, each behind a
  check against a limit the caller holds anyway (one comparison in the loop instead of the
  two of a slice); unit tests in the same file. (The safe form has that check and one more
  the compiler does not always fold into it: 1 to 3 % of the compression.)
- `src/mem.rs`, one block: the prefetch instruction, which reads nothing and takes any
  address.
- `src/enc/lazy.rs`, one block: the comparison of 16 tags of a row with SSE2, which every
  x86-64 processor has, reading the 16 bytes of the array it is given; a unit test in the
  same file compares the masks with those counted byte by byte.
- `src/enc/hash.rs`, two blocks: the read and the write of an entry of the hash tables of
  `fast` and `double fast` without a bounds check. The place of an entry is a hash of as
  many bits as the table has entries for, and can only be made by the table's own hasher;
  a unit test in the same file goes through the sizes and the kinds of hash. (For the
  table sizes of levels 1 and 3 on large inputs the safe form has no such check either:
  the size is a constant there.)
- `src/dec/block.rs` and `src/enc/entropy.rs`, one block each: the call of the copy of the
  block decoder and encoder that is compiled for BMI2, after the CPU was asked for it.

## Performance

Time relative to the C library 1.6.0 (`zstd` crate), median of 21 inputs: the 12 files of
the Silesia corpus and 9 BSON messages of 100 bytes to 8 MB, on a Zen 5 processor
(Ryzen AI Max+ 395), one core. `native`: the safe form built with
`RUSTFLAGS="-C target-cpu=native"`. Below 1 is faster than C.

| level | compression: `unsafe` | safe | safe, `native` | decompression: `unsafe` | safe | safe, `native` |
|------:|------:|------:|------:|------:|------:|------:|
|  1 | 1.08 | 1.13 | 1.08 | 1.01 | 1.13 | 1.09 |
|  3 | 1.02 | 1.04 | 1.05 | 1.00 | 1.14 | 1.09 |
|  6 | 1.13 | 1.43 | 1.33 | 1.00 | 1.15 | 1.09 |
|  9 | 1.17 | 1.42 | 1.26 | 0.99 | 1.14 | 1.10 |
| 12 | 1.40 | 1.51 | 1.18 | 1.00 | 1.14 | 1.10 |

At the levels 13 to 22, compression with the feature `unsafe` took 1.06 to 1.08 times C's
time on the same inputs (median; the safe form is not measured there), for frames within
0.03 % of C's size on each file of the Silesia corpus.

Most of the difference in decompression is BMI2: with the feature, a copy of the block
decoder and encoder for it is chosen when the program runs; without, it is there only if the
crate is compiled for a processor that has it (`-C target-cpu=native`, or
`-C target-feature=+bmi2,+lzcnt` for a program that is to run on others as well).

With a dictionary (16 KB, trained by the C library on BSON documents) and messages of 100
bytes to 1.7 KB, feature `unsafe`, a compressor and a decompressor that are kept: frames
are of the C library's size within 0.2 % or smaller; compression takes 1.05 to 1.5 times
its time at levels 1 and 3 and 0.6 to 1.3 times at levels 6 to 12, decompression 1.0 to 1.15
times (up to 1.4 for the messages of 100 bytes). At the levels 16 to 22 (`btopt` and
`btultra` for these sizes) the frames are of C's size or up to 4 % smaller and compression
takes 0.9 to 1.2 times its time; at 13 to 15 (`btlazy2`) 1.2 to 2.1 times.
`zbench --dict 16384` measures that.

`zbench` makes these measurements: `cargo run --release -p zbench -- FILES`
(`--features unsafe` for the crate with its feature).
Every frame it makes is checked to be read back by both libraries.

## Development

```sh
cargo test --workspace --release                          # the safe form
cargo test --workspace --release --features c14zz-zstd/unsafe
cargo clippy --workspace --all-targets
cargo +nightly fuzz run decode       # and `roundtrip`, `dictionary`, `with_dictionary`; `--features unsafe` for that form
cargo +nightly miri test --test kernel --features unsafe  # the decoder's copies
```

Pull requests run the tests and lints of both forms. A release is a pull request that
raises the version in `Cargo.toml`: once it is merged, the version is published to
crates.io and tagged.

## License

BSD-3-Clause, as the reference implementation this is derived from; see `LICENSE`.
