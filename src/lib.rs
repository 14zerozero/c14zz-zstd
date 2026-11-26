//! Zstandard (RFC 8878) compression and decompression in Rust, after the design of the
//! reference implementation ([facebook/zstd](https://github.com/facebook/zstd)). No
//! dependencies, and by default no `unsafe` code.
//!
//! Frames are standard: what this crate writes, every Zstandard decoder reads, and it reads
//! what the reference implementation writes.
//!
//! # One call
//!
//! ```
//! let data = b"some data, some data, some data";
//! let frame = c14zz_zstd::compress(data, 3);
//! assert_eq!(c14zz_zstd::decompress(&frame)?, data);
//! # Ok::<(), c14zz_zstd::Error>(())
//! ```
//!
//! [`compress`] and [`decompress`] return vectors; [`compress_into`] and
//! [`decompress_into`] write to a slice. A thread keeps the context of these functions
//! (tables of up to 4 MB) for its next call, so calls in a row cost what they cost with a
//! context kept by hand.
//!
//! # Contexts
//!
//! A [`Compressor`] or [`Decompressor`] holds the tables and buffers: once warm, a call
//! allocates nothing but what its result needs, and nothing at all when the result goes to
//! a vector or slice of the caller. This is the form for a server that handles many
//! messages.
//!
//! ```
//! let mut compressor = c14zz_zstd::Compressor::new(3);
//! let mut decompressor = c14zz_zstd::Decompressor::new();
//! // data that comes from elsewhere: say how large it may get
//! decompressor.set_limit(16 << 20);
//!
//! let (mut frame, mut data) = (Vec::new(), Vec::new());
//! for message in [&b"first message"[..], b"second message"] {
//!     frame.clear();
//!     compressor.compress_to_vec(message, &mut frame);
//!     decompressor.decompress_to_vec(&frame, &mut data)?;
//!     assert_eq!(data, message);
//! }
//! # Ok::<(), c14zz_zstd::Error>(())
//! ```
//!
//! # Streams
//!
//! [`stream::Encoder`] is a [`Write`](std::io::Write) that compresses what is written to
//! it, [`stream::Decoder`] a [`Read`](std::io::Read) that decompresses what it reads: for
//! data that is not in memory at once.
//!
//! ```
//! use std::io::{Read, Write};
//!
//! let mut encoder = c14zz_zstd::stream::Encoder::new(Vec::new(), 3);
//! encoder.write_all(b"written in ")?;
//! encoder.write_all(b"pieces")?;
//! let frame = encoder.finish()?;
//!
//! let mut text = String::new();
//! c14zz_zstd::stream::Decoder::new(&frame[..]).read_to_string(&mut text)?;
//! assert_eq!(text, "written in pieces");
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! # Levels
//!
//! Levels are the reference implementation's: 1 to 22, 0 for its default (3), negative
//! ones for faster than 1. They use its parameters for the size of the input.
//!
//! | level | strategy here | compared with the reference implementation |
//! |---|---|---|
//! | negative, 1, 2 | `fast` | the same search; sizes equal or close to its (mostly within 0.1 %) |
//! | 3, 4 | `dfast` | the same |
//! | 5 to 12 | `greedy`, `lazy`, `lazy2` | the same |
//! | 13 to 22 | `btlazy2`, `btopt`, `btultra`, `btultra2` | the same search and the same parse; small inputs have these strategies from level 9 on |
//!
//! # Untrusted data
//!
//! The decoder refuses what the format does not allow, with an [`Error`]; it does not
//! panic on any input, which a fuzz target checks. How much memory a frame may ask for is
//! the caller's to say: [`Decompressor::set_limit`] bounds the size of the data for the
//! calls that grow a vector, [`decompress_into`] and [`Decompressor::decompress_into`]
//! never write more than the slice they are given, and [`stream::Decoder::set_window_limit`]
//! bounds what a stream keeps. The one-call [`decompress`] has no limit. A dictionary may
//! come from elsewhere as well: making one of any bytes and decoding with it keeps to the
//! same rules.
//!
//! # Dictionaries
//!
//! Small messages of one kind compress much better with a dictionary of what they have in
//! common, which both sides have before the first message. A [`Dictionary`] is made once
//! of the bytes of a dictionary of the reference implementation's trainer (`zstd --train`),
//! or of any bytes as content, and given to the contexts of both sides
//! ([`Compressor::set_dictionary`], [`Decompressor::set_dictionary`]), to the streams, or
//! to [`compress_with_dictionary`] and [`decompress_with_dictionary`].
//!
//! ```
//! let dictionary = c14zz_zstd::Dictionary::new(b"{\"name\": \"\", \"count\": 0, \"active\": false}")?;
//! let mut compressor = c14zz_zstd::Compressor::new(3);
//! compressor.set_dictionary(&dictionary);
//! let mut decompressor = c14zz_zstd::Decompressor::new();
//! decompressor.set_dictionary(&dictionary);
//!
//! for message in [&b"{\"name\": \"ab\", \"count\": 1, \"active\": true}"[..], b"{\"name\": \"cd\", \"count\": 22, \"active\": false}"] {
//!     let frame = compressor.compress(message);
//!     assert!(frame.len() < message.len());
//!     assert_eq!(decompressor.decompress(&frame, 1000)?, message);
//! }
//! # Ok::<(), c14zz_zstd::Error>(())
//! ```
//!
//! The match finder's tables with a dictionary's content in them are made once per level
//! and kept with the dictionary; a compressor that has them compresses a small message at
//! a cost by the message's size, so a [`Compressor`] kept for many messages is the form to
//! use. The parameters are the reference implementation's for a dictionary of that size and
//! the size of the input. The bytes of a dictionary are checked when it is made
//! ([`Error::BadDictionary`]); a frame that names a dictionary is read with that one only
//! ([`Error::DictionaryNeeded`], [`Error::WrongDictionary`]). Dictionaries are not trained
//! here.
//!
//! # What is not there
//!
//! - Multithreaded compression and long-distance matching.
//!
//! # Features
//!
//! - `unsafe` (off by default): ten `unsafe` blocks in the place of their safe forms, for
//!   speed — unchecked copies in the decoder's inner loops, unchecked reads in the match
//!   finders, and copies of the block decoder and encoder for BMI2 that are chosen when the
//!   program runs. The frames are the same with and without. Without the feature the crate
//!   is `#![forbid(unsafe_code)]`; built with `-C target-cpu=native` (or
//!   `-C target-feature=+bmi2,+lzcnt`) the safe form gets most of the difference back. The
//!   README has the numbers.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "unsafe"), forbid(unsafe_code))]

mod bits;
mod dec;
mod dict;
mod enc;
mod error;
mod fse;
mod huf;
mod mem;
#[doc(hidden)]
pub mod prof;
pub mod stream;
pub mod xxh64;

pub use dec::FrameHeader;
pub use dict::Dictionary;
pub use enc::compress_bound;
pub use error::Error;

use dec::block::BlockDecoder;
use std::cell::Cell;
use dec::{SliceSink, VecSink};

/// A thread keeps the compressor of its one-call functions while its tables are no larger.
const KEEP_MAX: usize = 4 << 20;

thread_local! {
    // The contexts of this thread's one-call functions; taken out while one of them runs.
    // (What a context has seen makes no difference to what it writes or reads.)
    static COMPRESSOR: Cell<Option<Box<Compressor>>> = const { Cell::new(None) };
    static DECOMPRESSOR: Cell<Option<Box<Decompressor>>> = const { Cell::new(None) };
}

fn with_compressor<R>(level: i32, f: impl FnOnce(&mut Compressor) -> R) -> R {
    // (while a thread ends there may be none to take: then one for this call)
    let kept = COMPRESSOR.try_with(Cell::take).ok().flatten();
    let mut c = kept.unwrap_or_else(|| Box::new(Compressor::new(level)));
    c.opt = enc::FrameOptions { level, checksum: false, content_size: true };
    let r = f(&mut c);
    if c.enc.table_bytes() <= KEEP_MAX {
        let _ = COMPRESSOR.try_with(|kept| kept.set(Some(c)));
    }
    r
}

fn with_decompressor<R>(f: impl FnOnce(&mut Decompressor) -> R) -> R {
    let kept = DECOMPRESSOR.try_with(Cell::take).ok().flatten();
    let mut d = kept.unwrap_or_default();
    let r = f(&mut d);
    let _ = DECOMPRESSOR.try_with(|kept| kept.set(Some(d)));
    r
}

/// Compresses `src` into one frame at `level` (see the [levels](crate#levels)). The frame
/// says the size of its content and has no checksum; a [`Compressor`] can do otherwise.
///
/// ```
/// let frame = c14zz_zstd::compress(&[7u8; 1000], 1);
/// assert!(frame.len() < 30);
/// ```
pub fn compress(src: &[u8], level: i32) -> Vec<u8> {
    with_compressor(level, |c| c.compress(src))
}

/// Compresses `src` into one frame at `level` in `dst`; returns the frame's size.
/// [`compress_bound`] is the room that is always enough; with less, the call fails with
/// [`Error::OutputTooSmall`] if the frame does not fit.
///
/// ```
/// let data = [7u8; 1000];
/// let mut room = vec![0; c14zz_zstd::compress_bound(data.len())];
/// let size = c14zz_zstd::compress_into(&data, &mut room, 3)?;
/// assert_eq!(c14zz_zstd::decompress(&room[..size])?, data);
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub fn compress_into(src: &[u8], dst: &mut [u8], level: i32) -> Result<usize, Error> {
    with_compressor(level, |c| c.compress_into(src, dst))
}

/// Compresses `src` into one frame at `level` that is to be read with `dictionary`
/// ([`decompress_with_dictionary`], [`Decompressor::set_dictionary`]). The thread's context
/// stays with the dictionary it was last given: calls in a row with the same one cost what
/// they cost with a [`Compressor`] that has it.
///
/// ```
/// let dictionary = c14zz_zstd::Dictionary::raw(b"a stream of words, ");
/// let frame = c14zz_zstd::compress_with_dictionary(b"a stream of words, of words, of words", 3, &dictionary);
/// assert_eq!(c14zz_zstd::decompress_with_dictionary(&frame, &dictionary)?, b"a stream of words, of words, of words");
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub fn compress_with_dictionary(src: &[u8], level: i32, dictionary: &Dictionary) -> Vec<u8> {
    with_compressor(level, |c| {
        let mut out = Vec::with_capacity(src.len() / 2 + 32);
        let made = if dictionary.0.is_used() { c.enc.compress_with(src, &mut out, c.opt, &dictionary.0) } else { c.enc.compress(src, &mut out, c.opt) };
        made.expect("a vector takes all");
        out
    })
}

/// A compressor to keep between calls: its tables and buffers are made once.
///
/// What it has compressed before makes no difference to what it writes: a frame is the
/// same from a new compressor and from a used one.
///
/// ```
/// let mut compressor = c14zz_zstd::Compressor::new(6);
/// compressor.set_checksum(true);
/// let mut frame = Vec::new();
/// compressor.compress_to_vec(b"data, data, data, data", &mut frame);
/// assert_eq!(c14zz_zstd::decompress(&frame)?, b"data, data, data, data");
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub struct Compressor {
    enc: enc::Encoder,
    opt: enc::FrameOptions,
    dict: Option<Dictionary>,
}

impl Compressor {
    /// A compressor of `level`: 1 to 22 as the reference implementation counts them, 0 for
    /// its default (3), negative for faster than 1.
    ///
    /// Levels use the reference implementation's parameters for the size of the input, and
    /// its strategies, from `fast` to `btultra2`.
    pub fn new(level: i32) -> Self {
        Compressor { enc: enc::Encoder::new(), opt: enc::FrameOptions { level, checksum: false, content_size: true }, dict: None }
    }

    /// The frames to come are made with `dictionary`, and are to be read with it. (The
    /// compressor keeps a reference to the dictionary, and a copy of its content.)
    ///
    /// The match finder's tables with the dictionary's content in them are made once for a
    /// dictionary and a level, when a compressor first asks for them, and kept with the
    /// dictionary; a compressor copies them when it gets the dictionary. From then on a
    /// small input costs by its size: for many small inputs, keep the compressor.
    ///
    /// ```
    /// let dictionary = c14zz_zstd::Dictionary::new(b"{\"name\": \"\", \"count\": 0, \"active\": false}")?;
    /// let mut compressor = c14zz_zstd::Compressor::new(3);
    /// compressor.set_dictionary(&dictionary);
    /// let mut decompressor = c14zz_zstd::Decompressor::new();
    /// decompressor.set_dictionary(&dictionary);
    ///
    /// let message = b"{\"name\": \"ab\", \"count\": 1, \"active\": true}";
    /// let frame = compressor.compress(message);
    /// assert!(frame.len() < c14zz_zstd::compress(message, 3).len());
    /// assert_eq!(decompressor.decompress(&frame, 100)?, message);
    /// # Ok::<(), c14zz_zstd::Error>(())
    /// ```
    pub fn set_dictionary(&mut self, dictionary: &Dictionary) {
        self.dict = Some(dictionary.clone());
    }

    /// The frames to come are made without a dictionary.
    pub fn clear_dictionary(&mut self) {
        self.dict = None;
    }

    fn run<O: enc::Out>(&mut self, src: &[u8], out: &mut O) -> Result<(), Error> {
        match &self.dict {
            Some(d) if d.0.is_used() => self.enc.compress_with(src, out, self.opt, &d.0),
            _ => self.enc.compress(src, out, self.opt),
        }
    }

    /// Changes the level of the frames to come.
    pub fn set_level(&mut self, level: i32) {
        self.opt.level = level;
    }

    /// Whether frames end with a checksum of their content (not by default).
    pub fn set_checksum(&mut self, on: bool) {
        self.opt.checksum = on;
    }

    /// Whether frames say the size of their content (by default).
    pub fn set_content_size(&mut self, on: bool) {
        self.opt.content_size = on;
    }

    /// Appends `src` as one frame to `out`.
    pub fn compress_to_vec(&mut self, src: &[u8], out: &mut Vec<u8>) {
        out.reserve(src.len() / 2 + 32);
        self.run(src, out).expect("a vector takes all");
    }

    /// `src` as one frame.
    pub fn compress(&mut self, src: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.compress_to_vec(src, &mut out);
        out
    }

    /// Writes `src` as one frame into `dst`; returns the frame's size. [`compress_bound`]
    /// is the room that is always enough.
    pub fn compress_into(&mut self, src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        let mut out = enc::SliceOut { buf: dst, at: 0 };
        self.run(src, &mut out)?;
        Ok(out.at)
    }
}

/// Decompresses the frames `src` consists of: one, or several in a row, whose data is
/// joined.
///
/// There is no limit on the size of the result: for data that comes from elsewhere, use
/// [`decompress_into`] or a [`Decompressor`] with [`Decompressor::set_limit`].
///
/// ```
/// let mut frames = c14zz_zstd::compress(b"one, ", 3);
/// frames.extend(c14zz_zstd::compress(b"two", 3));
/// assert_eq!(c14zz_zstd::decompress(&frames)?, b"one, two");
/// assert_eq!(c14zz_zstd::decompress(b"no frame"), Err(c14zz_zstd::Error::BadMagic));
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, Error> {
    with_decompressor(|d| {
        let mut out = Vec::new();
        d.decompress_to_vec(src, &mut out)?;
        Ok(out)
    })
}

/// Decompresses the frames `src` consists of into `dst`; returns the size of the data.
/// Data that does not fit is refused with [`Error::OutputTooSmall`].
///
/// ```
/// let frame = c14zz_zstd::compress(b"twelve bytes", 3);
/// let mut room = [0u8; 64];
/// let size = c14zz_zstd::decompress_into(&frame, &mut room)?;
/// assert_eq!(&room[..size], b"twelve bytes");
/// assert_eq!(c14zz_zstd::decompress_into(&frame, &mut room[..5]), Err(c14zz_zstd::Error::OutputTooSmall));
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub fn decompress_into(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    with_decompressor(|d| d.decompress_into(src, dst))
}

/// Decompresses the frames `src` consists of, which were made with `dictionary` (or name
/// no dictionary). As [`decompress`], it has no limit on the size of the result; a
/// [`Decompressor`] with [`Decompressor::set_dictionary`] has the other forms.
///
/// ```
/// let dictionary = c14zz_zstd::Dictionary::raw(b"a stream of words, ");
/// // a frame of the reference implementation, made with the same dictionary
/// let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x25, 0x8d, 0x00, 0x00, 0x40, 0x6f, 0x66, 0x20, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x02, 0x00,
///     0x40, 0x6d, 0x60, 0xc9, 0x04, 0x02];
/// assert_eq!(c14zz_zstd::decompress_with_dictionary(&frame, &dictionary)?, b"a stream of words, of words, of words");
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub fn decompress_with_dictionary(src: &[u8], dictionary: &Dictionary) -> Result<Vec<u8>, Error> {
    with_decompressor(|d| {
        let mut out = Vec::new();
        match dec::decode_frames(&mut d.bd, src, &mut VecSink { v: &mut out, max: d.limit }, 0, Some(&dictionary.0)) {
            Ok(end) => {
                out.truncate(end);
                Ok(out)
            }
            Err(e) => Err(e),
        }
    })
}

/// A decompressor to keep between calls: its tables and buffers are made once.
///
/// ```
/// let frame = c14zz_zstd::compress(&[0u8; 100_000], 3);
/// let mut decompressor = c14zz_zstd::Decompressor::new();
/// let mut data = Vec::new();
/// decompressor.decompress_to_vec(&frame, &mut data)?;
/// assert_eq!(data.len(), 100_000);
///
/// // a frame of a few bytes may stand for a lot of data: a limit refuses it
/// decompressor.set_limit(1000);
/// assert_eq!(decompressor.decompress_to_vec(&frame, &mut data), Err(c14zz_zstd::Error::OutputTooSmall));
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub struct Decompressor {
    bd: BlockDecoder,
    limit: usize,
    dict: Option<Dictionary>,
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompressor {
    /// A decompressor without limit on the size of the data.
    pub fn new() -> Self {
        Decompressor { bd: BlockDecoder::new(), limit: usize::MAX - 64, dict: None }
    }

    /// The frames to come are read with `dictionary`: those that were made with it, or that
    /// name no dictionary. A frame that names another one is refused with
    /// [`Error::WrongDictionary`]. (The decompressor keeps a reference to the dictionary,
    /// not a copy.)
    ///
    /// ```
    /// let dictionary = c14zz_zstd::Dictionary::raw(b"a stream of words, ");
    /// // a frame of the reference implementation, made with the same dictionary
    /// let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x25, 0x8d, 0x00, 0x00, 0x40, 0x6f, 0x66, 0x20, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x02, 0x00,
    ///     0x40, 0x6d, 0x60, 0xc9, 0x04, 0x02];
    /// let mut decompressor = c14zz_zstd::Decompressor::new();
    /// // (a dictionary that is content only has no id that a frame could ask for)
    /// assert!(decompressor.decompress(&frame, 100).is_err());
    /// decompressor.set_dictionary(&dictionary);
    /// assert_eq!(decompressor.decompress(&frame, 100)?, b"a stream of words, of words, of words");
    /// # Ok::<(), c14zz_zstd::Error>(())
    /// ```
    pub fn set_dictionary(&mut self, dictionary: &Dictionary) {
        self.dict = Some(dictionary.clone());
    }

    /// The frames to come are read without a dictionary: those that name one are refused
    /// with [`Error::DictionaryNeeded`].
    pub fn clear_dictionary(&mut self) {
        self.dict = None;
    }


    /// Data larger than `limit` bytes is refused with [`Error::OutputTooSmall`] by the calls
    /// that return or fill a vector.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(usize::MAX - 64);
    }

    /// Decompresses the frames `src` consists of into `dst`; returns the size of the data.
    pub fn decompress_into(&mut self, src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        let dict = self.dict.as_ref().map(|d| &*d.0);
        dec::decode_frames(&mut self.bd, src, &mut SliceSink(dst), 0, dict)
    }

    /// Decompresses the frames `src` consists of; `out` is replaced by the data. (An `out`
    /// used before is not cleared first: its bytes are overwritten.)
    pub fn decompress_to_vec(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let dict = self.dict.as_ref().map(|d| &*d.0);
        match dec::decode_frames(&mut self.bd, src, &mut VecSink { v: out, max: self.limit }, 0, dict) {
            Ok(end) => {
                out.truncate(end);
                Ok(())
            }
            Err(e) => {
                out.clear();
                Err(e)
            }
        }
    }

    /// Decompresses the frames `src` consists of, of at most `capacity` bytes of data.
    pub fn decompress(&mut self, src: &[u8], capacity: usize) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let limit = self.limit.min(capacity);
        let dict = self.dict.as_ref().map(|d| &*d.0);
        match dec::decode_frames(&mut self.bd, src, &mut VecSink { v: &mut out, max: limit }, 0, dict) {
            Ok(end) => {
                out.truncate(end);
                Ok(out)
            }
            Err(e) => Err(e),
        }
    }
}

/// The size of the content of the frame at the start of `src`, if its header has it. (The
/// header is not proof: a frame that is not what it says is refused when it is decoded.)
///
/// ```
/// let frame = c14zz_zstd::compress(&[1u8; 500], 3);
/// assert_eq!(c14zz_zstd::content_size(&frame)?, Some(500));
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
pub fn content_size(src: &[u8]) -> Result<Option<u64>, Error> {
    Ok(FrameHeader::read(src)?.content_size)
}
