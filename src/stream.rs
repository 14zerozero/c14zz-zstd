//! Streams: an [`Encoder`] that compresses what is written to it, a [`Decoder`] that
//! decompresses what it reads.

use crate::dec::block::{BlockDecoder, BLOCK_MAX, SLACK};
use crate::dec::{block_header, FrameHeader};
use crate::dict::Dictionary;
use crate::enc::params::Params;
use crate::enc::{self, FrameOptions};
use crate::error::Error;
use crate::xxh64::Xxh64;
use std::io::{self, Read, Write};

/// Compresses what is written to it into one frame, written to `W`.
///
/// The data is collected into blocks of 128 KB; [`Write::flush`] ends the current block
/// early and flushes `W`. [`Encoder::finish`] ends the frame: without it the frame is not
/// complete.
///
/// ```
/// use std::io::Write;
///
/// let mut encoder = c14zz_zstd::stream::Encoder::new(Vec::new(), 3);
/// encoder.set_checksum(true);
/// for line in ["one\n", "two\n", "three\n"] {
///     encoder.write_all(line.as_bytes())?;
/// }
/// let frame = encoder.finish()?;
/// assert_eq!(c14zz_zstd::decompress(&frame)?, b"one\ntwo\nthree\n");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct Encoder<W: Write> {
    w: W,
    enc: enc::Encoder,
    opt: FrameOptions,
    pledged: Option<u64>,
    /// The frame's parameters, once it is started.
    params: Option<Params>,
    /// The data kept for matches (`..pending`) and the data not yet written (`pending..`).
    buf: Vec<u8>,
    pending: usize,
    first: bool,
    total: u64,
    hasher: Option<Xxh64>,
    out: Vec<u8>,
    dict: Option<Dictionary>,
    /// The size of the dictionary's content at the start of `buf`, while it is there.
    prefix: usize,
}

impl<W: Write> Encoder<W> {
    /// An encoder of `level` (see [`crate::Compressor::new`]) writing to `w`.
    pub fn new(w: W, level: i32) -> Self {
        Encoder {
            w,
            enc: enc::Encoder::new(),
            opt: FrameOptions { level, checksum: false, content_size: true },
            pledged: None,
            params: None,
            buf: Vec::new(),
            pending: 0,
            first: true,
            total: 0,
            hasher: None,
            out: Vec::new(),
            dict: None,
            prefix: 0,
        }
    }

    /// The frame is made with `dictionary`, and is to be read with it. To be set before
    /// the first block is written: later, it is not looked at.
    ///
    /// Each encoder copies the tables that are kept with the dictionary when its frame
    /// starts: for many small messages, a [`crate::Compressor`] with the dictionary is the
    /// faster way.
    ///
    /// ```
    /// use std::io::{Read, Write};
    ///
    /// let dictionary = c14zz_zstd::Dictionary::raw(b"a stream of words, ");
    /// let mut encoder = c14zz_zstd::stream::Encoder::new(Vec::new(), 3);
    /// encoder.set_dictionary(&dictionary);
    /// encoder.write_all(b"a stream of words, of words, of words")?;
    /// let frame = encoder.finish()?;
    ///
    /// let mut decoder = c14zz_zstd::stream::Decoder::new(&frame[..]);
    /// decoder.set_dictionary(&dictionary);
    /// let mut text = String::new();
    /// decoder.read_to_string(&mut text)?;
    /// assert_eq!(text, "a stream of words, of words, of words");
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_dictionary(&mut self, dictionary: &Dictionary) {
        if self.params.is_some() {
            return;
        }
        // the content before the data, where the match finders look for it
        self.buf.splice(..self.prefix, dictionary.0.content.iter().copied());
        self.pending += dictionary.0.content.len() - self.prefix;
        self.prefix = dictionary.0.content.len();
        self.dict = Some(dictionary.clone());
    }

    /// Whether the frame ends with a checksum of its content (not by default). To be set
    /// before the first write.
    pub fn set_checksum(&mut self, on: bool) {
        self.opt.checksum = on;
    }

    /// The size of all that will be written: the frame's header says it, the parameters fit
    /// it, and [`Encoder::finish`] fails if it was not kept. To be set before the first write.
    pub fn set_pledged_size(&mut self, size: u64) {
        self.pledged = Some(size);
    }

    /// The writer.
    pub fn get_ref(&self) -> &W {
        &self.w
    }

    fn start(&mut self) -> io::Result<Params> {
        if let Some(p) = self.params {
            return Ok(p);
        }
        self.out.clear();
        let p = match &self.dict {
            Some(d) if d.0.is_used() => self.enc.start_frame_with(self.opt, self.pledged, &d.0, &self.buf[..self.prefix], &mut self.out)?.0,
            _ => self.enc.start_frame(self.opt, self.pledged, &mut self.out)?,
        };
        self.hasher = self.opt.checksum.then(Xxh64::new);
        self.params = Some(p);
        Ok(p)
    }

    /// Writes the pending data as a block.
    fn block(&mut self, last: bool) -> io::Result<()> {
        let p = self.start()?;
        let end = self.buf.len();
        if let Some(h) = &mut self.hasher {
            h.update(&self.buf[self.pending..end]);
        }
        self.enc.chunk(&p, &self.buf, self.pending, end, last, self.first, self.prefix, &mut self.out)?;
        self.first = false;
        self.pending = end;
        self.w.write_all(&self.out)?;
        self.out.clear();
        // room for the next block: the window stays, at the front
        let window = 1usize << p.window_log;
        // (the dictionary's content stays as long as the frame's data is within a window)
        if end >= 2 * window + BLOCK_MAX && (self.prefix == 0 || end - self.prefix > window) {
            self.buf.copy_within(end - window..end, 0);
            self.buf.truncate(window);
            self.pending = window;
            self.prefix = 0;
        }
        Ok(())
    }

    /// Ends the frame and returns the writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.block(true)?;
        if self.pledged.is_some_and(|size| size != self.total) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the data is not of the size pledged"));
        }
        if let Some(h) = &self.hasher {
            self.w.write_all(&(h.digest() as u32).to_le_bytes())?;
        }
        self.w.flush()?;
        Ok(self.w)
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let n = data.len();
        self.total += n as u64;
        while !data.is_empty() {
            // a full block is written when more data comes, so that the last one can say so
            if self.buf.len() - self.pending == BLOCK_MAX {
                self.block(false)?;
            }
            let take = (BLOCK_MAX - (self.buf.len() - self.pending)).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buf.len() > self.pending {
            self.block(false)?;
        }
        self.w.flush()
    }
}

/// Decompresses the frames it reads from `R`.
///
/// `R` is read in pieces of a block and never further than the frames go on, except that
/// the end of the data is looked for behind a frame.
///
/// Errors of the data come as [`std::io::Error`]s of the kind `InvalidData` (or
/// `UnexpectedEof` for data that ends within a frame) with the crate's [`Error`]
/// inside.
///
/// ```
/// use std::io::Read;
///
/// let frame = c14zz_zstd::compress(&[5u8; 300_000], 3);
/// let mut decoder = c14zz_zstd::stream::Decoder::new(&frame[..]);
/// // frames that would make the decoder keep more than this are refused
/// decoder.set_window_limit(8 << 20);
/// let mut piece = [0u8; 4096];
/// let mut total = 0;
/// loop {
///     let n = decoder.read(&mut piece)?;
///     if n == 0 {
///         break;
///     }
///     total += n;
/// }
/// assert_eq!(total, 300_000);
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct Decoder<R: Read> {
    r: R,
    bd: BlockDecoder,
    /// A block as read, with the header of the next one.
    input: Vec<u8>,
    /// Decoded data: what a frame's blocks may refer to, at least.
    win: Vec<u8>,
    /// The end of the decoded data in `win`, and how far it is given out.
    end: usize,
    given: usize,
    /// The size of the dictionary's content the frame started behind in `win`.
    base: usize,
    state: State,
    header: Option<FrameHeader>,
    /// The next block's header.
    next: [u8; 3],
    produced: u64,
    hasher: Option<Xxh64>,
    window_limit: u64,
    dict: Option<Dictionary>,
    /// The dictionary (its `uid`, 0 for none) whose content is at the start of `win`: a
    /// frame's data follows it there, as what the first blocks may refer to.
    front: usize,
}

#[derive(PartialEq)]
enum State {
    /// Between frames.
    Start,
    /// In a frame, `next` read.
    Block,
    /// At the end of the data, or behind an error.
    Done,
}

impl<R: Read> Decoder<R> {
    /// A decoder of the frames in `r`, of windows up to 128 MB.
    pub fn new(r: R) -> Self {
        Decoder {
            r,
            bd: BlockDecoder::new(),
            input: Vec::new(),
            win: Vec::new(),
            end: 0,
            given: 0,
            base: 0,
            state: State::Start,
            header: None,
            next: [0; 3],
            produced: 0,
            hasher: None,
            window_limit: 1 << 27,
            dict: None,
            front: 0,
        }
    }

    /// The frames to come are read with `dictionary`: those that were made with it, or
    /// that name no dictionary. (Its content is kept beside the window.)
    ///
    /// ```
    /// use std::io::Read;
    ///
    /// let dictionary = c14zz_zstd::Dictionary::raw(b"a stream of words, ");
    /// // a frame of the reference implementation, made with the same dictionary
    /// let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x25, 0x8d, 0x00, 0x00, 0x40, 0x6f, 0x66, 0x20, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x02, 0x00,
    ///     0x40, 0x6d, 0x60, 0xc9, 0x04, 0x02];
    /// let mut decoder = c14zz_zstd::stream::Decoder::new(&frame[..]);
    /// decoder.set_dictionary(&dictionary);
    /// let mut text = String::new();
    /// decoder.read_to_string(&mut text)?;
    /// assert_eq!(text, "a stream of words, of words, of words");
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_dictionary(&mut self, dictionary: &Dictionary) {
        self.dict = Some(dictionary.clone());
    }

    /// The frames to come are read without a dictionary.
    pub fn clear_dictionary(&mut self) {
        self.dict = None;
    }

    /// Frames that need a larger window than `bytes` are refused (the window is memory this
    /// keeps).
    pub fn set_window_limit(&mut self, bytes: u64) {
        self.window_limit = bytes;
    }

    /// The reader.
    pub fn get_ref(&self) -> &R {
        &self.r
    }

    /// The reader back.
    pub fn into_inner(self) -> R {
        self.r
    }

    /// Reads all of `buf`, or nothing at the end of `r`: `false`.
    fn read_or_end(&mut self, len: usize) -> io::Result<bool> {
        self.input.resize(len, 0);
        let mut got = 0;
        while got < len {
            match self.r.read(&mut self.input[got..]) {
                Ok(0) if got == 0 => return Ok(false),
                Ok(0) => return Err(Error::Truncated.into()),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    fn read_exact(&mut self, len: usize) -> io::Result<()> {
        if !self.read_or_end(len)? && len > 0 {
            return Err(Error::Truncated.into());
        }
        Ok(())
    }

    /// Reads the header of the next frame; `false` at the end of the data.
    fn start_frame(&mut self) -> io::Result<bool> {
        loop {
            if !self.read_or_end(4)? {
                return Ok(false);
            }
            let mut head = [0u8; 18 + 3];
            head[..4].copy_from_slice(&self.input);
            if u32::from_le_bytes(self.input[..4].try_into().unwrap()) & 0xFFFF_FFF0 == crate::dec::SKIPPABLE_MAGIC {
                self.read_exact(4)?;
                head[4..8].copy_from_slice(&self.input);
                let mut left = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
                while left > 0 {
                    let n = left.min(1 << 16);
                    self.read_exact(n)?;
                    left -= n;
                }
                continue;
            }
            // the rest of the header's size is in its first byte
            self.read_exact(2)?;
            head[4..6].copy_from_slice(&self.input);
            let fhd = head[4];
            let single = fhd & 0x20 != 0;
            let size = 5 + !single as usize + [0usize, 1, 2, 4][(fhd & 3) as usize] + [single as usize, 2, 4, 8][(fhd >> 6) as usize];
            // (6 bytes are read: a frame is at least a header of 6, or of 5 and a block)
            let more = size + 3 - 6;
            self.read_exact(more)?;
            head[6..6 + more].copy_from_slice(&self.input);
            let header = FrameHeader::read(&head[..size])?;
            crate::dec::check_dictionary(&header, self.dict.as_ref().map(|d| &*d.0))?;
            if header.window_size > self.window_limit {
                return Err(Error::WindowTooLarge.into());
            }
            self.next.copy_from_slice(&head[size..size + 3]);
            // the dictionary's content first, unless it is there from the frame before
            let mut base = 0;
            match &self.dict {
                Some(d) => {
                    let d = &*d.0;
                    self.bd.reset_with(d);
                    base = d.content.len();
                    if self.front != d.uid {
                        if self.win.len() < base {
                            self.win.resize(base, 0);
                        }
                        self.win[..base].copy_from_slice(&d.content);
                        self.front = d.uid;
                    }
                }
                None => {
                    self.bd.reset();
                    self.front = 0;
                }
            }
            self.base = base;
            self.end = base;
            self.given = base;
            self.produced = 0;
            self.hasher = header.checksum.then(Xxh64::new);
            self.header = Some(header);
            return Ok(true);
        }
    }

    /// Decodes the next block into `win`; `false` behind the last one.
    fn block(&mut self) -> io::Result<()> {
        let header = self.header.unwrap();
        let window = header.window_size as usize;
        let block_max = window.clamp(1, BLOCK_MAX);
        let (last, kind, size) = block_header(&self.next, 0)?;
        if kind == 3 || size > block_max {
            return Err(Error::Corrupt("block header").into());
        }
        // room for a block behind the window (and all of it behind the dictionary's content,
        // while that is there)
        let need = self.base
            + match header.content_size {
                Some(size) if size <= window as u64 => size as usize + SLACK,
                _ => 2 * window + BLOCK_MAX + SLACK,
            };
        if self.win.len() < need.min(self.end + BLOCK_MAX + SLACK) {
            self.win.resize(need.min((self.end + BLOCK_MAX + SLACK).max(2 * self.win.len())), 0);
        }
        if self.end + BLOCK_MAX + SLACK > self.win.len() && self.end > window && header.content_size.is_none_or(|s| s > window as u64) {
            // (only data of the frame is kept: it is more than a window by now, so that
            // the dictionary is no longer referred to)
            self.win.copy_within(self.end - window..self.end, 0);
            self.end = window;
            self.front = 0;
        }
        let body = if kind == 1 { 1 } else { size };
        let tail = if last { 4 * header.checksum as usize } else { 3 };
        self.read_exact(body + tail)?;
        let start = self.end;
        let limit = (self.win.len().saturating_sub(SLACK)).min(start + BLOCK_MAX);
        match kind {
            0 | 1 => {
                if start + size > limit {
                    return Err(Error::ContentSize.into());
                }
                if kind == 0 {
                    self.win[start..start + size].copy_from_slice(&self.input[..size]);
                } else {
                    self.win[start..start + size].fill(self.input[0]);
                }
                self.end = start + size;
            }
            _ => {
                self.end = self.bd.decode(&self.input[..body], 0, body, &mut self.win, start, limit, &[]).map_err(|e| match e {
                    Error::OutputTooSmall => Error::ContentSize,
                    e => e,
                })?;
            }
        }
        self.given = start;
        self.produced += (self.end - start) as u64;
        if let Some(h) = &mut self.hasher {
            h.update(&self.win[start..self.end]);
        }
        if last {
            if header.content_size.is_some_and(|size| size != self.produced) {
                return Err(Error::ContentSize.into());
            }
            if let Some(h) = &self.hasher {
                if self.input[body..body + 4] != (h.digest() as u32).to_le_bytes() {
                    return Err(Error::Checksum.into());
                }
            }
            self.state = State::Start;
        } else {
            self.next.copy_from_slice(&self.input[body..body + 3]);
        }
        Ok(())
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.given < self.end {
                let n = (self.end - self.given).min(buf.len());
                buf[..n].copy_from_slice(&self.win[self.given..self.given + n]);
                self.given += n;
                return Ok(n);
            }
            let step = match self.state {
                State::Done => return Ok(0),
                State::Start => self.start_frame().map(|more| self.state = if more { State::Block } else { State::Done }),
                State::Block => self.block(),
            };
            if let Err(e) = step {
                self.state = State::Done;
                return Err(e);
            }
        }
    }
}
