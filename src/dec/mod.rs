//! Decompression: frames, their blocks, and where the data goes.

pub(crate) mod block;
pub(crate) mod tables;

use crate::dict::Inner;
use crate::error::{Error, Result};
use crate::mem::{rd16, rd32, rd64};
use crate::xxh64::xxh64;
use block::{BlockDecoder, BLOCK_MAX, SLACK};

pub(crate) const MAGIC: u32 = 0xFD2F_B528;
pub(crate) const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
/// The largest window the format's decoders must take on 64-bit machines.
const WINDOW_LOG_MAX: u32 = 31;

/// What a frame's header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// How far back the frame's data refers at most.
    pub window_size: u64,
    /// The size of the frame's content, if the header has it.
    pub content_size: Option<u64>,
    /// The id of the dictionary the frame needs ([`crate::Dictionary::id`]); 0 if it names none.
    pub dictionary_id: u32,
    /// The frame ends with a checksum of its content.
    pub checksum: bool,
    /// The size of the header.
    pub header_size: usize,
}

impl FrameHeader {
    /// Reads the header of the frame at the start of `src` (not of a skippable frame).
    pub fn read(src: &[u8]) -> Result<FrameHeader> {
        if src.len() < 5 {
            return Err(if src.len() >= 4 && rd32(src, 0) != MAGIC { Error::BadMagic } else { Error::Truncated });
        }
        if rd32(src, 0) != MAGIC {
            return Err(Error::BadMagic);
        }
        let fhd = src[4];
        let fcs_flag = fhd >> 6;
        let single = fhd & 0x20 != 0;
        if fhd & 0x08 != 0 {
            return Err(Error::Corrupt("reserved bit of the frame header"));
        }
        let dict_bytes = [0usize, 1, 2, 4][(fhd & 3) as usize];
        let fcs_bytes = match fcs_flag {
            0 => single as usize,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let header_size = 5 + !single as usize + dict_bytes + fcs_bytes;
        if src.len() < header_size {
            return Err(Error::Truncated);
        }
        let mut at = 5;
        let mut window_size = 0u64;
        if !single {
            let w = src[at];
            at += 1;
            let log = 10 + (w >> 3) as u32;
            if log > WINDOW_LOG_MAX {
                return Err(Error::WindowTooLarge);
            }
            window_size = (1u64 << log) + ((1u64 << log) >> 3) * (w & 7) as u64;
        }
        let dictionary_id = match dict_bytes {
            0 => 0,
            1 => src[at] as u32,
            2 => rd16(src, at),
            _ => rd32(src, at),
        };
        at += dict_bytes;
        let content_size = match fcs_bytes {
            0 => None,
            1 => Some(src[at] as u64),
            2 => Some(rd16(src, at) as u64 + 256),
            4 => Some(rd32(src, at) as u64),
            _ => Some(rd64(src, at)),
        };
        if single {
            window_size = content_size.unwrap();
        }
        Ok(FrameHeader { window_size, content_size, dictionary_id, checksum: fhd & 4 != 0, header_size })
    }
}

/// The size of the skippable frame at the start of `src`, if there is one.
pub(crate) fn skippable(src: &[u8]) -> Result<Option<usize>> {
    if src.len() >= 4 && rd32(src, 0) & 0xFFFF_FFF0 == SKIPPABLE_MAGIC {
        if src.len() < 8 {
            return Err(Error::Truncated);
        }
        let size = 8 + rd32(src, 4) as usize;
        if size > src.len() {
            return Err(Error::Truncated);
        }
        return Ok(Some(size));
    }
    Ok(None)
}

/// A header of a block: `(last, kind, size, )`.
#[inline]
pub(crate) fn block_header(src: &[u8], at: usize) -> Result<(bool, u32, usize)> {
    if at + 3 > src.len() {
        return Err(Error::Truncated);
    }
    let h = src[at] as u32 | (src[at + 1] as u32) << 8 | (src[at + 2] as u32) << 16;
    Ok((h & 1 != 0, (h >> 1) & 3, (h >> 3) as usize))
}

/// Where decompressed data goes: a buffer that may grow.
pub(crate) trait Sink {
    /// The buffer, with room for `n` bytes at `at` if it can have that, and the end of the
    /// room data may use (behind it there may be room for scratch).
    fn room(&mut self, at: usize, n: usize) -> (&mut [u8], usize);
}

/// A slice as it is.
pub(crate) struct SliceSink<'a>(pub &'a mut [u8]);

impl Sink for SliceSink<'_> {
    #[inline]
    fn room(&mut self, _at: usize, _n: usize) -> (&mut [u8], usize) {
        let len = self.0.len();
        (self.0, len)
    }
}

/// A vector that grows up to `max` bytes of data; its length is the room made so far.
pub(crate) struct VecSink<'a> {
    pub v: &'a mut Vec<u8>,
    pub max: usize,
}

impl Sink for VecSink<'_> {
    #[inline]
    fn room(&mut self, at: usize, n: usize) -> (&mut [u8], usize) {
        let end = at.saturating_add(n).min(self.max);
        if self.v.len() < end + SLACK {
            self.v.resize(end + SLACK, 0);
        }
        (&mut self.v[..], end)
    }
}

/// Whether a frame with `header` is one to decode with `dict`: a frame that names a
/// dictionary is read with that one only (as the reference implementation has it, a frame
/// that names none is read with whatever is given).
pub(crate) fn check_dictionary(header: &FrameHeader, dict: Option<&Inner>) -> Result<()> {
    match dict {
        _ if header.dictionary_id == 0 => Ok(()),
        None => Err(Error::DictionaryNeeded),
        Some(d) if d.id != header.dictionary_id => Err(Error::WrongDictionary),
        Some(_) => Ok(()),
    }
}

/// Decompresses all frames of `src` into `sink` from `start` on, each with `dict`; returns
/// the end of the data.
pub(crate) fn decode_frames<S: Sink>(bd: &mut BlockDecoder, src: &[u8], sink: &mut S, start: usize, dict: Option<&Inner>) -> Result<usize> {
    let mut at = 0;
    let mut op = start;
    if src.is_empty() {
        return Err(Error::Truncated);
    }
    while at < src.len() {
        if let Some(size) = skippable(&src[at..])? {
            at += size;
            continue;
        }
        let (used, end) = decode_frame(bd, &src[at..], sink, op, dict)?;
        at += used;
        op = end;
    }
    Ok(op)
}

/// Decompresses the frame at the start of `src` into `sink` at `start`; returns the size of
/// the frame and the end of its data.
pub(crate) fn decode_frame<S: Sink>(bd: &mut BlockDecoder, src: &[u8], sink: &mut S, start: usize, dict: Option<&Inner>) -> Result<(usize, usize)> {
    let header = FrameHeader::read(src)?;
    check_dictionary(&header, dict)?;
    let ext: &[u8] = match dict {
        Some(d) => {
            bd.reset_with(d);
            &d.content
        }
        None => {
            bd.reset();
            &[]
        }
    };
    let block_max = (header.window_size.min(BLOCK_MAX as u64) as usize).max(1);
    let mut at = header.header_size;
    let mut op = start;
    if let Some(size) = header.content_size {
        // a block of 4 bytes gives 128 KB at most: more than that per byte is not a frame's size
        if size / (BLOCK_MAX as u64 / 4 + 1) > src.len() as u64 {
            return Err(Error::Corrupt("content size beyond what the frame can hold"));
        }
        let (buf, end) = sink.room(start, size as usize);
        if end - start < size as usize || buf.len() < end {
            return Err(Error::OutputTooSmall);
        }
    }
    loop {
        let (last, kind, size) = block_header(src, at)?;
        at += 3;
        match kind {
            0 | 1 => {
                if size > block_max {
                    return Err(Error::Corrupt("block larger than the frame allows"));
                }
                let (buf, end) = sink.room(op, size);
                if size > end.min(buf.len()).saturating_sub(op) {
                    return Err(Error::OutputTooSmall);
                }
                if kind == 0 {
                    let raw = src.get(at..at + size).ok_or(Error::Truncated)?;
                    buf[op..op + size].copy_from_slice(raw);
                    at += size;
                } else {
                    let &byte = src.get(at).ok_or(Error::Truncated)?;
                    buf[op..op + size].fill(byte);
                    at += 1;
                }
                op += size;
            }
            2 => {
                if size > block_max {
                    return Err(Error::Corrupt("block larger than the frame allows"));
                }
                if at + size > src.len() {
                    return Err(Error::Truncated);
                }
                // (no more room than the frame says it needs: a small frame is no reason to
                // make room for a whole block)
                let (most, known) = match header.content_size {
                    Some(size) => (BLOCK_MAX.min((size as usize).saturating_sub(op - start)), true),
                    None => (BLOCK_MAX, false),
                };
                let (buf, end) = sink.room(op, most);
                let limit = end.min(buf.len()).min(op + most);
                let bound_by_frame = known && limit == op + most;
                // the frame's data starts at `start`: matches do not reach before it, but
                // into the dictionary
                op = start
                    + bd.decode(src, at, size, &mut buf[start..], op - start, limit.saturating_sub(start).max(op - start), ext).map_err(|e| match e {
                        Error::OutputTooSmall if bound_by_frame => Error::ContentSize,
                        e => e,
                    })?;
                at += size;
            }
            _ => return Err(Error::Corrupt("reserved block type")),
        }
        if last {
            break;
        }
    }
    if let Some(size) = header.content_size {
        if (op - start) as u64 != size {
            return Err(Error::ContentSize);
        }
    }
    if header.checksum {
        if at + 4 > src.len() {
            return Err(Error::Truncated);
        }
        let (buf, _) = sink.room(op, 0);
        if rd32(src, at) != xxh64(&buf[start..op]) as u32 {
            return Err(Error::Checksum);
        }
        at += 4;
    }
    Ok((at, op))
}
