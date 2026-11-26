//! The errors of this crate.

use core::fmt;

/// Why data could not be decompressed (or, for [`Error::OutputTooSmall`], compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The data does not start with a zstd frame.
    BadMagic,
    /// The data ends within a frame.
    Truncated,
    /// The data is not what a compressor writes.
    Corrupt(&'static str),
    /// The frame needs a window larger than the limit of the decompressor.
    WindowTooLarge,
    /// The frame needs a dictionary, and none was given.
    DictionaryNeeded,
    /// The frame needs another dictionary than the one given: the ids are not the same.
    WrongDictionary,
    /// The bytes say they are a dictionary of the standard format and are not: what is
    /// wrong.
    BadDictionary(&'static str),
    /// The frame's checksum does not match its content.
    Checksum,
    /// The frame's content is not of the size its header says.
    ContentSize,
    /// The result does not fit the room given.
    OutputTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadMagic => f.write_str("not a zstd frame"),
            Error::Truncated => f.write_str("the data ends within a frame"),
            Error::Corrupt(what) => write!(f, "corrupt data: {what}"),
            Error::WindowTooLarge => f.write_str("the frame's window is larger than the limit"),
            Error::DictionaryNeeded => f.write_str("the frame needs a dictionary"),
            Error::WrongDictionary => f.write_str("the frame needs another dictionary"),
            Error::BadDictionary(what) => write!(f, "not a dictionary: {what}"),
            Error::Checksum => f.write_str("the checksum does not match"),
            Error::ContentSize => f.write_str("the content is not of the size the frame header says"),
            Error::OutputTooSmall => f.write_str("the result does not fit"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        let kind = match e {
            Error::Truncated => std::io::ErrorKind::UnexpectedEof,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, e)
    }
}

pub(crate) type Result<T> = core::result::Result<T, Error>;
