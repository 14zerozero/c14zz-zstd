//! Dictionaries: data that a frame's first matches may refer to and, for a dictionary in the
//! format of the reference implementation's trainer, the tables and repeat offsets a frame
//! starts with.

use crate::dec::block::Tabs;
use crate::dec::tables::*;
use crate::enc::params::Params;
use crate::enc::prefix::Prepared;
use crate::error::{Error, Result};
use crate::fse::{self, SeqSym, MAX_TABLE_SIZE, SEQ_ZERO};
use crate::huf;
use crate::mem::rd32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// What a dictionary in the standard format starts with.
pub(crate) const DICT_MAGIC: u32 = 0xEC30_A437;

/// A dictionary: what the data of small inputs has in common, known to both sides before
/// the first frame. A frame made with one is read with the same one only.
///
/// [`Dictionary::new`] takes the bytes of a dictionary as the reference implementation's
/// trainer writes them (`zstd --train`, `ZDICT_trainFromBuffer`): they start with the magic
/// number `0xEC30A437` and have an id, tables and repeat offsets for the first block of a
/// frame, and content for its matches. Bytes that do not start with that number are
/// content only, as are any bytes given to [`Dictionary::raw`].
///
/// A `Dictionary` is made once and given to as many contexts as there are: a clone is a
/// reference to the same one.
///
/// ```
/// // content only: any bytes that are like the data
/// let dictionary = c14zz_zstd::Dictionary::new(b"{\"name\": \"\", \"count\": 0, \"active\": false}")?;
/// assert_eq!(dictionary.id(), 0);
///
/// // a frame of the reference implementation, made with the same bytes as its dictionary
/// let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x2a, 0x9d, 0x00, 0x00, 0x40, 0x61, 0x62, 0x31, 0x74, 0x72, 0x75, 0x65, 0x7d, 0x03, 0x00,
///     0x80, 0x13, 0x4e, 0x71, 0x64, 0x9b, 0x0a, 0x02];
/// let mut decompressor = c14zz_zstd::Decompressor::new();
/// decompressor.set_dictionary(&dictionary);
/// assert_eq!(decompressor.decompress(&frame, 100)?, b"{\"name\": \"ab\", \"count\": 1, \"active\": true}");
/// # Ok::<(), c14zz_zstd::Error>(())
/// ```
#[derive(Clone)]
pub struct Dictionary(pub(crate) Arc<Inner>);

pub(crate) struct Inner {
    /// Which dictionary this is, among those of the program: never 0.
    pub uid: usize,
    pub id: u32,
    /// The size of the bytes the dictionary was made of.
    pub size: usize,
    pub content: Vec<u8>,
    /// What a frame's first block has in the place of the previous block's tables.
    pub entropy: Option<Arc<DecoderTables>>,
    /// The same for the compressor.
    pub tables: Option<Box<EncoderTables>>,
    /// The match finders' tables with the content in them, for the parameters they were
    /// asked for so far.
    prepared: Mutex<Vec<Arc<Prepared>>>,
}

/// The tables of a dictionary as the block encoder has them, and its repeat offsets.
pub(crate) struct EncoderTables {
    pub huf: huf::CTable,
    /// The table has a code for every byte.
    pub huf_valid: bool,
    /// Literal lengths, offsets, match lengths (as in the block encoder).
    pub fse: [fse::CTable; 3],
    /// The table has every code a first block may need.
    pub fse_valid: [bool; 3],
    pub rep: [u32; 3],
    /// If the Huffman table is one to use as it is: the counts the tables stand for.
    pub counts: Option<Counts>,
}

/// How often the literals and the codes of the sequences are met, for the optimal parser's
/// prices: literals out of about 2048, codes out of about 1024.
#[derive(Clone, Copy)]
pub(crate) struct Counts {
    pub lit: [u32; 256],
    pub ll: [u32; 36],
    pub ml: [u32; 53],
    pub of: [u32; 32],
}

impl Inner {
    /// Whether a frame made with the dictionary is another than one made without.
    pub fn is_used(&self) -> bool {
        !self.content.is_empty() || self.tables.is_some()
    }

    /// The match finders' tables for `p` with the content in them: made when first asked
    /// for, and then the same ones for every compressor.
    pub fn prepared(&self, p: Params) -> Arc<Prepared> {
        let mut all = self.prepared.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = all.iter().find(|pre| pre.p == p) {
            return found.clone();
        }
        let made = Arc::new(Prepared::new(p, &self.content));
        all.push(made.clone());
        made
    }
}

/// The tables of a dictionary as the decoder has them, and its repeat offsets.
pub(crate) struct DecoderTables {
    pub huf: huf::DTable,
    /// Literal lengths, offsets, match lengths (as in the block decoder).
    pub tabs: [[SeqSym; MAX_TABLE_SIZE]; 3],
    pub logs: [u32; 3],
    pub rep: [usize; 3],
}

fn next_uid() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl Dictionary {
    /// A dictionary of `bytes`: in the standard format if they start with its magic number
    /// (then [`Error::BadDictionary`] if they are not what they say), else content only.
    pub fn new(bytes: &[u8]) -> Result<Dictionary> {
        if bytes.len() < 8 || rd32(bytes, 0) != DICT_MAGIC {
            return Ok(Dictionary::raw(bytes));
        }
        let id = rd32(bytes, 4);
        let (entropy, mut tables, offset_codes, used) = read_tables(&bytes[8..])?;
        let content = &bytes[8 + used..];
        if entropy.rep.iter().any(|&r| r == 0 || r > content.len()) {
            return Err(Error::BadDictionary("repeat offset beyond the content"));
        }
        // the offsets of a first block reach the content and a block's own data
        let reach = (content.len() as u64 + (128 << 10)).min(u32::MAX as u64);
        tables.fse_valid[1] = offset_codes >> (63 - reach.leading_zeros()).min(31) & 1 != 0;
        Ok(Dictionary(Arc::new(Inner {
            uid: next_uid(),
            id,
            size: bytes.len(),
            content: content.to_vec(),
            entropy: Some(Arc::from(entropy)),
            tables: Some(tables),
            prepared: Mutex::new(Vec::new()),
        })))
    }

    /// A dictionary whose content is `content`, whatever it starts with: no id, no tables.
    ///
    /// ```
    /// let dictionary = c14zz_zstd::Dictionary::raw(b"what messages have in common");
    /// assert_eq!(dictionary.id(), 0);
    /// ```
    pub fn raw(content: &[u8]) -> Dictionary {
        Dictionary(Arc::new(Inner { uid: next_uid(), id: 0, size: content.len(), content: content.to_vec(), entropy: None, tables: None, prepared: Mutex::new(Vec::new()) }))
    }

    /// The id of the dictionary, which frames made with it have in their headers; 0 for
    /// one that is content only.
    pub fn id(&self) -> u32 {
        self.0.id
    }
}

impl core::fmt::Debug for Dictionary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dictionary").field("id", &self.0.id).field("content_size", &self.0.content.len()).finish()
    }
}

/// Reads the tables and repeat offsets of a dictionary, which follow its id: the Huffman
/// table of the literals, the tables of the offsets, the match lengths and the literal
/// lengths, three offsets. Returns them for the decoder and for the encoder, up to which
/// code the table of the offsets has all codes (bit `c`: all up to `c`), and their size.
fn read_tables(src: &[u8]) -> Result<(Box<DecoderTables>, Box<EncoderTables>, u32, usize)> {
    // (the readers are those of a block's tables, and so are their errors: here it is the
    // dictionary that is wrong)
    fn bad(e: Error) -> Error {
        match e {
            Error::Corrupt(what) => Error::BadDictionary(what),
            _ => Error::BadDictionary("the tables are cut short"),
        }
    }
    let mut t = Box::new(DecoderTables { huf: huf::DTable::new(), tabs: [[SEQ_ZERO; MAX_TABLE_SIZE]; 3], logs: [0; 3], rep: [0; 3] });
    let mut at = t.huf.read(src).map_err(bad)?;
    let table = fse::CTable::new;
    let mut e = Box::new(EncoderTables { huf: huf::CTable::new(), huf_valid: false, fse: [table(), table(), table()], fse_valid: [false; 3], rep: [0; 3], counts: None });
    (_, e.huf_valid) = e.huf.read(src).map_err(bad)?;
    // (as the reference implementation's optimal parser takes them from the tables: a code
    // of `b` bits is one of `1 << b` cases; a code that is not there, one case)
    let mut counts = Counts { lit: [1; 256], ll: [1; 36], ml: [1; 53], of: [1; 32] };
    for (b, c) in counts.lit.iter_mut().enumerate() {
        let bits = e.huf.code_len(b);
        *c = if bits > 0 { 1 << 11u32.saturating_sub(bits) } else { 1 };
    }
    let mut offset_codes = 0u32;
    // (in the order of the dictionary; `k` as the block decoder counts the tables)
    const KINDS: [(usize, &[u32], &[u8], u32); 3] = [(1, &OF_BASE, &OF_BITS, 8), (2, &ML_BASE, &ML_BITS, 9), (0, &LL_BASE, &LL_BITS, 9)];
    for (k, base, bits, max_log) in KINDS {
        let mut norm = [0i16; fse::MAX_SYMBOL + 1];
        let (n, log, used) = fse::read_ncount(&mut norm[..base.len()], max_log, &src[at..]).map_err(bad)?;
        at += used;
        if !fse::seq_table(&mut t.tabs[k], &norm, n, log, base, bits) {
            return Err(Error::BadDictionary("FSE table of the sequences"));
        }
        t.logs[k] = log;
        e.fse[k].build(&norm[..n], log);
        let of_code: &mut [u32] = match k {
            0 => &mut counts.ll,
            1 => &mut counts.of,
            _ => &mut counts.ml,
        };
        for (c, &norm) in of_code.iter_mut().zip(&norm[..n]) {
            // the most bits a state of the code takes
            let bits = match norm {
                0 => log + 1,
                -1 | 1 => log,
                _ => log - (31 - (norm as u32 - 1).leading_zeros()),
            };
            *c = 1 << 10u32.saturating_sub(bits);
        }
        // (a table to repeat without a look at the codes has them all: every code of the
        // lengths, and for the offsets every code up to the largest a block needs)
        let complete = norm[..n].iter().take_while(|&&c| c != 0).count();
        e.fse_valid[k] = complete == base.len();
        if k == 1 {
            offset_codes = ((1u64 << complete) - 1) as u32;
        }
    }
    if src.len() < at + 12 {
        return Err(Error::BadDictionary("the tables are cut short"));
    }
    for (i, rep) in t.rep.iter_mut().enumerate() {
        *rep = rd32(src, at + 4 * i) as usize;
        e.rep[i] = *rep as u32;
    }
    if e.huf_valid {
        e.counts = Some(counts);
    }
    Ok((t, e, offset_codes, at + 12))
}

impl DecoderTables {
    /// Copies the table `k` to where the block decoder has its own.
    pub fn copy_table(&self, k: usize, to: &mut Tabs) {
        let n = 1usize << self.logs[k];
        to[k][..n].copy_from_slice(&self.tabs[k][..n]);
    }
}
