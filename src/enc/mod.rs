//! Compression: frames, their blocks, the match finders' state.

mod bt;
mod dfast;
mod entropy;
mod fast;
mod hash;
mod lazy;
mod opt;
pub(crate) mod params;
pub(crate) mod prefix;
mod postsplit;
mod seq;
mod split;

use crate::dec::block::BLOCK_MAX;
use crate::dec::MAGIC;
use crate::dict;
use crate::error::{Error, Result};
use crate::xxh64::Xxh64;
use entropy::BlockEncoder;
use params::{Params, Strategy};
use seq::SeqStore;
use std::sync::Arc;

/// Indexes of the match finders' tables stay below this: beyond it the tables are cleared.
const INDEX_MAX: u64 = 0xE000_0000;

/// A level that stores the data in raw blocks.
pub(crate) const STORE: i32 = i32::MIN;

/// Where compressed data goes.
pub(crate) trait Out {
    fn put(&mut self, bytes: &[u8]) -> Result<()>;
}

impl Out for Vec<u8> {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// A slice filled from its start.
pub(crate) struct SliceOut<'a> {
    pub buf: &'a mut [u8],
    pub at: usize,
}

impl Out for SliceOut<'_> {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let room = self.buf.get_mut(self.at..self.at + bytes.len()).ok_or(Error::OutputTooSmall)?;
        room.copy_from_slice(bytes);
        self.at += bytes.len();
        Ok(())
    }
}

/// The largest size of the frame for `len` bytes (the reference implementation's bound).
pub fn compress_bound(len: usize) -> usize {
    len + (len >> 8) + if len < BLOCK_MAX { (BLOCK_MAX - len) >> 11 } else { 0 }
}

/// The match finders' tables. Their entries are indexes that grow from frame to frame, so
/// that those of earlier frames are known by their value and the tables need no clearing.
pub(crate) struct Tables {
    hash: Vec<u32>,
    chain: Vec<u32>,
    /// The tags of the row-based match finder.
    tags: Vec<u8>,
    /// The optimal parser's table of the latest positions of 3 bytes.
    hash3: Vec<u32>,
    /// The index of the first position the lazy match finder has not in its table yet.
    next_to_update: u32,
    /// The index of the next byte.
    next_idx: u32,
    /// The dictionary (its `uid`, 0 for none) and the parameters whose prepared tables
    /// these are, but for what the current frame's data put into them.
    kept: (usize, Option<Params>),
    /// There may be entries of frames that were not compressed with tables kept with a
    /// dictionary (`dirty_beyond`), or of such tables (`was_kept`): the indexes of the one
    /// kind are not those of the other, so the tables are cleared in between.
    dirty_beyond: bool,
    was_kept: bool,
    /// How far back the matches of the tree match finders may be in the block at hand.
    tree_window_log: u32,
}

/// The parameters of the row-based match finder for `p`: `(row log, hash log)`.
fn row_params(p: &Params) -> (u32, u32) {
    let row_log = p.search_log.clamp(4, 6);
    (row_log, p.hash_log.min(24 + row_log).max(row_log + 1))
}

/// Whether the lazy strategies of `p` search rows: hash chains are faster in small windows
/// (the reference implementation's choice).
fn use_rows(p: &Params) -> bool {
    p.rows
}

/// Whether `p`'s strategy searches binary trees: they are in the chain table.
fn use_trees(p: &Params) -> bool {
    p.strategy >= Strategy::BtLazy2
}

/// The number of bits of the hashes of 3 bytes the optimal parser keeps the latest positions
/// of, if `p` has matches of 3 bytes; else 0.
fn hash3_log(p: &Params) -> u32 {
    if p.strategy >= Strategy::BtOpt && p.min_match <= 3 {
        p.window_log.min(17)
    } else {
        0
    }
}

/// The `n` entries of `v` from the first one at a multiple of 64 bytes on, the size of a
/// cache line: a row of 16 positions, or 64 tags, is in one line then, not in two. (`v` has
/// 64 bytes more than `n` entries; where it starts makes no difference to what is found,
/// only to how fast.)
fn aligned<T>(v: &mut [T], n: usize) -> &mut [T] {
    let skip = v.as_ptr().align_offset(64);
    let skip = if skip <= v.len() - n { skip } else { 0 };
    &mut v[skip..skip + n]
}

impl Tables {
    fn new() -> Self {
        Tables { hash: Vec::new(), chain: Vec::new(), tags: Vec::new(), hash3: Vec::new(), next_to_update: 1, next_idx: 1, kept: (0, None), dirty_beyond: false, was_kept: false, tree_window_log: 0 }
    }

    /// Makes the tables `p` needs.
    fn prepare(&mut self, p: &Params) {
        let rows = use_rows(p);
        let hash = 1usize << if rows { row_params(p).1 } else { p.hash_log };
        // (with room to start the rows at a multiple of 64 bytes: see `aligned`)
        if self.hash.len() < hash + 16 {
            self.hash.resize(hash + 16, 0);
        }
        let chain = if p.strategy == Strategy::DFast || (p.strategy >= Strategy::Greedy && !rows) { 1usize << p.chain_log } else { 0 };
        if self.chain.is_empty() && chain > 0 {
            // (zeroed memory as the system gives it: a tree of a large window touches only as
            // much of its table as there is data)
            self.chain = vec![0; chain];
        } else if self.chain.len() < chain {
            self.chain.resize(chain, 0);
        }
        if rows && self.tags.len() < hash + 64 {
            self.tags.resize(hash + 64, 0);
        }
        let hash3 = hash3_log(p);
        if hash3 > 0 && self.hash3.len() < 1 << hash3 {
            self.hash3.resize(1 << hash3, 0);
        }
    }

    fn clear(&mut self) {
        self.hash.fill(0);
        self.chain.fill(0);
        self.tags.fill(0);
        self.hash3.fill(0);
        self.next_idx = 1;
        self.next_to_update = 1;
        self.kept = (0, None);
    }
}

/// What compression keeps between frames.
pub(crate) struct Encoder {
    tables: Tables,
    store: SeqStore,
    blocks: BlockEncoder,
    /// The optimal parser's counts and tables.
    opt: opt::State,
    /// The block splitter's partitions.
    parts: postsplit::Parts,
    rep: [u32; 3],
    /// How much smaller than its data the frame is so far.
    savings: i64,
    /// The size of the frame's header; 0 once it is in `savings`.
    header: usize,
    /// For a frame with a dictionary: the dictionary's content (of the dictionary with the
    /// `uid` beside it) and behind it the start of the frame's data, as far as the content
    /// can be referred to.
    joined: Vec<u8>,
    joined_dict: usize,
    /// The tables kept with a dictionary (its `uid`) for a level, as last asked for: a frame
    /// after another with the same ones does not ask the dictionary again.
    kept: Option<(usize, i32, Arc<prefix::Prepared>)>,
}

/// What a frame is to have.
#[derive(Clone, Copy)]
pub(crate) struct FrameOptions {
    pub level: i32,
    pub checksum: bool,
    pub content_size: bool,
}

fn frame_header(out: &mut [u8; 18], p: &Params, size: Option<u64>, checksum: bool, dict_id: u32) -> usize {
    out[..4].copy_from_slice(&MAGIC.to_le_bytes());
    let window = 1u64 << p.window_log;
    let single = size.is_some_and(|s| s <= window);
    let fcs_code = match size {
        None => 0,
        Some(s) => (s >= 256) as u8 + (s >= 65536 + 256) as u8 + (s >= 0xFFFF_FFFF) as u8,
    };
    let id_code = (dict_id > 0) as u8 + (dict_id >= 256) as u8 + (dict_id >= 65536) as u8;
    out[4] = fcs_code << 6 | (single as u8) << 5 | (checksum as u8) << 2 | id_code;
    let mut at = 5;
    if !single {
        out[at] = ((p.window_log - 10) << 3) as u8;
        at += 1;
    }
    let id_bytes = [0, 1, 2, 4][id_code as usize];
    out[at..at + id_bytes].copy_from_slice(&dict_id.to_le_bytes()[..id_bytes]);
    at += id_bytes;
    if let Some(s) = size {
        match fcs_code {
            0 => {
                if single {
                    out[at] = s as u8;
                    at += 1;
                }
            }
            1 => {
                out[at..at + 2].copy_from_slice(&((s - 256) as u16).to_le_bytes());
                at += 2;
            }
            2 => {
                out[at..at + 4].copy_from_slice(&(s as u32).to_le_bytes());
                at += 4;
            }
            _ => {
                out[at..at + 8].copy_from_slice(&s.to_le_bytes());
                at += 8;
            }
        }
    }
    at
}

impl Encoder {
    pub fn new() -> Self {
        Encoder { tables: Tables::new(), store: SeqStore::new(), blocks: BlockEncoder::new(), opt: opt::State::new(), parts: postsplit::Parts::new(), rep: [1, 4, 8], savings: 0, header: 0, joined: Vec::new(), joined_dict: 0, kept: None }
    }

    /// The size of the match finders' tables.
    pub fn table_bytes(&self) -> usize {
        4 * (self.tables.hash.capacity() + self.tables.chain.capacity() + self.tables.hash3.capacity()) + self.tables.tags.capacity() + self.joined.capacity()
    }

    /// Writes `src` as one frame.
    pub fn compress<O: Out>(&mut self, src: &[u8], out: &mut O, opt: FrameOptions) -> Result<()> {
        let size = src.len() as u64;
        let p = self.start_frame(opt, Some(size), out)?;
        self.chunk(&p, src, 0, src.len(), true, true, 0, out)?;
        if opt.checksum {
            let mut h = Xxh64::new();
            h.update(src);
            out.put(&(h.digest() as u32).to_le_bytes())?;
        }
        Ok(())
    }

    /// Starts a frame of `size` bytes (`None`: not known) and writes its header; returns the
    /// parameters its blocks are to be written with.
    pub fn start_frame<O: Out>(&mut self, opt: FrameOptions, size: Option<u64>, out: &mut O) -> Result<Params> {
        let p = params::params(opt.level, size);
        let mut header = [0u8; 18];
        let n = frame_header(&mut header, &p, size.filter(|_| opt.content_size), opt.checksum, 0);
        out.put(&header[..n])?;
        self.savings = 0;
        self.header = n;
        self.begin(&p, size.unwrap_or(0));
        Ok(p)
    }

    /// Writes `src` as one frame that is to be read with the dictionary `d`.
    pub fn compress_with<O: Out>(&mut self, src: &[u8], out: &mut O, opt: FrameOptions, d: &dict::Inner) -> Result<()> {
        // the content before the data, in one piece: what the match finders ask for
        let mut joined = core::mem::take(&mut self.joined);
        if self.joined_dict != d.uid {
            joined.clear();
            joined.extend_from_slice(&d.content);
            self.joined_dict = d.uid;
        }
        let content = d.content.len();
        joined.truncate(content);
        let started = self.start_frame_with(opt, Some(src.len() as u64), d, &joined, out);
        let result = started.and_then(|(p, kept)| {
            // (data further on than a window is behind the content's reach: it is
            // compressed where it is)
            let near = src.len().min(1 << p.window_log);
            joined.extend_from_slice(&src[..near]);
            let result = self.chunk(&p, &joined, content, content + near, near == src.len(), true, content, out).and_then(|()| {
                if near < src.len() {
                    self.chunk(&p, src, near, src.len(), true, false, 0, out)?;
                }
                Ok(())
            });
            if let Some(kept) = kept {
                if near == src.len() && kept.restores(near) && self.tables.kept.0 == d.uid {
                    kept.restore(&mut self.tables, &joined, content, hash3_log(&p));
                } else {
                    self.tables.kept = (0, None);
                }
            }
            result
        });
        self.joined = joined;
        result?;
        if opt.checksum {
            let mut h = Xxh64::new();
            h.update(src);
            out.put(&(h.digest() as u32).to_le_bytes())?;
        }
        Ok(())
    }

    /// Starts a frame of `size` bytes (`None`: not known) that is to be read with the
    /// dictionary `d` and writes its header. `content` is the dictionary's content, where
    /// the frame's data will follow it. Returns the parameters its blocks are to be written
    /// with and, if the tables are now the ones kept with the dictionary, those: after
    /// the frame they can be had again with `Prepared::restore`.
    ///
    /// As in the reference implementation (`ZSTD_compress_usingCDict`), an input that is
    /// small, or small beside the dictionary, or of unknown size, is compressed with the
    /// parameters and tables that are kept with the dictionary; a large one gets the
    /// parameters of its size, and tables that the content is put into for this frame.
    pub fn start_frame_with<O: Out>(&mut self, opt: FrameOptions, size: Option<u64>, d: &dict::Inner, content: &[u8], out: &mut O) -> Result<(Params, Option<Arc<prefix::Prepared>>)> {
        let n = content.len() as u64;
        let small = n > 0 && size.is_none_or(|size| size < 128 << 10 || size < n.saturating_mul(6));
        let kept = small.then(|| match &self.kept {
            Some((uid, level, kept)) if (*uid, *level) == (d.uid, opt.level) => kept.clone(),
            _ => {
                // (the parameters are those for the size of all of the dictionary)
                let kept = d.prepared(params::for_dictionary(opt.level, d.size as u64));
                self.kept = Some((d.uid, opt.level, kept.clone()));
                kept
            }
        });
        let p = match (&kept, size) {
            (Some(kept), _) => Params { window_log: params::window_with_kept(&kept.p, size), ..kept.p },
            (None, Some(size)) if n > 0 => params::with_dictionary(opt.level, size, n),
            _ => params::params(opt.level, size),
        };
        let mut header = [0u8; 18];
        let header_size = frame_header(&mut header, &p, size.filter(|_| opt.content_size), opt.checksum, d.id);
        out.put(&header[..header_size])?;
        self.savings = 0;
        self.header = header_size;
        match &kept {
            Some(kept) => {
                if self.tables.kept != (d.uid, Some(kept.p)) {
                    kept.copy_to(&mut self.tables, content.len());
                    self.tables.kept = (d.uid, Some(kept.p));
                }
                // (the frame's window may be larger than the one of the kept tables, and
                // what goes by it with it)
                self.tables.prepare(&p);
                self.rep = [1, 4, 8];
                self.blocks.reset();
                self.opt.reset();
            }
            None => {
                self.begin(&p, n + size.unwrap_or(0));
                // the content into the tables, as the data before the frame's
                let t = &mut self.tables;
                let (hash, chain, tags) = prefix::parts(&p, &mut t.hash, &mut t.chain, &mut t.tags);
                prefix::load(&p, hash, chain, tags, content, t.next_idx, false);
                t.next_idx = t.next_idx.wrapping_add(content.len() as u32);
                t.next_to_update = t.next_idx;
            }
        }
        if let Some(tables) = &d.tables {
            self.blocks.reset_with(tables);
            self.opt.reset_with(tables);
            self.rep = tables.rep;
        }
        Ok((p, kept))
    }

    /// Starts a frame of `size` bytes (as far as known).
    fn begin(&mut self, p: &Params, size: u64) {
        if core::mem::take(&mut self.tables.was_kept) {
            self.tables.clear();
        }
        self.tables.kept = (0, None);
        self.tables.dirty_beyond = true;
        self.tables.prepare(p);
        // (`btultra2` takes the indexes of its first block twice)
        let twice = if p.strategy == Strategy::BtUltra2 { BLOCK_MAX as u64 } else { 0 };
        if self.tables.next_idx as u64 + size.min(u32::MAX as u64) + twice >= INDEX_MAX {
            self.tables.clear();
        }
        self.tables.next_to_update = self.tables.next_idx;
        if use_rows(p) {
            // The positions of earlier frames are known by their indexes, but only after
            // their tags were found to be the ones searched: none are, without the tags.
            // (They would be most of the time where the same kind of data comes again.)
            aligned(&mut self.tables.tags, 1 << row_params(p).1).fill(0);
        }
        self.rep = [1, 4, 8];
        self.blocks.reset();
        self.opt.reset();
    }

    /// Writes `data[at..end]`, which follows the frame's data so far, as blocks; what is
    /// before it in `data` is that data, as far back as it is kept (at least the window, or
    /// all). `last`: the frame ends with it; `first`: it starts with it. `prefix`: so many
    /// bytes at the start of `data` are the content of the frame's dictionary, all the
    /// frame's data so far follows them.
    #[allow(clippy::too_many_arguments)]
    pub fn chunk<O: Out>(&mut self, p: &Params, data: &[u8], mut at: usize, end: usize, last: bool, mut first: bool, prefix: usize, out: &mut O) -> Result<()> {
        loop {
            // A block of the largest size may end early where its data changes (as the
            // reference implementation has it): not as long as nothing was gained, so that
            // data that does not compress grows by its block headers only.
            // (No block is larger than the window. Windows that small are those of a stream
            // with a small dictionary only: other frames of unknown size have large ones.)
            let mut size = (end - at).min(BLOCK_MAX).min(1 << p.window_log);
            if size == BLOCK_MAX && self.savings >= 3 {
                size = split::block_size(&data[at..at + BLOCK_MAX], p.strategy);
            }
            let block_end = at + size;
            let written = self.block(p, data, at, block_end, last && block_end == end, first, prefix, out)?;
            self.savings += size as i64 - written as i64;
            first = false;
            at = block_end;
            if at == end {
                break;
            }
        }
        // (the header counts once the first call is over, as in the reference implementation)
        self.savings -= core::mem::take(&mut self.header) as i64;
        Ok(())
    }

    /// Writes the block `data[at..end]` (see `chunk`); returns the size of what was written.
    #[allow(clippy::too_many_arguments)]
    fn block<O: Out>(&mut self, p: &Params, data: &[u8], at: usize, end: usize, last: bool, first: bool, prefix: usize, out: &mut O) -> Result<usize> {
        let size = end - at;
        // (a dictionary's content can all be referred to as long as the frame's data is
        // within one window, and not at all from then on; the tree match finders look at
        // the window of each position, as the reference implementation's do: the history is
        // that of the block's first one)
        let window = 1usize << p.window_log;
        let whole = end - prefix <= window;
        let low = if whole {
            0
        } else if use_trees(p) {
            at.saturating_sub(window).max(prefix)
        } else {
            end - window
        };
        // (the content may be further back than a window is large)
        self.tables.tree_window_log = if whole && prefix > 0 { usize::BITS - 1 } else { p.window_log };
        // `btultra2` parses the first block of a frame twice, the second time at new indexes
        let seed = size >= 7 && !p.store && opt::seeds(p, &self.opt, at, size);
        let indexes = if seed { 2 * size } else { size };
        let mut idx = self.tables.next_idx;
        if idx as u64 + indexes as u64 >= INDEX_MAX {
            // the indexes are used up: start over, with nothing in the tables
            self.tables.clear();
            idx = 1u32.wrapping_add((at - low) as u32);
        }
        self.tables.next_idx = idx.wrapping_add(indexes as u32);
        let mut compressed = 0;
        let rep_before = self.rep;
        if size >= 7 && !p.store {
            let s = &data[low..end];
            let start = at - low;
            let low_idx = idx.wrapping_sub(start as u32);
            self.store.reset(size);
            let t = &mut self.tables;
            let (store, rep) = (&mut self.store, &mut self.rep);
            let clock = crate::prof::start();
            match p.strategy {
                // (behind a dictionary's content, a search for small inputs)
                Strategy::Fast if prefix > 0 && low == 0 => {
                    let hash = hash::Table::new(&mut t.hash, p.hash_log);
                    match p.min_match {
                        0..=4 => fast::block_behind_content::<4>(hash, p.target_length, store, rep, s, start, low_idx),
                        5 => fast::block_behind_content::<5>(hash, p.target_length, store, rep, s, start, low_idx),
                        6 => fast::block_behind_content::<6>(hash, p.target_length, store, rep, s, start, low_idx),
                        7 => fast::block_behind_content::<7>(hash, p.target_length, store, rep, s, start, low_idx),
                        _ => fast::block_behind_content::<8>(hash, p.target_length, store, rep, s, start, low_idx),
                    }
                }
                Strategy::Fast => {
                    let hash = hash::Table::new(&mut t.hash, p.hash_log);
                    match p.min_match {
                    0..=4 => fast::block::<4>(hash, p.target_length, store, rep, s, start, low_idx),
                    5 => fast::block::<5>(hash, p.target_length, store, rep, s, start, low_idx),
                    6 => fast::block::<6>(hash, p.target_length, store, rep, s, start, low_idx),
                    7 => fast::block::<7>(hash, p.target_length, store, rep, s, start, low_idx),
                    _ => fast::block::<8>(hash, p.target_length, store, rep, s, start, low_idx),
                    }
                }
                Strategy::DFast => {
                    let hash = hash::Table::new(&mut t.hash, p.hash_log);
                    let chain = hash::Table::new(&mut t.chain, p.chain_log);
                    match p.min_match {
                        0..=4 => dfast::block::<4>(hash, chain, store, rep, s, start, low_idx),
                        5 => dfast::block::<5>(hash, chain, store, rep, s, start, low_idx),
                        6 => dfast::block::<6>(hash, chain, store, rep, s, start, low_idx),
                        _ => dfast::block::<7>(hash, chain, store, rep, s, start, low_idx),
                    }
                }
                Strategy::BtLazy2 => {
                    let trees = bt::TreeTables {
                        hash: &mut t.hash[..1 << p.hash_log],
                        chain: &mut t.chain[..1 << p.chain_log],
                        hash3: &mut [],
                        hash_log: p.hash_log,
                        hash3_log: 0,
                        search_log: p.search_log,
                        window_log: t.tree_window_log,
                        target_length: p.target_length,
                        next_to_update: &mut t.next_to_update,
                    };
                    match p.min_match.clamp(4, 6) {
                        4 => lazy::block::<_, 2>(bt::DubtFinder::<4>::new(trees, s, start, low_idx), store, rep, s, start),
                        5 => lazy::block::<_, 2>(bt::DubtFinder::<5>::new(trees, s, start, low_idx), store, rep, s, start),
                        _ => lazy::block::<_, 2>(bt::DubtFinder::<6>::new(trees, s, start, low_idx), store, rep, s, start),
                    }
                }
                Strategy::BtOpt | Strategy::BtUltra | Strategy::BtUltra2 => opt::block(t, &mut self.opt, p, store, rep, s, start, low_idx, seed),
                _ => {
                    let depth = match p.strategy {
                        Strategy::Greedy => 0,
                        Strategy::Lazy => 1,
                        _ => 2,
                    };
                    macro_rules! lazy {
                        ($finder:expr) => {{
                            let f = $finder;
                            match depth {
                                0 => lazy::block::<_, 0>(f, store, rep, s, start),
                                1 => lazy::block::<_, 1>(f, store, rep, s, start),
                                _ => lazy::block::<_, 2>(f, store, rep, s, start),
                            }
                        }};
                    }
                    if use_rows(p) {
                        let (row_log, hash_log) = row_params(p);
                        let rows = lazy::Rows {
                            table: aligned(&mut t.hash, 1 << hash_log),
                            tags: aligned(&mut t.tags, 1 << hash_log),
                            row_hash_log: hash_log - row_log,
                            search_log: p.search_log,
                            next_to_update: &mut t.next_to_update,
                        };
                        match (p.min_match.clamp(4, 6), row_log) {
                            (4, 4) => lazy!(lazy::RowFinder::<4, 4>::new(rows, s, start, low_idx)),
                            (4, 5) => lazy!(lazy::RowFinder::<4, 5>::new(rows, s, start, low_idx)),
                            (4, _) => lazy!(lazy::RowFinder::<4, 6>::new(rows, s, start, low_idx)),
                            (5, 4) => lazy!(lazy::RowFinder::<5, 4>::new(rows, s, start, low_idx)),
                            (5, 5) => lazy!(lazy::RowFinder::<5, 5>::new(rows, s, start, low_idx)),
                            (5, _) => lazy!(lazy::RowFinder::<5, 6>::new(rows, s, start, low_idx)),
                            (_, 4) => lazy!(lazy::RowFinder::<6, 4>::new(rows, s, start, low_idx)),
                            (_, 5) => lazy!(lazy::RowFinder::<6, 5>::new(rows, s, start, low_idx)),
                            (_, _) => lazy!(lazy::RowFinder::<6, 6>::new(rows, s, start, low_idx)),
                        }
                    } else {
                        let chains = lazy::Chains {
                            hash: &mut t.hash[..1 << p.hash_log],
                            chain: &mut t.chain[..1 << p.chain_log],
                            hash_log: p.hash_log,
                            search_log: p.search_log,
                            next_to_update: &mut t.next_to_update,
                        };
                        match p.min_match.clamp(4, 6) {
                            4 => lazy!(lazy::ChainFinder::<4>::new(chains, s, start, low_idx)),
                            5 => lazy!(lazy::ChainFinder::<5>::new(chains, s, start, low_idx)),
                            _ => lazy!(lazy::ChainFinder::<6>::new(chains, s, start, low_idx)),
                        }
                    }
                }
            }
            crate::prof::stop(clock, 3);
            let literal_compression = !(p.strategy == Strategy::Fast && p.target_length > 0);
            if postsplit::enabled(p) {
                // the block as several, if its sequences are of several kinds
                if let Some(written) = self.split(p, data, at, end, last, first, rep_before, out)? {
                    return Ok(written);
                }
            }
            let clock = crate::prof::start();
            compressed = self.blocks.encode(&self.store, size, p.strategy, literal_compression);
            crate::prof::stop(clock, 5);
            if !first && compressed < 25 && data[at..end].iter().all(|&b| b == data[at]) {
                compressed = 1;
            }
        }
        let header = |kind: u32, size: usize| ((last as u32) | kind << 1 | (size as u32) << 3).to_le_bytes();
        if compressed > 1 {
            self.blocks.confirm();
        }
        self.blocks.block_done();
        match compressed {
            0 => {
                self.rep = rep_before;
                out.put(&header(0, size)[..3])?;
                out.put(&data[at..end])?;
                Ok(3 + size)
            }
            1 => {
                self.rep = rep_before;
                out.put(&header(1, size)[..3])?;
                out.put(&data[at..at + 1])?;
                Ok(4)
            }
            n => {
                out.put(&header(2, n)[..3])?;
                out.put(&self.blocks.out[..n])?;
                Ok(3 + n)
            }
        }
    }
}
