//! The parameters of the levels: the reference implementation's tables by input size, and
//! its adjustment to small inputs.

/// How matches are searched, from fastest to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Strategy {
    Fast = 1,
    DFast,
    Greedy,
    Lazy,
    Lazy2,
    BtLazy2,
    BtOpt,
    BtUltra,
    BtUltra2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Params {
    pub window_log: u32,
    pub chain_log: u32,
    pub hash_log: u32,
    pub search_log: u32,
    pub min_match: u32,
    pub target_length: u32,
    pub strategy: Strategy,
    /// No compression: raw blocks.
    pub store: bool,
    /// The lazy strategies search rows, not hash chains.
    pub rows: bool,
}

const fn p(window_log: u32, chain_log: u32, hash_log: u32, search_log: u32, min_match: u32, target_length: u32, strategy: Strategy) -> Params {
    Params { window_log, chain_log, hash_log, search_log, min_match, target_length, strategy, store: false, rows: false }
}

pub(crate) const MAX_LEVEL: i32 = 22;
pub(crate) const DEFAULT_LEVEL: i32 = 3;

/// By input size (any, <= 256 KB, <= 128 KB, <= 16 KB), then by level (0: the base of the
/// negative levels).
static TABLE: [[Params; 23]; 4] = [
    [
        p(19, 12, 13, 1, 6, 1, Strategy::Fast),
        p(19, 13, 14, 1, 7, 0, Strategy::Fast),
        p(20, 15, 16, 1, 6, 0, Strategy::Fast),
        p(21, 16, 17, 1, 5, 0, Strategy::DFast),
        p(21, 18, 18, 1, 5, 0, Strategy::DFast),
        p(21, 18, 19, 3, 5, 2, Strategy::Greedy),
        p(21, 18, 19, 3, 5, 4, Strategy::Lazy),
        p(21, 19, 20, 4, 5, 8, Strategy::Lazy),
        p(21, 19, 20, 4, 5, 16, Strategy::Lazy2),
        p(22, 20, 21, 4, 5, 16, Strategy::Lazy2),
        p(22, 21, 22, 5, 5, 16, Strategy::Lazy2),
        p(22, 21, 22, 6, 5, 16, Strategy::Lazy2),
        p(22, 22, 23, 6, 5, 32, Strategy::Lazy2),
        p(22, 22, 22, 4, 5, 32, Strategy::BtLazy2),
        p(22, 22, 23, 5, 5, 32, Strategy::BtLazy2),
        p(22, 23, 23, 6, 5, 32, Strategy::BtLazy2),
        p(22, 22, 22, 5, 5, 48, Strategy::BtOpt),
        p(23, 23, 22, 5, 4, 64, Strategy::BtOpt),
        p(23, 23, 22, 6, 3, 64, Strategy::BtUltra),
        p(23, 24, 22, 7, 3, 256, Strategy::BtUltra2),
        p(25, 25, 23, 7, 3, 256, Strategy::BtUltra2),
        p(26, 26, 24, 7, 3, 512, Strategy::BtUltra2),
        p(27, 27, 25, 9, 3, 999, Strategy::BtUltra2),
    ],
    [
        p(18, 12, 13, 1, 5, 1, Strategy::Fast),
        p(18, 13, 14, 1, 6, 0, Strategy::Fast),
        p(18, 14, 14, 1, 5, 0, Strategy::DFast),
        p(18, 16, 16, 1, 4, 0, Strategy::DFast),
        p(18, 16, 17, 3, 5, 2, Strategy::Greedy),
        p(18, 17, 18, 5, 5, 2, Strategy::Greedy),
        p(18, 18, 19, 3, 5, 4, Strategy::Lazy),
        p(18, 18, 19, 4, 4, 4, Strategy::Lazy),
        p(18, 18, 19, 4, 4, 8, Strategy::Lazy2),
        p(18, 18, 19, 5, 4, 8, Strategy::Lazy2),
        p(18, 18, 19, 6, 4, 8, Strategy::Lazy2),
        p(18, 18, 19, 5, 4, 12, Strategy::BtLazy2),
        p(18, 19, 19, 7, 4, 12, Strategy::BtLazy2),
        p(18, 18, 19, 4, 4, 16, Strategy::BtOpt),
        p(18, 18, 19, 4, 3, 32, Strategy::BtOpt),
        p(18, 18, 19, 6, 3, 128, Strategy::BtOpt),
        p(18, 19, 19, 6, 3, 128, Strategy::BtUltra),
        p(18, 19, 19, 8, 3, 256, Strategy::BtUltra),
        p(18, 19, 19, 6, 3, 128, Strategy::BtUltra2),
        p(18, 19, 19, 8, 3, 256, Strategy::BtUltra2),
        p(18, 19, 19, 10, 3, 512, Strategy::BtUltra2),
        p(18, 19, 19, 12, 3, 512, Strategy::BtUltra2),
        p(18, 19, 19, 13, 3, 999, Strategy::BtUltra2),
    ],
    [
        p(17, 12, 12, 1, 5, 1, Strategy::Fast),
        p(17, 12, 13, 1, 6, 0, Strategy::Fast),
        p(17, 13, 15, 1, 5, 0, Strategy::Fast),
        p(17, 15, 16, 2, 5, 0, Strategy::DFast),
        p(17, 17, 17, 2, 4, 0, Strategy::DFast),
        p(17, 16, 17, 3, 4, 2, Strategy::Greedy),
        p(17, 16, 17, 3, 4, 4, Strategy::Lazy),
        p(17, 16, 17, 3, 4, 8, Strategy::Lazy2),
        p(17, 16, 17, 4, 4, 8, Strategy::Lazy2),
        p(17, 16, 17, 5, 4, 8, Strategy::Lazy2),
        p(17, 16, 17, 6, 4, 8, Strategy::Lazy2),
        p(17, 17, 17, 5, 4, 8, Strategy::BtLazy2),
        p(17, 18, 17, 7, 4, 12, Strategy::BtLazy2),
        p(17, 18, 17, 3, 4, 12, Strategy::BtOpt),
        p(17, 18, 17, 4, 3, 32, Strategy::BtOpt),
        p(17, 18, 17, 6, 3, 256, Strategy::BtOpt),
        p(17, 18, 17, 6, 3, 128, Strategy::BtUltra),
        p(17, 18, 17, 8, 3, 256, Strategy::BtUltra),
        p(17, 18, 17, 10, 3, 512, Strategy::BtUltra),
        p(17, 18, 17, 5, 3, 256, Strategy::BtUltra2),
        p(17, 18, 17, 7, 3, 512, Strategy::BtUltra2),
        p(17, 18, 17, 9, 3, 512, Strategy::BtUltra2),
        p(17, 18, 17, 11, 3, 999, Strategy::BtUltra2),
    ],
    [
        p(14, 12, 13, 1, 5, 1, Strategy::Fast),
        p(14, 14, 15, 1, 5, 0, Strategy::Fast),
        p(14, 14, 15, 1, 4, 0, Strategy::Fast),
        p(14, 14, 15, 2, 4, 0, Strategy::DFast),
        p(14, 14, 14, 4, 4, 2, Strategy::Greedy),
        p(14, 14, 14, 3, 4, 4, Strategy::Lazy),
        p(14, 14, 14, 4, 4, 8, Strategy::Lazy2),
        p(14, 14, 14, 6, 4, 8, Strategy::Lazy2),
        p(14, 14, 14, 8, 4, 8, Strategy::Lazy2),
        p(14, 15, 14, 5, 4, 8, Strategy::BtLazy2),
        p(14, 15, 14, 9, 4, 8, Strategy::BtLazy2),
        p(14, 15, 14, 3, 4, 12, Strategy::BtOpt),
        p(14, 15, 14, 4, 3, 24, Strategy::BtOpt),
        p(14, 15, 14, 5, 3, 32, Strategy::BtUltra),
        p(14, 15, 15, 6, 3, 64, Strategy::BtUltra),
        p(14, 15, 15, 7, 3, 256, Strategy::BtUltra),
        p(14, 15, 15, 5, 3, 48, Strategy::BtUltra2),
        p(14, 15, 15, 6, 3, 128, Strategy::BtUltra2),
        p(14, 15, 15, 7, 3, 256, Strategy::BtUltra2),
        p(14, 15, 15, 8, 3, 256, Strategy::BtUltra2),
        p(14, 15, 15, 8, 3, 512, Strategy::BtUltra2),
        p(14, 15, 15, 9, 3, 512, Strategy::BtUltra2),
        p(14, 15, 15, 10, 3, 999, Strategy::BtUltra2),
    ],
];

/// The parameters of `level` for an input of `size` bytes (`None`: not known).
pub(crate) fn params(level: i32, size: Option<u64>) -> Params {
    tuned(level, size, 0, false)
}

/// The parameters of `level` for the tables that are kept with a dictionary of `content`
/// bytes of content, for the small inputs a dictionary is for (the reference
/// implementation's parameters of a `CDict`).
pub(crate) fn for_dictionary(level: i32, content: u64) -> Params {
    tuned(level, None, content, true)
}

/// The parameters of `level` for an input of `size` bytes behind a dictionary of `content`
/// bytes of content.
pub(crate) fn with_dictionary(level: i32, size: u64, content: u64) -> Params {
    tuned(level, Some(size), content, false)
}

/// The window that a frame of `size` bytes (`None`: not known) is to have when it is
/// compressed with the tables of `kept` (see `for_dictionary`): large enough for the data
/// to be all in it, up to the window of level 1.
pub(crate) fn window_with_kept(kept: &Params, size: Option<u64>) -> u32 {
    match size {
        Some(size) => {
            let limited = size.min(1 << 19) as u32;
            kept.window_log.max(if limited > 1 { 32 - (limited - 1).leading_zeros() } else { 1 })
        }
        None => kept.window_log,
    }
}

/// The number of bits of the positions that the tables are to tell apart: those of the
/// window and, where the data does not fill it, of a dictionary's content before it.
fn dict_and_window_log(window_log: u32, size: u64, dict: u64) -> u32 {
    let window = 1u64 << window_log;
    if dict == 0 || window >= dict.saturating_add(size) {
        window_log
    } else if dict + window >= 1 << 31 {
        31
    } else {
        64 - (dict + window - 1).leading_zeros()
    }
}

/// The parameters of `level` for an input of `size` bytes (`None`: not known) behind `dict`
/// bytes of a dictionary's content; `kept`: for tables to keep with the dictionary.
fn tuned(level: i32, size: Option<u64>, dict: u64, kept: bool) -> Params {
    // (the reference implementation's sum for an input of unknown size wraps around to this)
    let known = match size {
        Some(size) => size.saturating_add(dict),
        None if dict > 0 => dict + 499,
        None => u64::MAX,
    };
    let table = (known <= 256 << 10) as usize + (known <= 128 << 10) as usize + (known <= 16 << 10) as usize;
    let row = if level == 0 { DEFAULT_LEVEL } else { level.clamp(0, MAX_LEVEL) };
    let mut p = TABLE[table][row.max(0) as usize];
    if level == super::STORE {
        p = TABLE[table][1];
        p.store = true;
    } else if level < 0 {
        // faster than level 1: larger steps, no literal compression
        p = TABLE[table][0];
        p.target_length = (-level.max(-(1 << 17))) as u32;
    }
    // (tables that are kept with a dictionary are for small inputs)
    let size = if kept && dict > 0 && size.is_none() { Some(513) } else { size };
    if let Some(size) = size {
        // no window larger than the input, no tables larger than the window needs
        if size < 1 << 30 && dict <= 1 << 30 {
            let total = size + dict;
            let src_log = if total < 64 { 6 } else { 64 - (total - 1).leading_zeros() };
            p.window_log = p.window_log.min(src_log);
        }
    }
    let reach = dict_and_window_log(p.window_log, size.unwrap_or(u64::MAX), dict);
    p.hash_log = p.hash_log.min(reach + 1);
    // (a binary tree has two entries of the chain table per position)
    let tree = (p.strategy >= Strategy::BtLazy2) as u32;
    if p.chain_log > reach + tree {
        p.chain_log = reach + tree;
    }
    p.window_log = p.window_log.max(10);
    // hash chains are faster in small windows (the reference implementation's choice)
    p.rows = p.strategy >= Strategy::Greedy && p.strategy < Strategy::BtLazy2 && p.window_log > 14;
    p
}
