//! The codes of the sequences section: base values, extra bits, predefined distributions.

use crate::fse::{build_seq_table, SeqSym, MAX_TABLE_SIZE, SEQ_ZERO};

pub(crate) const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000,
    0x4000, 0x8000, 0x10000,
];
pub(crate) const LL_BITS: [u8; 36] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
pub(crate) const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51,
    59, 67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803, 0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
];
pub(crate) const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16,
];
/// Offset code `n` reads `n` bits; codes above 1 give the offset itself.
pub(crate) const OF_BASE: [u32; 32] = {
    let mut t = [0u32; 32];
    t[1] = 1;
    let mut n = 2;
    while n < 32 {
        t[n] = (1u32 << n) - 3;
        n += 1;
    }
    t
};
pub(crate) const OF_BITS: [u8; 32] = {
    let mut t = [0u8; 32];
    let mut n = 0;
    while n < 32 {
        t[n] = n as u8;
        n += 1;
    }
    t
};

pub(crate) const LL_DEFAULT_NORM: [i16; 36] = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1];
pub(crate) const LL_DEFAULT_LOG: u32 = 6;
pub(crate) const OF_DEFAULT_NORM: [i16; 29] = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1];
pub(crate) const OF_DEFAULT_LOG: u32 = 5;
pub(crate) const ML_DEFAULT_NORM: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1,
    -1, -1, -1, -1,
];
pub(crate) const ML_DEFAULT_LOG: u32 = 6;

const fn default_table(norm: &[i16], log: u32, base: &[u32], bits: &[u8]) -> [SeqSym; MAX_TABLE_SIZE] {
    let mut t = [SEQ_ZERO; MAX_TABLE_SIZE];
    assert!(build_seq_table(&mut t, norm, norm.len(), log, base, bits));
    t
}

pub(crate) static LL_DEFAULT: [SeqSym; MAX_TABLE_SIZE] = default_table(&LL_DEFAULT_NORM, LL_DEFAULT_LOG, &LL_BASE, &LL_BITS);
pub(crate) static OF_DEFAULT: [SeqSym; MAX_TABLE_SIZE] = default_table(&OF_DEFAULT_NORM, OF_DEFAULT_LOG, &OF_BASE, &OF_BITS);
pub(crate) static ML_DEFAULT: [SeqSym; MAX_TABLE_SIZE] = default_table(&ML_DEFAULT_NORM, ML_DEFAULT_LOG, &ML_BASE, &ML_BITS);
