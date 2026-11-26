//! Where the time goes, by stage: counters for measurements, compiled in with the feature
//! `prof` only (then a clock is read twice per stage and block).

/// The stages: decoding (literals, sequence tables, sequences), then compressing (match
/// search, literals, sequences).
pub const STAGES: [&str; 6] = ["d-lit", "d-tab", "d-seq", "c-match", "c-lit", "c-seq"];

#[cfg(feature = "prof")]
mod on {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::time::Instant;

    static NS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];

    pub(crate) type Start = Instant;

    #[inline(always)]
    pub(crate) fn start() -> Start {
        Instant::now()
    }

    #[inline(always)]
    pub(crate) fn stop(start: Start, stage: usize) -> Start {
        let now = Instant::now();
        NS[stage].fetch_add((now - start).as_nanos() as u64, Relaxed);
        now
    }

    /// The nanoseconds per stage since the last call.
    pub fn take() -> [u64; 6] {
        std::array::from_fn(|i| NS[i].swap(0, Relaxed))
    }
}

#[cfg(not(feature = "prof"))]
mod on {
    /// (Not `()`: a clock that is not there is still kept in a variable.)
    #[derive(Clone, Copy)]
    pub(crate) struct Start;

    #[inline(always)]
    pub(crate) fn start() -> Start {
        Start
    }

    #[inline(always)]
    pub(crate) fn stop(start: Start, _stage: usize) -> Start {
        start
    }

    /// The nanoseconds per stage since the last call: nothing without the feature `prof`.
    pub fn take() -> [u64; 6] {
        [0; 6]
    }
}

pub use on::take;
pub(crate) use on::{start, stop};
