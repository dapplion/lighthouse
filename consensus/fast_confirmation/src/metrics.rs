//! Prometheus metrics for the Fast Confirmation Rule.

pub use metrics::*;
use std::sync::LazyLock;

pub static FCR_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram_with_buckets(
        "beacon_fcr_seconds",
        "Runtime of the fast confirmation rule computation",
        exponential_buckets(1e-3, 2.0, 12),
    )
});
pub static FAST_CONFIRMATION_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fast_confirmation_slot",
        "Slot of the most recent confirmed block",
    )
});
pub static FCR_CONFIRMED_ROOT_CHANGES: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fcr_confirmed_root_changes_total",
        "Count of times the FCR confirmed root has changed",
    )
});
pub static FCR_ERRORS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_fcr_errors_total",
        "Count of FCR errors by error category",
        &["error"],
    )
});
pub static FCR_CONFIRMATION_DELAY_SLOTS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fcr_confirmation_delay_slots",
        "Confirmation delay: current head slot minus confirmed root slot",
    )
});
pub static FCR_SETTLED_CONFIRMATION_DELAY_SLOTS: LazyLock<Result<Histogram>> = LazyLock::new(
    || {
        try_create_histogram_with_buckets(
            "beacon_fcr_settled_confirmation_delay_slots",
            "Distribution of the FCR confirmation delay (current slot minus confirmed root slot, in \
         slots), sampled once per slot at the FCR per-slot update so block-import recomputes don't \
         bias the distribution",
            Ok(vec![1.0, 2.0, 3.0, 4.0, 5.0, 8.0, 12.0]),
        )
    },
);
pub(crate) static FAST_CONFIRMATION_FALLBACKS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_fallbacks_total",
        "Count of fallbacks of the confirmed root to the finalized block",
    )
});
pub static FCR_UNCONFIRMATION_DISTANCE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fcr_unconfirmation_distance",
        "Slots between a block FCR had confirmed and the point the confirmation withdrew to",
    )
});
pub(crate) static FCR_FALLBACK_REASONS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_fcr_fallback_reasons_total",
        "Breakdown of `beacon_fast_confirmation_fallbacks_total` by reason. Kept separate because \
         the standardised metric is specified without labels",
        &["reason"],
    )
});
pub static FAST_CONFIRMATION_REORGS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_reorgs_total",
        "Count of unconfirmations: a chain reorg made a previously confirmed block non-canonical. \
         Should always be zero under the FCR safety assumptions",
    )
});
pub(crate) static FCR_FALLBACK_SUPPORT_RATIO: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram_with_buckets(
        "beacon_fcr_fallback_support_ratio",
        "support / safety_threshold of the block that triggered a below_safety_threshold \
         fallback; values near 1.0 are marginal, lower values indicate real support loss",
        Ok(vec![0.5, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99, 1.0]),
    )
});
pub(crate) static FAST_CONFIRMATION_RESTARTS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_restarts_total",
        "Count of restarts of the confirmed root from the observed justified checkpoint",
    )
});
pub(crate) static FCR_ADVANCE: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fcr_advance_total",
        "Count of FCR advances of the confirmed root to a descendant",
    )
});
