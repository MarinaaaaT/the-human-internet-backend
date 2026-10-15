//! Where an invocation's time goes, in the logs.
//!
//! Each step logs one `timing` event: `step` names it, `ms` is how long it
//! took, and some add a detail (bytes, JPEG quality attempts). The JSON
//! subscriber nests these under `fields`, and every event carries the
//! invocation's `requestId` in its span, so in CloudWatch Logs Insights:
//!
//! ```text
//! fields @timestamp, fields.step, fields.ms
//! | filter fields.message = "timing"
//! | stats avg(fields.ms), pct(fields.ms, 90), count() by fields.step
//! ```
//!
//! and `filter span.requestId = "…"` lays out a single invocation. The steps:
//! `download`, `decode`, `draw_mark`, `encode` (with `quality` and
//! `attempts`), `check_input`, `add_ingredient` (with `ingredient`), `sign`
//! (with `manifest`: `capture`, `mark` or `photo`), `upload` (with
//! `output`), and `total` (with `path` and `status`) once per invocation.
//! c2pa makes claim and ingredient thumbnails inside `sign` and
//! `add_ingredient`, by decoding the asset, so their time is counted there.

use std::time::Instant;

/// Milliseconds since `start`, to 0.1ms.
pub fn ms_since(start: Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 10_000.0).round() / 10.0
}

/// Runs `f` and logs how long it took as `step`.
pub fn time<T>(step: &'static str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    tracing::info!(step, ms = ms_since(start), "timing");
    out
}
