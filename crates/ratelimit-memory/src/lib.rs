//! In-process implementations of the `RateLimiter` port: `memory` (keyed token buckets, single instance)
//! and `noop`.

#![forbid(unsafe_code)]

pub mod config;
pub mod memory;
pub mod noop;
pub mod plugin;
