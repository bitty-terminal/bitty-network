//! DNS resolution and caching.
//!
//! This module re-exports the DNS functionality from `bitty-network-dns`,
//! which provides explicit resolver seam with cancellation and deadlines,
//! plus a shared answer cache.

pub use bitty_network_dns::*;
