//! `bitty-network-core`: shared core functionality for the Bitty network stack.
//!
//! This crate provides the fundamental building blocks used across the network
//! implementation crates:
//!
//! - [`diagnostics`]: Redacted diagnostic snapshots for logs and errors that
//!   strip secrets while preserving correlation data.
//! - [`policy`]: Re-exports of policy vocabulary from `bitty-network-api`.
//! - [`protocol`]: Protocol markers (HTTP, WebSocket) and bounded subprotocol
//!   negotiation helpers.
//! - [`runtime`]: Runtime ownership shell (marker for future executor).
//!
//! This crate is dependency-minimal: it depends only on `bitty-network-api`
//! and the Rust standard library. All modules are pure, perform no I/O, spawn
//! no background tasks, and open no sockets.

#![forbid(unsafe_code)]

pub mod diagnostics;
pub mod policy;
pub mod protocol;
pub mod runtime;
