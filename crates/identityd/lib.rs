//! Identity daemon process boundary.

mod daemon;

// Keep the crate-root API stable while the implementation is grouped under
// the daemon capability.
pub use daemon::*;
