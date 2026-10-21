//! Bounded deterministic authority policy over typed application observations.
//!
//! No certificate, signer, transport, runtime adapter or target output is consumed.

mod evaluation;

mod model;

pub use evaluation::*;

pub use model::*;
