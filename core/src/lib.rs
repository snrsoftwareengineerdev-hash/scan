//! scan-core: secp256k1 range engine for the Bitcoin puzzle challenge.
//!
//! `fast` walks a range in centered batches (C ± i·G) with one shared field inversion
//! per batch; `range` is the straightforward reference implementation used for cross-checks
//! and for tiny start keys.

pub mod addr;
pub mod fast;
pub mod fe;
pub mod range;
#[cfg(target_arch = "x86_64")]
pub mod rmd8;
