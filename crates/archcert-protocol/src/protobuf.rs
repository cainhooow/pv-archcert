//! Generated transport DTOs and the single validated ingress conversion boundary.
//! Wire decoding is not authentication or acceptance of source bytes.

mod conversion;
pub use conversion::{ConversionError, decode_submission, encode_submission};

/// Supported source-ingress contract version, independent of source hash schemas.
pub const CONTRACT_VERSION: u32 = 1;
/// Fully qualified source-ingress package.
pub const SOURCE_PACKAGE: &str = "archcert.source.v1";
/// Fully qualified shared identity package.
pub const COMMON_PACKAGE: &str = "archcert.common.v1";
/// Build-generated descriptor set for schema inspection, not canonical identity.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/archcert-v1.bin"));

/// Shared identity DTOs generated from authority-owned common/v1 schemas.
#[allow(missing_docs)]
pub mod common {
    /// Version 1 identities; all inbound values require validated conversion.
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/archcert.common.v1.rs"));
    }
}
/// Source-ingress DTOs generated from authority-owned source/v1 schemas.
#[allow(missing_docs)]
pub mod source {
    /// Version 1 source state; decoding never grants a capability.
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/archcert.source.v1.rs"));
    }
}

/// Private worker process protocol conversions.
pub mod worker;
/// Execution transport contracts, owned exclusively by this protocol adapter.
#[allow(missing_docs)]
pub mod execution {
    /// Version 1 worker assignment/result contracts.
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/archcert.execution.v1.rs"));
    }
}
