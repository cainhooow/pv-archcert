//! Trusted host capacity selection shared by projection, receive and restoration.

use crate::IngressError;
use archcert_domain::source::SourceLimits;
use archcert_source::PackLimits;
use serde::{Deserialize, Serialize};

/// Explicit ingress capacity. It grants no repository or certification authority.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressCapacity {
    /// Transport, decoder and independent delta safety budgets.
    pub pack_limits: PackLimits,
    /// Selected commit closure and retained snapshot budgets.
    pub source_limits: SourceLimits,
    /// Total live-input, decoding, Git and pre-publication wall time.
    pub session_seconds: u64,
    /// Finite retained accepted and rejected submissions, without automatic eviction.
    pub max_submissions: u32,
}

impl Default for IngressCapacity {
    fn default() -> Self {
        Self {
            pack_limits: PackLimits::default(),
            source_limits: SourceLimits::default(),
            session_seconds: 30,
            max_submissions: 32,
        }
    }
}

impl IngressCapacity {
    /// Checks both layers and their shared object/work relationship before use.
    pub fn validate(self) -> Result<Self, IngressError> {
        self.pack_limits.validate().map_err(crate::unavailable)?;
        self.source_limits.validate().map_err(crate::unavailable)?;

        if !(1..=120).contains(&self.session_seconds)
            || !(1..=32).contains(&self.max_submissions)
            || self.source_limits.max_object_bytes > self.pack_limits.max_object_bytes
            || self.source_limits.max_object_work_bytes > self.pack_limits.max_decoded_bytes
        {
            return Err(IngressError::Unavailable);
        }

        Ok(self)
    }
}

/// Loads a private host-selected capacity file, never a repository/request setting.
pub fn read_capacity(path: &std::path::Path) -> Result<IngressCapacity, IngressError> {
    let bytes = crate::store::read_private_configuration(path)?;
    let capacity: IngressCapacity =
        serde_json::from_slice(&bytes).map_err(|_| IngressError::Configuration)?;

    capacity.validate().map_err(|_| IngressError::Configuration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_rejects_zero_overflow_unknown_fields_and_inconsistent_layers()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = serde_json::to_value(IngressCapacity::default())?;
        let fields = [
            ("source_limits", "max_files"),
            ("source_limits", "max_total_bytes"),
            ("source_limits", "max_blob_bytes"),
            ("source_limits", "max_tree_depth"),
            ("source_limits", "max_objects"),
            ("source_limits", "max_object_bytes"),
            ("source_limits", "max_object_work_bytes"),
            ("pack_limits", "max_pack_bytes"),
            ("pack_limits", "max_objects"),
            ("pack_limits", "max_object_bytes"),
            ("pack_limits", "max_decoded_bytes"),
            ("pack_limits", "max_delta_depth"),
            ("pack_limits", "max_expansion_ratio"),
        ];

        for (section, field) in fields {
            for value in [
                serde_json::json!(0),
                serde_json::json!(-1),
                serde_json::json!(u64::MAX),
            ] {
                let mut candidate = original.clone();
                candidate[section][field] = value;
                let parsed = serde_json::from_value::<IngressCapacity>(candidate);

                assert!(
                    parsed.is_err() || parsed.is_ok_and(|c| c.validate().is_err()),
                    "{section}.{field}"
                );
            }
        }

        for field in ["session_seconds", "max_submissions"] {
            for value in [0, 121, u64::MAX] {
                let mut candidate = original.clone();
                candidate[field] = serde_json::json!(value);
                let parsed = serde_json::from_value::<IngressCapacity>(candidate);

                assert!(parsed.is_err() || parsed.is_ok_and(|c| c.validate().is_err()));
            }
        }

        let mut candidate = original.clone();
        candidate["candidate_override"] = serde_json::json!(true);
        assert!(serde_json::from_value::<IngressCapacity>(candidate).is_err());

        let mut capacity = IngressCapacity::default();
        capacity.pack_limits.max_object_bytes = capacity.source_limits.max_object_bytes - 1;
        assert!(capacity.validate().is_err());

        capacity = IngressCapacity::default();
        capacity.pack_limits.max_decoded_bytes = capacity.source_limits.max_object_work_bytes - 1;
        assert!(capacity.validate().is_err());

        let mut pilot = IngressCapacity::default();
        pilot.pack_limits.max_pack_bytes = 128 * 1024 * 1024;
        pilot.source_limits.max_total_bytes = 128 * 1024 * 1024;
        pilot.session_seconds = 120;
        assert!(pilot.validate().is_ok());

        Ok(())
    }
}
