//! Source infrastructure: bounded loose/packed Git objects and immutable storage.
//!
//! This adapter never invokes Git or reads project configuration, references,
//! hooks, alternates, LFS endpoints or the developer's working tree.

#[cfg(unix)]
mod loose;

#[cfg(unix)]
mod pack;

#[cfg(unix)]
pub use loose::LocalGitGateway;

#[cfg(unix)]
pub use pack::{GitObjectFormat, PackLimits, PackedGitGateway, receive_pack};

mod artifact;

pub use artifact::{read_snapshot, write_snapshot};

use archcert_application::source::SourceStore;
use archcert_domain::source::{SourceError, SourceSnapshot};
use std::sync::Arc;

/// Development source store; process-local retention with no mutable snapshot API.
#[derive(Default)]
pub struct MemorySourceStore {
    snapshots: Vec<Arc<SourceSnapshot>>,
}

impl SourceStore for MemorySourceStore {
    fn load(
        &self,
        reference: &archcert_domain::materialization::SnapshotReference,
    ) -> Result<Arc<SourceSnapshot>, SourceError> {
        self.snapshots
            .iter()
            .find(|s| {
                s.project() == reference.project
                    && s.repository() == &reference.repository
                    && s.identity() == &reference.identity
            })
            .map(Arc::clone)
            .ok_or(SourceError::SnapshotUnavailable)
    }

    fn retain(&mut self, snapshot: SourceSnapshot) -> Result<Arc<SourceSnapshot>, SourceError> {
        snapshot.verify(&snapshot.identity().snapshot_sha256)?;
        let snapshot = Arc::new(snapshot);
        self.snapshots.push(Arc::clone(&snapshot));

        Ok(snapshot)
    }
}
