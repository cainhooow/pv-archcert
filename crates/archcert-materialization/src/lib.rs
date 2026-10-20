//! Verified ephemeral source materialization. No Git, network, shell or target execution.
//!
//! The Unix adapter requires an authority-owned private root on a trusted local
//! filesystem. Its permission seal is best effort against accidental writes, not
//! isolation against owner/root. See ADR-0008 and execution source-view ADR-0018.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    AuthorityWorkspaceRoot, MaterializedDirectory, PendingMaterialization, SealedMaterialization,
    UnixSourceMaterializer, WorkspaceDestruction, WorkspaceLease, WorkspaceLocation,
};
