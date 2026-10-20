# ADR-0033: Immutable resolved snapshots and credential-free execution

Status: Accepted. Extends ADR-0031's initial prepared representation into an
accepted, materializable source. Schema-1 source identity remains unchanged.

The operator-only `archcert-gateway resolve SUBMISSION --config PRIVATE_JSON`
command resolves one authority-permitted incomplete parent into a new submission
and schema-2 SourceSnapshot. The original source and submission remain immutable.
A receive forced command cannot invoke this operation or supply its configuration.
Resolution does not create a certification job or run target code.

The development acquisition adapter uses two controlled sources:

- LFS bytes in a private, owner-controlled, digest-addressed object directory.
  Exact parent project/repository/commit/tree/source identity and per-path
  digest/size grants are mandatory. Directory/file reads reject symlinks, unsafe
  ancestors, wrong owner/modes, nonregular files and multiple hardlinks. Acquisition
  verifies actual byte size and SHA-256 under the existing source budgets.
- Submodule source from an already authenticated accepted submission in the same
  bounded development store. An explicit path-to-child-submission grant includes
  child project, repository, exact commit, tree and independent source digest.
  The gitlink commit must match and the child must be complete. Previously resolved
  complete children are supported; incomplete children never trigger recursion.

The private operator configuration and OS ownership form this adapter's acquisition
authority. It needs no SSH/LFS/submodule network credentials. No URL argument,
`.gitmodules` interpretation, discovery, redirect, DNS lookup or arbitrary filesystem
path from candidate source selects acquisition. Future HTTPS acquisition remains
separate work and must apply endpoint/address/redirect/credential controls before
using this port. Authority provisioning of this local LFS directory is explicit;
Northgate does not implement a Git LFS Batch API server or remote downloader.

SourceBinding is immutable credential-free metadata describing either schema-1
manifest hashing or ADR-0031's schema-2 canonical preimage. ResolvedDependency binds
verified LFS digest/size and scoped child identities. Child recipes are retained
for independent recursive verification; their verified digests already bind them
indirectly into the parent's preimage. The flattened content manifest is constructed
from owned bytes. Original unchanged files, modes, exact dependency coverage and
child manifest hashes are checked before sealing. A new identity cannot overwrite
the original. No audit time or submission ID participates in canonicalization.
Schema 2 intentionally includes original Git provenance and child authority scope;
it is not an alias for the schema-1 digest of the flattened files alone.

The bounded development artifact stores the binding as untrusted metadata alongside
retained bytes. Loading reconstructs the manifest and source identity, verifies
recipe consistency, then compares full accepted scope/identity/completeness and
resolution evidence. Deserialize does not produce SourceSnapshot or acceptance.
Schema-1 artifacts without this metadata remain readable and retain their hashes.

The materializer holds SourceBinding with its sealed directory capability and
reconstructs its digest at verification, permission sealing, handoff and export.
VerifiedSourceExport exposes only an owned recipe and bounded verified files. The
runner checks the exported bytes before runtime work and reconstructs the stopped
sandbox filesystem manifest under the same recipe before execution. It rechecks
the host capability and recipe at the final boundary. No acquisition authority,
locator, store or cleanup capability is added to RunnerInput. Nested LFS coverage
uses the child's own recipe: expanding a gitlink alone cannot hide an unresolved
pointer. Verified LFS bytes that happen to look like a pointer remain final bytes.

Recursive identity verification has hard limits of depth 32, 10,000 dependency
bindings, 25,000 aggregate manifest entry visits and 256 MiB canonical manifest
work. Existing file/blob/source/path limits still apply before acquisition and
flattening. Malformed, overlapping, unordered or inconsistent recipes reject.

Resolution evidence records original submission/scope, resolver attribution and
verified counts. Source submitter/key and Git pack/ref provenance refer to the
original reception and remain distinguishable from the new resolution event.
Failure records no accepted snapshot. A later independent operator certification
request references the new immutable source; acquisition configuration/files and
SSH service can already be destroyed. The development regression demonstrates
this through actual OCI checks, signing and offline verification, with an
independent Python reproduction of the schema-2 canonical source identity.
