# ADR-0031: Controlled external source and explicit schema-2 preparation

Status: Accepted for Northgate. Extended by ADR-0033 for accepted schema-2 snapshots
and credential-free materialization/execution.

Recognizable LFS pointers use a strict supported canonical v1 grammar: exactly
three LF-terminated lines, lowercase SHA-256, canonical decimal size and no
extensions/CRLF. Pointer bytes remain the schema-1 source, never acquired content.
Gitlinks preserve path/exact commit. Their location/resolution state is an
explicit authority mapping or UNMAPPED/UNRESOLVED; .gitmodules remains untrusted
source data and is never parsed to acquire network authority.

ExternalSourceAuthority is a separate acquisition port. LFS acquisition names only
a digest; implementations select allowed authenticated storage, retain credentials
privately and return bounded readers. Verification checks declared digest, size
and source budgets. Submodules require an explicit authority path-to-scoped
SnapshotReference mapping; full repository/project/commit/tree/source digest and
completeness must match. There is no candidate URL argument or fallback. Thus
file://, localhost/LAN/metadata/control-service URLs, embedded credentials and
unexpected protocols cannot cause a request. Authority adapters must apply endpoint
and DNS/redirect controls before any future network transport is introduced.

resolve_external_source returns a new immutable ResolvedSourceRepresentation,
never edits the original snapshot. Its schema-2 preimage is domain
ARCHCERT-RESOLVED-SOURCE NUL + big-endian u32(2), length-prefixed original commit,
tree and schema-1 digest, u64 binding count, sorted length-prefixed bindings and
a length-prefixed schema-1 manifest of the resolved bytes. LFS bindings contain
kind byte 1, path, verified digest, u64 size. Submodule bindings contain kind byte
2, path, authority project UUID/repository, exact commit/tree/source digest.
All field lengths are big-endian u64. No audit time participates. Nested incomplete
submodules reject; recursion is not implicitly enabled.

Completeness is also an unconditional policy eligibility floor and an explicit
certificate-preparation gate, even if an authority bundle omits/excludes its
SOURCE_COMPLETE property. It is not a selectable weakening.

The initial receive endpoint does not provision network LFS/submodule credentials
or automatically invoke a resolver. Required external content remains explicitly
INCOMPLETE_EXTERNAL_SOURCE and cannot materialize or become certificate eligible.
ADR-0033 now supplies an operator-only private LFS/accepted-child adapter and a
versioned SourceBinding carried through the immutable snapshot, materializer and
runner. Only successfully resolved NEW snapshots can execute. The original
incomplete state remains immutable and cannot become eligible.
