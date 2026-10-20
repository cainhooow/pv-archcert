# ADR-0030: Fresh quarantine and immutable accepted-source publication

Status: Accepted for Northgate; extends ADRs 0005–0008.

Every authorized receive creates a fresh authority-generated private quarantine.
It contains no signing/runtime credentials and no existing refs, alternates,
objects, project hooks or project configuration. Receiving pack bytes never writes
to the accepted-source store. Independent pack and M1 closure validation precede
Git's isolated strict receive. Source sealing, rehashing and storage publication
precede delivery of Git's successful report-status to the client.

Object validation produces owned bytes through the same ObjectReader/ValidatedSource
boundary as loose ingestion. No retained path into quarantine or mutable object
store survives SourceSnapshot::seal. Quarantine is destroyed at session end.
Candidate refs are provenance; an internal
refs/archcert/candidates/<project>/<submission> identity is generated separately.
No normal branch constitutes certification state. Repeated/force-marked create
pushes cannot update earlier accepted snapshots; nonzero old-OID commands reject.
A client-side --force flag on a genuinely new ref has no wire distinction and
confers no additional authority.

DevelopmentSubmissionStore is finite local development storage, not Ravenport's
durable control plane. Private owner-only roots, descriptor-relative no-follow
reads, trusted non-writable (or root/owner sticky) ancestor checks, exclusive files, random submission IDs, one receive lock, checked scope and
bounded codecs prevent candidate-controlled storage names and cross-project reuse.
Snapshot bytes and evidence publish together by directory rename; files become
owner-read-only. Retrieval reconstructs the manifest and checks full scope and
commit/tree/digest against evidence. JSON evidence alone cannot recreate source.

Crash consistency, orphan recovery, secure erasure, hostile same-UID/root writers,
quota coordination across hosts, durable audit and transactional databases remain
outside this development store's guarantees. A disconnect after publication may
leave an accepted submission that the client did not learn about; it never changes
a published source into a rejection. Same-source replays have distinct submissions.
