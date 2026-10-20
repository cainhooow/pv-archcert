# Git ingestion threat model — validator archcert-loose-v1

## Scope and assets

All repository data is hostile. The authority-provided project/repository mapping,
application, local object reader, hash/compression/Unicode libraries and source
store are trusted. This development adapter accepts an exact selected-commit
closure in loose storage on Unix. It is not a network receiver, process sandbox,
history verifier or certificate issuer.

Assets are source identity, immutable retained source, truthful completeness,
bounded authority resources, repository confidentiality and future credential
separation. No signing key or certification policy participates in ingestion.

| Threat | Security property | Mitigation | Remaining risk |
| --- | --- | --- | --- |
| Malformed objects/compression | Invalid bytes cannot become source | Bounded decode, explicit stream end/checksum, no trailing data, strict headers/lengths/commit/tree grammar | Custom parser/dependencies require independent review and fuzzing; supported grammar intentionally narrower than all Git variants |
| Object substitution/confusion | Bytes match selected immutable IDs and required types | Rehash complete Git object; check commit/tree/blob types and fixed ID widths; reject zero references | Git SHA-1 collision detection is absent; independent source SHA-256 identifies actual accepted bytes |
| Reference/tag confusion | No mutable ref decides source | Full validated OID only; no HEAD, replace refs, grafts, tag peeling or revision expressions | Authentication/provenance is supplied externally and is not implemented by the local adapter |
| Missing graph objects | Entire selected file closure exists | Missing commits/trees/blobs have distinct failures; no fallback to worktree, pack, alternate or remote | Historical parents and unreachable objects are out of scope |
| Path traversal/absolute paths | Names cannot escape future source root | Validate each tree component and full path; reject dot traversal, separators and reserved names | Future filesystem writer must enforce descriptor-relative containment too |
| Symlink escape | Link bytes cannot trigger outside reads | Hash/retain target blob as data; no checkout; NOFOLLOW on object directories/files | Materialization must preserve this rule while writing and verifying |
| Unicode/path ambiguity | No lossy names or silent collisions | Strict UTF-8 NFC; preserve bytes; reject lowercase/prefix aliases including empty directories | Full host case-folding, short-name aliases and Unicode confusables need filesystem-specific handling; future runner should use byte-preserving case-sensitive storage |
| Submodule substitution | Gitlink is not mistaken for source bytes | Record path and referenced commit; mark incomplete; no automatic remote fetching | No submodule provenance, nested source or remote authentication yet |
| LFS substitution | Pointer does not stand in for binary content | Retain pointer, record claimed content ID/size separately, mark incomplete; reject malformed recognized pointers | Detection uses the supported prefix, not attribute semantics; full retrieval and extension support are deferred |
| Mutation during validation | Accepted bytes reproduce object and source IDs | Descriptor-anchored reads; every received object independently hashed; owned payloads leave quarantine | Concurrent mutation can reject or deny service; read is not an atomic transaction over a hostile filesystem |
| Mutation after validation / TOCTOU | Runner input will bind to expected source | No mutable snapshot API; source store owns bytes; rehash at retention and explicit verification boundary | Actual volume materialization and execution boundary remain unimplemented |
| Repository bombs / repeated subtrees | Traversal has finite bounded work | File, source-byte, blob, depth, object-visit, per-object byte and aggregate work limits; depth hard ceiling | No wall-clock/I/O timeout, process RSS quota or multi-submission admission control; per-depth tree buffers contribute to peak memory |
| Huge blobs/compression bombs | Compressed size cannot hide unlimited inflation | Both compressed and inflated caps; bounded decode chunks and aggregate charge | Limited decoder work still consumes CPU; production needs process/OS budgets |
| Host filesystem interaction | Repository-controlled symlink swaps do not redirect opens | openat from held directory descriptors, NOFOLLOW on each component, regular file checks, NONBLOCK on object open | Hardlinks, mount changes, slow/network filesystems and same-UID attacks require deployment isolation; local gateway must not have access to secrets |
| Hook/filter/config execution | Ingestion never runs target code | No Git executable, checkout, shell, config parsing, filters, hooks or package tooling in runtime adapter | Compromised authority binary/dependency remains part of trusted computing base |
| Credential leakage | Future runner needs no source credentials | Source-only data port, no repository locator in materializer; no remote requests/logged Git command diagnostics | No OS capability isolation yet; run ingress with no signer/control-plane credentials before production |
| Fake reports/agent claims | Evidence derives from bytes | Application builds evidence from verified closure and computed canonical manifest; hash deserialization validates values; snapshot cannot deserialize | Returned events are not yet durable or signed; self-review is not independent certification |
| Ambiguous acceptance | Incomplete source cannot become runner-ready | Separate source completeness; typed rejection; require_complete guard | Future orchestration must enforce guard and materialization verification contract |

## Review and operational assumptions

Authority operators select input locators and resource budgets. Repository IDs
are labels, never paths. Production must isolate the gateway under an identity
that cannot open signing keys or control-plane credentials. The current process
does not enforce that OS deployment property. Source bytes can themselves contain
secrets; evidence outputs contain metadata and paths, not blob contents.

Test coverage includes independent normal Git fixtures, SHA-1/SHA-256 stores,
missing/wrong-type objects, malformed trees/commits/compression, path attacks,
object-file symlinks, immutable retained bytes, explicit incomplete states,
deterministic manifest ordering and resource failures. This is self-validation,
not independent certification, proof of parser correctness or a production
security assessment.
