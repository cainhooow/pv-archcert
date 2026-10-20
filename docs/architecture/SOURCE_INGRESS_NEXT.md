# Next source-ingress requirements

Current LocalGitGateway consumes only the required loose SHA-1/SHA-256 objects
from an explicit local bare/.git directory. It does not invoke Git, discover refs,
consult project Git configuration, authenticate pushes or resolve external sources.
CLI source evidence is process-local; emitted JSON is not reusable retained source.

Future ingress must explicitly design and test:

| Requirement | Required boundary |
| --- | --- |
| Packfiles | Bounded pack/index/delta parsing, checksums, expansion/depth/work limits and exact closure validation; no silent Git fallback |
| Authenticated Git gateway | Authority authentication, repository authorization, secret-free quarantine worker and bounded protocol/admission controls |
| Exact push/ref mapping | Authenticate repository/ref updates, resolve to a full immutable commit at receipt; never reinterpret later mutable HEAD/ref state |
| Git LFS acquisition | Authority-approved endpoints/credentials, bounded fetch, hash/size verification, provenance and a new resolved representation; pointers remain incomplete today |
| Submodule resolution | Authority repository mapping, pinned exact commits, recursion/count/byte budgets, separate credentials and explicit provenance; no .gitmodules authority |
| Durable source storage | Immutable scoped bytes and manifests, integrity checks on retrieval, retention/access controls, crash recovery and audit continuity |

Clone and pack-to-loose conversion for external demonstrations are trusted test
preparation outside ArchCert. They do not establish a production transport or
authenticated provenance. Preserve the independent SHA-256 source identity and
credential-free execution boundary when those features are implemented.
