# Current trusted computing base and dependency review

Terminology: [ADR 0045](../adr/0045-roadmap-reconciliation.md) reconciles this work to M7 Asterwyn,
M8 Greywatch and their durable lifecycle integration. `Ironcrest` in retained
implementation identifiers and this document is a historical label. Canonical
M6 Ironcrest (Artifact Binding, Reproducible Builds & Release Permit) remains
PLANNED / NOT YET IMPLEMENTED. No security or compatibility semantics change.

## Ironcrest integrated authority path

The controlled review path adds application knowledge/semantic/challenge models,
ports and private admission/issuance prerequisites; archcert-knowledge's passive
syntax parser; archcert-semantic's local exact replay; and the independent
PostgreSQL review/admission journal in migrations 0004–0005. IroncrestWorkflow
composes verified immutable object publication with create-only role metadata,
one non-expiring invocation claim, exact review restore, gate/plan freeze and
accepted deterministic challenge evidence. These services grant no signer or
runtime capability to a reviewer or extractor.

archcert-control-plane now selects accepted target/baseline, the fixed versioned
profile, scoped mandatory knowledge and extractor registry under a private grant.
The controller's separate Ironcrest module composes those application services;
normal continuation restores accepted review/challenge evidence before policy and
certificate preparation. Policy data adds a distinct controlled bundle requiring
the challenge, while the deterministic rule engine remains unchanged. The issuer
adds the private Ironcrest prerequisite and schema-2 manifest binding; certificate
v1 payload grammar, cryptography and offline verification retain their semantics.

These authority selections, controller, metadata/object adapters and issuer remain
TCB. A digest is not authentication of a compromised authority. The reviewer has
no database, storage, runtime, signing or administrative credential capability.
No external provider is configured or implicitly selected. Local replay establishes
boundary behavior, not model quality or universal defect detection. Prompt injection
containment is architectural, not a mathematical model-safety guarantee.

The continuation activates only existing workspace edges: control-plane to
knowledge, controller to semantic and controller's already resolved async-trait.
No third-party package/version, network service or license exception was added.
See ADRs 0041–0044, IRONCREST_DEPENDENCY_REVIEW.md and the current architecture
snapshot. Stoneward worker/runner, lease/fencing and cleanup mechanisms remain
unchanged; the original exact native qualification is not broadened.

## Existing certification path

Scope: M1–M5 authenticated source acceptance, materialization, isolated engineering execution,
deterministic policy eligibility and development certificate issuance/verification.
This inventory separates what must be trusted for current observations from future
certification authority. A crate being a workspace member does not make it active.
The review used all manifests, Cargo.lock, Cargo metadata/tree, source imports and
cargo-deny. It is not a source audit of every third-party implementation.

## ACTIVE TCB

- archcert-domain: validated identities, canonical source manifest and bounded
  recursive SourceBinding for resolved external source, structural
  commands, finite budgets and operational evidence. Git IDs/modes/LFS pointer
  completeness rules are domain source semantics; no Git storage/transport or
  Docker/HTTP/filesystem/PostgreSQL/Tokio implementation exists here. OS randomness
  via uuid is an explicit infrastructure service for opaque identities, not I/O
  orchestration in domain code. No exception permitting adapter imports is required.
- archcert-application: scoped source/materialization ports, source-only handoff,
  strict project parser, authority registry/mandatory composition, execution port,
  plan/evidence mapping. No protocol/HTTP, materializer or runtime adapter import.
- archcert-source: shared bounded loose/pack object validation, gitoxide deltas,
  no-follow reads and verified immutable snapshot artifacts; no Git invocation here.
- archcert-gateway: restricted authenticated receive, explicit repository grants,
  isolated system Git protocol adapter, finite private submission storage and
  operator-only private LFS/accepted-child acquisition grants. OpenSSH, configured Git and public-key provisioning join the ingress TCB.
- archcert-materialization: no-follow descriptor syscalls, inode/device/mode/content
  verifier, versioned source-binding rehash, limited permission seal, verified export
  and separate cleanup ownership.
- archcert-runner: bounded archive transfer/reconstruction, runtime control/inspect,
  isolated start, capture/termination and sandbox/image cleanup. Materialization is
  now test-only, not a production dependency; verified export contract is inward.
- archcert-policy: strict bounded authority parser, immutable canonical SHA-256 policy
  identity, typed observation matching, five-state interpretation, stable findings and
  fail-closed pre-signing eligibility. Depends only on application/domain workspace
  contracts; no runtime/filesystem/source adapter, HTTP or signer dependency.
- archcert-evidence: deterministic manifest, exact observation/finding resolution and
  separate canonical detailed bundle with execution records and bounded log prefixes.
- archcert-certificate: eligibility/integrity gates, immutable owned canonical
  drafts, exact source/evaluation/manifest binding and proof-backed CERTIFIED.
- archcert-crypto: narrow key-identified Ed25519 signer port, strict offline
  verification and feature-gated DEVELOPMENT ONLY local key adapter. No workspace
  dependencies or authority access from execution components.
- archcert-cli: operator composition, trusted/runtime inputs, request selection,
  source expectation, result serialization/exit and source-cleanup ownership. It
  cannot be removed from the TCB while it controls those operations. CLI flags
  belong to the trusted operator, not project configuration.
- archcert-protocol: source-inspection Protobuf DTOs, bounded binary decoding and
  checked conversion for the operator gateway export. Generated codecs and the
  pinned compiler/build chain add scoped protocol/build trust, never canonical
  identity or policy/signing authority. Domain/application have no Protobuf edge.
- Approved image binaries/libraries and supply chain; Docker executable/daemon,
  containerd/runc/rootlesskit, Linux kernel/user namespaces/seccomp/cgroups, trusted
  filesystem/root/ACLs, OS randomness and administrator/worker identity. On Colima,
  also the VM/controller/tunnel. Client/version reports do not attest these binaries.

Current source-only consumers need not trust the OCI backend for source identity;
execution consumers additionally trust it. Dependencies below are scoped to the
component using them rather than treated as evidence authorities themselves.

## FUTURE TCB

Authenticated authority policy provisioning and evidence retention, durable
scheduler/recovery, hardened gateway deployment/durable storage, network external-source acquisition
and production signing/key custody remain future trust. M4B activates evidence,
certificate orchestration and crypto only through authority CLI composition.
The development local key adapter is not production key management.

## OUTSIDE CURRENT TCB

- archcertd remains outside current source/execution processing:
  the daemon has only liveness and disabled submission, with no runner/store/signer
  capability. It remains trusted for its own HTTP 501/liveness behavior. A future
  submission worker integration would place relevant transport/auth logic in its
  own active control-plane TCB; this is not claimed today.
- Test fixture generators, trusted Python runtime simulator, Git fixture/clone/
  pack-to-loose preparation and live harness are engineering test infrastructure,
  not execution of a submitted project or authenticated source provenance.
- Target code, commands and printed/file status claims have no authority.
- Historical reports and unsigned JSON are records, not independently authenticated
  certificate/evidence authority. Building every workspace crate is not linking all
  scaffolds into the CLI/daemon. A default architecture test checks active edges.

## Dependency findings

M3.5/M4A dependency history: no third-party package was added or replaced. TOML moved from CLI to application
for a single parser; it was already in the active CLI trust path. Application's
unused async-trait dependency was removed with the synchronous bootstrap check.
CLI's direct serde and runner's direct serde were unused and removed; serde remains
required transitively for real serialization. All other direct dependencies have
observed uses. Protocol no longer enters application consumers. Concrete
materialization stays in runner dev-dependencies only. Evidence/crypto remain outside runner/source/materialization and daemon dependency
graphs; M4B activates them in the CLI issuance graph. M4A replaces
the policy→evidence edge with policy→application/domain, adds CLI→policy and
normal application serde_json for exact plan identities. Policy reuses existing
TOML/serde_json/thiserror/SHA-256 dependencies; no third-party version/package was
added. The lockfile changes workspace dependency edges only.

Security-sensitive roles:

| Role | Packages and purpose |
| --- | --- |
| Cryptography | sha2 and RustCrypto digest/block-buffer/crypto-common/generic-array/typenum/cpufeatures compute source/output/policy/plan/observation/finding SHA-256; sha1 is Git compatibility only, not certificate trust; hex is fixed-format identity encoding. M4B adds Ed25519 via ed25519-dalek 3.0.0, zeroization and PKCS#8 key codecs; see the separate crypto review. |
| Git parsing | ArchCert-owned strict shared commit/tree/path validator; gitoxide bounded pack/header/delta decoding and packet framing; isolated observed system Git advertisement/receive/fsck in gateway only. Custom validator/admission review and fuzzing remain required. |
| Decompression | flate2/miniz_oxide stream admission plus gix-zlib/zlib-rs pack decoding; compressed/inflated/work/depth/expansion budgets and stream completion are checked by ArchCert. |
| Filesystem/syscalls | rustix, libc/linux-raw-sys, errno/bitflags; no-follow/exclusive/descriptor operations and nonblocking pipes. tempfile uses rustix/getrandom/fastrand for private runtime temporary storage and tests. uuid/getrandom supply opaque IDs. Third-party unsafe is not claimed absent. |
| Archive | tar 0.4.46, default xattr disabled, plus filetime; controlled transfer and bounded in-memory parse, never host extraction. GNU/PAX metadata parsing is bounded by the 96 MiB actual input; upstream extension read_all caps initial allocation at 128 KiB. |
| Serialization | serde/core/derive, serde_json, toml and its parser/writer/datetime/spanned/winnow dependencies; strict private TOML wire types, 256 KiB project and 64 KiB policy predecode bounds, bounded runtime JSON; schema-1 sorted JSON policy/plan identity. Serialization cannot manufacture sealed source/authority/runtime capabilities. |
| Runtime control | std::process plus rustix nonblocking pipes; explicit trusted Docker CLI in runner and isolated Git CLI in gateway, cleared environments. No Docker SDK dependency. tokio/mio/socket2/signal stack belongs to the bootstrap HTTP service, not domain or runner orchestration. |
| Transport | Operator-managed OpenSSH authenticates/restricts Git receive; axum/core, hyper/util, http/body/httparse, tower/http layers and URL/JSON decoding belong to the disabled-submission HTTP service. No transport dependency leaks inward. |
| Diagnostics/build | anyhow/thiserror, tracing stack/regex, clap/terminal handling and Rust proc-macro/toolchain code remain trusted for their respective build/operator/service roles. Hostile binary output is serialized as bytes, never rendered directly. |

syn 2 and 3 remain because tracing-attributes uses 2 while current derive/macros
use 3. winnow 0.7 and 1 remain because toml 0.9 and toml_parser use different
major versions. cargo-deny reports duplicate warnings, not failed bans. Forcing
unrelated upstream migrations would not establish a stronger boundary here.
TOML's existing default writer-related features remain compiled but unused by the
production parser; no new writer contract is exposed. Platform-specific lockfile
packages are not all built on the observed host. The following complete resolved
inventory records these distinctions by role, without claiming dependency correctness.

## M4A resolved third-party inventory (historical base)

Versions from locked Cargo metadata; build/platform-only entries are retained for
cross-platform review. Macro/build support is part of build trust, not live target
execution. The lockfile is the authoritative resolution.

| Package | Version | Review role |
| --- | --- | --- |
| adler2 | 2.0.1 | Decompression/checksum |
| aho-corasick | 1.1.5 | Diagnostics/error/filter support |
| anstream | 1.0.0 | Operator CLI/terminal parsing |
| anstyle | 1.0.14 | Operator CLI/terminal parsing |
| anstyle-parse | 1.0.0 | Operator CLI/terminal parsing |
| anstyle-query | 1.1.5 | Operator CLI/terminal parsing |
| anstyle-wincon | 3.0.11 | Operator CLI/terminal parsing |
| anyhow | 1.0.104 | Diagnostics/error/filter support |
| async-trait | 0.1.92 | Build/proc-macro support |
| atomic-waker | 1.1.2 | Async runtime/control support (bootstrap service) |
| axum | 0.8.9 | HTTP transport (bootstrap service) |
| axum-core | 0.5.6 | HTTP transport (bootstrap service) |
| bitflags | 2.13.2 | Filesystem/syscall/random identity |
| block-buffer | 0.10.4 | Cryptography/hash support |
| bumpalo | 3.20.3 | Other-target platform/bindings/build support |
| bytes | 1.12.1 | Async runtime/control support (bootstrap service) |
| cfg-if | 1.0.5 | Build/proc-macro support |
| clap | 4.6.7 | Operator CLI/terminal parsing |
| clap_builder | 4.6.7 | Operator CLI/terminal parsing |
| clap_derive | 4.6.7 | Build/proc-macro support |
| clap_lex | 1.1.1 | Operator CLI/terminal parsing |
| colorchoice | 1.0.5 | Operator CLI/terminal parsing |
| cpufeatures | 0.2.17 | Cryptography/hash support |
| crc32fast | 1.5.2 | Decompression/checksum |
| crypto-common | 0.1.7 | Cryptography/hash support |
| digest | 0.10.7 | Cryptography/hash support |
| equivalent | 1.0.3 | Serialization/parsing/Unicode |
| errno | 0.3.14 | Filesystem/syscall/random identity |
| fastrand | 2.5.0 | Filesystem/syscall/random identity |
| filetime | 0.2.29 | Archive/metadata |
| flate2 | 1.1.10 | Decompression/checksum |
| form_urlencoded | 1.2.2 | HTTP transport (bootstrap service) |
| futures-core | 0.3.34 | Async runtime/control support (bootstrap service) |
| futures-task | 0.3.34 | Async runtime/control support (bootstrap service) |
| futures-util | 0.3.34 | Async runtime/control support (bootstrap service) |
| generic-array | 0.14.7 | Cryptography/hash support |
| getrandom | 0.4.3 | Filesystem/syscall/random identity |
| hashbrown | 0.17.1 | Serialization/parsing/Unicode |
| heck | 0.5.0 | Build/proc-macro support |
| hex | 0.4.3 | Cryptography/hash support |
| http | 1.5.0 | HTTP transport (bootstrap service) |
| http-body | 1.1.0 | HTTP transport (bootstrap service) |
| http-body-util | 0.1.5 | HTTP transport (bootstrap service) |
| httparse | 1.10.1 | HTTP transport (bootstrap service) |
| httpdate | 1.0.3 | HTTP transport (bootstrap service) |
| hyper | 1.12.0 | HTTP transport (bootstrap service) |
| hyper-util | 0.1.21 | HTTP transport (bootstrap service) |
| indexmap | 2.14.2 | Serialization/parsing/Unicode |
| is_terminal_polyfill | 1.70.2 | Operator CLI/terminal parsing |
| itoa | 1.0.18 | Serialization/parsing/Unicode |
| js-sys | 0.3.106 | Other-target platform/bindings/build support |
| lazy_static | 1.5.1 | Diagnostics/error/filter support |
| libc | 0.2.191 | Filesystem/syscall/random identity |
| linux-raw-sys | 0.12.1 | Filesystem/syscall/random identity |
| log | 0.4.34 | Diagnostics/error/filter support |
| matchers | 0.2.0 | Diagnostics/error/filter support |
| matchit | 0.8.4 | HTTP transport (bootstrap service) |
| memchr | 2.8.3 | Serialization/parsing/Unicode |
| mime | 0.3.17 | HTTP transport (bootstrap service) |
| miniz_oxide | 0.9.1 | Decompression/checksum |
| mio | 1.2.4 | Async runtime/control support (bootstrap service) |
| nu-ansi-term | 0.50.3 | Diagnostics/error/filter support |
| once_cell | 1.21.4 | Diagnostics/error/filter support |
| once_cell_polyfill | 1.70.2 | Operator CLI/terminal parsing |
| percent-encoding | 2.3.2 | HTTP transport (bootstrap service) |
| pin-project-lite | 0.2.17 | Async runtime/control support (bootstrap service) |
| proc-macro2 | 1.0.107 | Build/proc-macro support |
| quote | 1.0.47 | Build/proc-macro support |
| r-efi | 6.0.0 | Other-target platform/bindings/build support |
| regex-automata | 0.4.18 | Diagnostics/error/filter support |
| regex-syntax | 0.8.11 | Diagnostics/error/filter support |
| rustix | 1.1.5 | Filesystem/syscall/random identity |
| rustversion | 1.0.23 | Build/proc-macro support |
| ryu | 1.0.23 | Serialization/parsing/Unicode |
| serde | 1.0.229 | Serialization/parsing/Unicode |
| serde_core | 1.0.229 | Serialization/parsing/Unicode |
| serde_derive | 1.0.229 | Build/proc-macro support |
| serde_json | 1.0.154 | Serialization/parsing/Unicode |
| serde_path_to_error | 0.1.20 | Serialization/parsing/Unicode |
| serde_spanned | 1.1.2 | Serialization/parsing/Unicode |
| serde_urlencoded | 0.7.1 | Serialization/parsing/Unicode |
| sha1 | 0.10.7 | Cryptography/hash support |
| sha2 | 0.10.9 | Cryptography/hash support |
| sharded-slab | 0.1.7 | Diagnostics/error/filter support |
| signal-hook-registry | 1.4.8 | Async runtime/control support (bootstrap service) |
| simd-adler32 | 0.3.10 | Decompression/checksum |
| slab | 0.4.12 | Async runtime/control support (bootstrap service) |
| smallvec | 1.16.3 | Diagnostics/error/filter support |
| socket2 | 0.6.5 | Async runtime/control support (bootstrap service) |
| strsim | 0.11.1 | Operator CLI/terminal parsing |
| syn | 2.0.119 | Build/proc-macro support |
| syn | 3.0.9 | Build/proc-macro support |
| sync_wrapper | 1.0.2 | Async runtime/control support (bootstrap service) |
| tar | 0.4.46 | Archive/metadata |
| tempfile | 3.27.0 | Filesystem/syscall/random identity |
| thiserror | 2.0.21 | Diagnostics/error/filter support |
| thiserror-impl | 2.0.21 | Build/proc-macro support |
| thread_local | 1.1.10 | Diagnostics/error/filter support |
| tinyvec | 1.13.3 | Serialization/parsing/Unicode |
| tokio | 1.54.0 | Async runtime/control support (bootstrap service) |
| tokio-macros | 2.7.2 | Build/proc-macro support |
| toml | 0.9.12+spec-1.1.0 | Serialization/parsing/Unicode |
| toml_datetime | 0.7.5+spec-1.1.0 | Serialization/parsing/Unicode |
| toml_parser | 1.1.5+spec-1.1.0 | Serialization/parsing/Unicode |
| toml_writer | 1.1.3+spec-1.1.0 | Serialization/parsing/Unicode |
| tower | 0.5.3 | HTTP transport (bootstrap service) |
| tower-http | 0.6.11 | HTTP transport (bootstrap service) |
| tower-layer | 0.3.3 | HTTP transport (bootstrap service) |
| tower-service | 0.3.3 | HTTP transport (bootstrap service) |
| tracing | 0.1.44 | Diagnostics/error/filter support |
| tracing-attributes | 0.1.31 | Build/proc-macro support |
| tracing-core | 0.1.36 | Diagnostics/error/filter support |
| tracing-log | 0.2.0 | Diagnostics/error/filter support |
| tracing-subscriber | 0.3.23 | Diagnostics/error/filter support |
| typenum | 1.20.1 | Cryptography/hash support |
| unicode-ident | 1.0.27 | Build/proc-macro support |
| unicode-normalization | 0.1.26 | Serialization/parsing/Unicode |
| utf8parse | 0.2.2 | Operator CLI/terminal parsing |
| uuid | 1.28.0 | Filesystem/syscall/random identity |
| valuable | 0.1.1 | Diagnostics/error/filter support |
| version_check | 0.9.5 | Build/proc-macro support |
| wasi | 0.11.1+wasi-snapshot-preview1 | Other-target platform/bindings/build support |
| wasm-bindgen | 0.2.129 | Other-target platform/bindings/build support |
| wasm-bindgen-macro | 0.2.129 | Other-target platform/bindings/build support |
| wasm-bindgen-macro-support | 0.2.129 | Other-target platform/bindings/build support |
| wasm-bindgen-shared | 0.2.129 | Other-target platform/bindings/build support |
| windows-link | 0.2.1 | Other-target platform/bindings/build support |
| windows-sys | 0.61.2 | Other-target platform/bindings/build support |
| winnow | 0.7.15 | Serialization/parsing/Unicode |
| winnow | 1.0.4 | Serialization/parsing/Unicode |
| zmij | 1.0.23 | Serialization/parsing/Unicode |


## M4B additions and active signing TCB

The [crypto dependency review](CRYPTO_DEPENDENCY_REVIEW.md) records every new
locked third-party name/version pair, purpose, maintenance/unsafe considerations,
transitive tree and independent cryptographic reproduction. This supplements the
M4A inventory above; Cargo.lock remains authoritative. The architecture guard now
checks direct and transitive exclusion of signing authority from execution and
transport graphs while allowing CLI composition. The signing threat model covers
local key theft/leakage, canonical ambiguity, substitutions, parser confusion and
remaining controller/runtime/OS trust. No production custody assurance is claimed.

## Northgate additions

The ingress TCB includes operator-managed OpenSSH/public-key provisioning,
configured system Git (path/version observed, not attested), pinned gitoxide pack/
packetline/hash/zlib and their transitive implementations, and the private bounded
development source store. Candidate packets/objects are hostile; the source
validator, canonical manifest and credential-free handoff remain ArchCert-owned.
The adapter never loads signing material, runs target hooks or acquires Docker
access. The dependency guard excludes execution/policy/signing from both gateway
crate and standalone binary. See NORTHGATE_DEPENDENCY_REVIEW.md for feature,
license, unsafe-footprint and upstream choices. Production process containment and
durable Ravenport control-plane storage remain separate qualification work.

## Northgate internal Protobuf contracts

Protocol Buffers are the primary internal machine-to-machine schema/wire format,
not cryptographic canonical serialization. The existing protocol crate owns
generated common/source v1 types and validated conversions; application owns only
transport-independent ingress observations. The separate operator gateway CLI
composes the evidence projection with a read-only Protobuf export. No runtime
receive/store/execution/signing format changes, tonic, services, persistence,
or scheduling are introduced.

[PROTOBUF_DEPENDENCY_REVIEW.md](PROTOBUF_DEPENDENCY_REVIEW.md) supplements the
earlier inventory with exact prost/prost-build/prost-types/prost-derive 0.14.4,
protoc-bin-vendored/platform crates 3.3.0, bundled libprotoc 36.2, build helpers,
maintenance, unsafe footprint, and TCB impact. Cargo.lock remains authoritative.
The reviewed build-only foldhash =0.1.5 Zlib exception is narrow; advisory/source
and other license checks remain enabled. Prost contains third-party runtime unsafe;
native protoc is trusted C++ build tooling, never run on candidate schemas.

Only authority-owned explicitly listed .proto files and pinned bundled includes
participate in generation into OUT_DIR. Candidate repositories cannot provide
schemas, plugins, includes, or compiler selection. Schema/package evolution,
unknown-value rejection, artifact-versus-semantic identity, and future narrow
signer constraints are recorded in [PROTOBUF_PROTOCOL_CONTRACTS.md](PROTOBUF_PROTOCOL_CONTRACTS.md).
The focused Northgate completion report records final gates without rewriting
earlier milestone evidence.

## Ravenport durable control-plane additions

archcert-storage owns SQLx/PostgreSQL protocol, pooling, explicit migrations and
local immutable object filesystem access. Domain/application remain independent
of persistence and wire dependencies. archcert-control-plane composes admission
and reads without execution/signing. archcertd authenticates loopback bearer
requests and maps HTTP DTOs to durable operations. archcert-controller is trusted
issuance composition and may load the explicit development key after execution,
durable eligibility and digest-bound preparation. archcert-worker receives only
private process assignments; its graph excludes storage/signing. Neither worker
nor target receives the controller environment. This local process topology trusts
the controller OS identity and executable provisioning; it does not attest worker
binaries or isolate a malicious same-UID authority process. See
[Ravenport dependency review](RAVENPORT_DEPENDENCY_REVIEW.md) and
[operations](RAVENPORT_OPERATIONS.md). No new cryptographic canonicalization,
network signer/RPC, broker, production KMS or custom encryption is introduced.
