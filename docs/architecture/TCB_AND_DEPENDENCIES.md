# Current trusted computing base and dependency review

Scope: M1–M4A source acceptance, materialization, isolated engineering execution and
deterministic unsigned policy eligibility.
This inventory separates what must be trusted for current observations from future
certification authority. A crate being a workspace member does not make it active.
The review used all manifests, Cargo.lock, Cargo metadata/tree, source imports and
cargo-deny. It is not a source audit of every third-party implementation.

## ACTIVE TCB

- archcert-domain: validated identities, canonical source manifest, structural
  commands, finite budgets and operational evidence. Git IDs/modes/LFS pointer
  completeness rules are domain source semantics; no Git storage/transport or
  Docker/HTTP/filesystem/PostgreSQL/Tokio implementation exists here. OS randomness
  via uuid is an explicit infrastructure service for opaque identities, not I/O
  orchestration in domain code. No exception permitting adapter imports is required.
- archcert-application: scoped source/materialization ports, source-only handoff,
  strict project parser, authority registry/mandatory composition, execution port,
  plan/evidence mapping. No protocol/HTTP, materializer or runtime adapter import.
- archcert-source: bounded custom loose-object parser/decompressor, no-follow reads,
  process-local retained bytes; no system Git invocation in the active path.
- archcert-materialization: no-follow descriptor syscalls, inode/device/mode/content
  verifier, limited permission seal, verified export and separate cleanup ownership.
- archcert-runner: bounded archive transfer/reconstruction, runtime control/inspect,
  isolated start, capture/termination and sandbox/image cleanup. Materialization is
  now test-only, not a production dependency; verified export contract is inward.
- archcert-policy: strict bounded authority parser, immutable canonical SHA-256 policy
  identity, typed observation matching, five-state interpretation, stable findings and
  fail-closed pre-signing eligibility. Depends only on application/domain workspace
  contracts; no runtime/filesystem/source adapter, HTTP or signer dependency.
- archcert-cli: operator composition, trusted/runtime inputs, request selection,
  source expectation, result serialization/exit and source-cleanup ownership. It
  cannot be removed from the TCB while it controls those operations. CLI flags
  belong to the trusted operator, not project configuration.
- Approved image binaries/libraries and supply chain; Docker executable/daemon,
  containerd/runc/rootlesskit, Linux kernel/user namespaces/seccomp/cgroups, trusted
  filesystem/root/ACLs, OS randomness and administrator/worker identity. On Colima,
  also the VM/controller/tunnel. Client/version reports do not attest these binaries.

Current source-only consumers need not trust the OCI backend for source identity;
execution consumers additionally trust it. Dependencies below are scoped to the
component using them rather than treated as evidence authorities themselves.

## FUTURE TCB

Authenticated authority policy provisioning and evidence retention, durable
scheduler/recovery, production source gateway/storage, external source acquisition
and signing/key storage remain future trust. Generic evidence-payload and crypto
packages stay inactive. The old verdict-bearing evidence scaffold was replaced
with payload references, and the old policy scaffold was replaced by the active
M4A evaluator after boundary review. No signer implementation/call exists.

## OUTSIDE CURRENT TCB

- archcert-protocol and archcertd are outside current source/execution processing:
  the daemon has only liveness and disabled submission, with no runner/store/signer
  capability. They remain trusted for their own HTTP 501/liveness behavior. A future
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

No third-party package was added or replaced. TOML moved from CLI to application
for a single parser; it was already in the active CLI trust path. Application's
unused async-trait dependency was removed with the synchronous bootstrap check.
CLI's direct serde and runner's direct serde were unused and removed; serde remains
required transitively for real serialization. All other direct dependencies have
observed uses. Protocol no longer enters application consumers. Concrete
materialization stays in runner dev-dependencies only. Existing inactive
evidence/crypto packages remain outside the active execution graph. M4A replaces
the policy→evidence edge with policy→application/domain, adds CLI→policy and
normal application serde_json for exact plan identities. Policy reuses existing
TOML/serde_json/thiserror/SHA-256 dependencies; no third-party version/package was
added. The lockfile changes workspace dependency edges only.

Security-sensitive roles:

| Role | Packages and purpose |
| --- | --- |
| Cryptography | sha2 and RustCrypto digest/block-buffer/crypto-common/generic-array/typenum/cpufeatures compute source/output/policy/plan/observation/finding SHA-256; sha1 is Git compatibility only, not certificate trust; hex is fixed-format identity encoding. No signing primitive/key is added. |
| Git parsing | ArchCert-owned strict loose/commit/tree parser; no libgit2/gix or Git subprocess dependency in active source ingestion. Custom parser review/fuzzing remains required. |
| Decompression | flate2 with explicit miniz_oxide, adler2/simd-adler32/crc32fast; compressed/inflated/work budgets and stream completion are checked by ArchCert. |
| Filesystem/syscalls | rustix, libc/linux-raw-sys, errno/bitflags; no-follow/exclusive/descriptor operations and nonblocking pipes. tempfile uses rustix/getrandom/fastrand for private runtime temporary storage and tests. uuid/getrandom supply opaque IDs. Third-party unsafe is not claimed absent. |
| Archive | tar 0.4.46, default xattr disabled, plus filetime; controlled transfer and bounded in-memory parse, never host extraction. GNU/PAX metadata parsing is bounded by the 96 MiB actual input; upstream extension read_all caps initial allocation at 128 KiB. |
| Serialization | serde/core/derive, serde_json, toml and its parser/writer/datetime/spanned/winnow dependencies; strict private TOML wire types, 256 KiB project and 64 KiB policy predecode bounds, bounded runtime JSON; schema-1 sorted JSON policy/plan identity. Serialization cannot manufacture sealed source/authority/runtime capabilities. |
| Runtime control | std::process plus rustix nonblocking pipes; only explicit trusted Docker CLI is spawned by production code, cleared environment. No Docker SDK dependency. tokio/mio/socket2/signal stack belongs to the bootstrap HTTP service, not domain or runner orchestration. |
| Transport | axum/core, hyper/util, http/body/httparse, tower/http layers and URL/JSON decoding belong to the disabled-submission HTTP service. No transport dependency leaks inward. |
| Diagnostics/build | anyhow/thiserror, tracing stack/regex, clap/terminal handling and Rust proc-macro/toolchain code remain trusted for their respective build/operator/service roles. Hostile binary output is serialized as bytes, never rendered directly. |

syn 2 and 3 remain because tracing-attributes uses 2 while current derive/macros
use 3. winnow 0.7 and 1 remain because toml 0.9 and toml_parser use different
major versions. cargo-deny reports duplicate warnings, not failed bans. Forcing
unrelated upstream migrations would not establish a stronger boundary here.
TOML's existing default writer-related features remain compiled but unused by the
production parser; no new writer contract is exposed. Platform-specific lockfile
packages are not all built on the observed host. The following complete resolved
inventory records these distinctions by role, without claiming dependency correctness.

## Resolved third-party inventory

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
