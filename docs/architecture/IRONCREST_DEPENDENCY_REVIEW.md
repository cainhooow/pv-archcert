# Ironcrest dependency review

Scope: passive knowledge, local semantic replay and durable authority composition.
Updated: October 21, 2026. This is a scoped
dependency review, not an independent source audit or parser safety proof.

## Rust syntax parser

The structural adapter directly pins syn 2.0.119 and quote 1.0.47, already present
in Cargo.lock through the existing build graph. This activates a parser at runtime;
prior build-only use does not establish hostile-input safety. No version upgrade
or additional third-party package is required for this adapter.

The [upstream parser repository](https://github.com/dtolnay/syn) is actively
maintained; [syn's documented syntax model](https://docs.rs/syn/2.0.119/syn/)
represents source syntax, not compiler name/type resolution. The pinned major 2
retains the already resolved parser version instead of adopting a new major for
this milestone. Revisit maintenance/security status when upgrading authority builds.

Enabled syn features: full, parsing and printing; default features disabled.
quote default features are disabled. Cargo feature unification may activate
features required elsewhere in the trusted build. Runtime transitives are
proc-macro2 1.0.107, quote 1.0.47 and unicode-ident 1.0.27. syn/quote/proc-macro2
use MIT OR Apache-2.0; unicode-ident uses Unicode-3.0. No license exception is added.
The lockfile and cargo-deny remain the authoritative resolved dependency inventory.

Inspection of pinned syn source identifies unsafe lifetime/cursor operations in
parse.rs and related token-buffer internals. The workspace's unsafe-code prohibition
does not audit or prohibit upstream unsafe. proc-macro2 also has compiler/platform
integration internals. No formal memory-safety claim is made. The adapter itself
contains no unsafe code and invokes no generated macro, compiler, build script,
target process, file/network discovery or database. Parsing owns no credentials.

Source bytes are already accepted but remain hostile parser input. Bounds cover
aggregate files/bytes, per-file bytes, conservative delimiter/punctuation complexity,
inline module traversal, graph nodes/edges, retained omissions and canonical output.
Preflight deliberately includes strings/comments and may reject valid source.
Rejected/unsupported structure leaves an explicit blind spot while exact inventory
remains available. Limit exhaustion cannot yield complete structure. These finite
bounds do not prove stack usage, parser correctness, global availability or absence
of dependency vulnerabilities. Source-process isolation for parsing is not implemented.

No generic graph library/database, AI SDK, SaaS client, shell runner or additional
service is introduced. Local replay reuses async-trait and existing serialization;
it adds no external package or runtime network/process dependency. The controlled
challenge uses Python/SQLite supplied by the existing authority-selected pinned
Python image. It executes only through the existing isolated runner, never as a
host-side knowledge/provider operation. Application/domain have no parser/provider SDK dependency;
the parser lives in archcert-knowledge behind the application extractor port.

Validation commands and actual outcomes are retained in the intentionally untracked
M6 working report and ignored target/m6 logs. cargo-deny must pass before completion.

## Integrated controller and issuance composition

The continuation adds no third-party package or version. Cargo.lock records only
new existing-workspace edges: control-plane to knowledge, controller to semantic
and its already resolved async-trait dependency. PostgreSQL, immutable objects,
TOML/canonical JSON, source loading and Ed25519 reuse the reviewed implementations.
No provider SDK, HTTP client, dynamic registry loader, generic graph/database,
process-based reviewer or external disclosure path was added.

Application owns orchestration, canonical evidence identities and private
reviewed-admission/accepted-challenge prerequisites. Control-plane and controller
remain trusted composition. New policy data uses the existing deterministic
command-evidence rule; certificate v1 retains its grammar, signature algorithm and
offline verifier. Manifest schema 2 is explicit and preserves the complete original
schema-1 deterministic manifest. See ADR 0044 for compatibility/security details.

Real rootless controlled challenges and source-to-certificate/crash regressions
exercise this composition. No Stoneward runner, worker, fencing, reconciliation or
cleanup implementation changed, so no native Linux requalification was required.
This does not establish a broader qualified execution platform or production keys.
