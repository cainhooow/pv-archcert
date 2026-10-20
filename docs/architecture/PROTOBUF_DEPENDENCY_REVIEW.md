# Northgate Protobuf dependency review

Reviewed October 20, 2026 against exact manifests, Cargo.lock, cargo info/tree,
registry source, licenses, and cargo-deny. This is an engineering inventory and
focused source inspection, not an independent audit of every dependency/binary.

| Addition | Version | Purpose and maintenance | Unsafe footprint and TCB impact |
| --- | --- | --- | --- |
| prost | 0.14.4, exact | Maintained tokio-rs/prost Rust Protobuf codec; Apache-2.0 | Runtime unsafe in optimized varint access and string buffer mutation. Adds wire-parser trust only where protocol decoding is invoked; bounded ingress decoder and semantic conversion remain required. |
| prost-types | 0.14.4, exact | Same maintained project; Google Timestamp and descriptor types; Apache-2.0 | No unsafe blocks found in its src tree. Uses prost. Timestamps are validated in protocol, never owned by domain/application or used as source identity. |
| prost-build | 0.14.4, exact | Same maintained project; converts descriptors into Rust during Cargo build; Apache-2.0 | No unsafe implementation found in its src tree. Build TCB includes descriptor parsing, name/type generation, process invocation, temporary files, graph and formatting dependencies. No runtime generation or authority policy. |
| prost-derive | 0.14.4, locked transitively | Same project; Message/Enumeration code generation; Apache-2.0 | No unsafe implementation found in its src tree. Proc-macro/build TCB; generated codecs invoke prost runtime. |
| protoc-bin-vendored | 3.3.0, exact | Maintained Stepan Koltsov rust-protoc-bin-vendored packaging; MIT wrapper; supplies Google compiler binaries and well-known .proto includes | Small Rust path-selector wrapper has no unsafe blocks found. Native protoc is a memory-unsafe C++ compiler binary, an explicit build supply-chain TCB dependency. Not executed on candidate sources. |
| protoc-bin-vendored-{linux-aarch_64,linux-ppcle_64,linux-s390_64,linux-x86_32,linux-x86_64,macos-aarch_64,macos-x86_64,win32} | 3.3.0 each, exact upstream pins | Platform-specific bundled compiler/includes; same packaging maintainer; Cargo metadata MIT | All platform packages are locked/checksummed; only the build host's compiler is invoked. The inspected macOS x86_64 executable reports libprotoc 36.2. Unsupported hosts fail, with no arbitrary local compiler fallback. |
| foldhash | 0.1.5, locked | Maintained Orson Peters hash implementation; Zlib; build-only through prost-build -> petgraph 0.8.3 -> hashbrown 0.15.5 | Unsafe global seed storage/Sync implementation exists. Build graph hashing only, not cryptographic hashing, source identity, or signing. Narrow exact-version license exception documented below. |

The direct exact versions and all transitive registry checksums live in Cargo.lock.
Newly selected build helpers include fixedbitset 0.5.7, hashbrown 0.15.5, heck 0.5.0,
multimap 0.10.1, petgraph 0.8.3, prettyplease 0.2.37, regex 1.13.1,
regex-automata 0.4.18, regex-syntax 0.8.11, and syn 2.0.119. Prost derive also
selects itertools 0.14.0/either 1.19.0. Existing bytes 1.12.1, anyhow, proc-macro2,
quote, tempfile, serde, thiserror, and hex are reused. Additional dependency versions
and paths are reproducible with `cargo tree -p archcert-protocol --locked`.
Upstream transitive libraries may contain unsafe code; workspace unsafe_code=forbid
does not audit or forbid third-party unsafe. No custom unsafe code is introduced.

foldhash's Zlib license permits commercial use, modification, and redistribution
subject to origin attribution, marking altered sources, and retaining its notice.
Its locked source LICENSE was inspected. deny.toml allows only foldhash =0.1.5
under a narrow Zlib exception, like the separate existing zlib-rs exception; it does
not globally allow new licenses or waive advisories/source checks. The initial
cargo-deny run correctly rejected this new license until review. Duplicate-version
warnings remain visible; no blanket duplicate suppression is added.

Build.rs supplies the exact vendored executable, a fixed list of two trusted owned
schemas, and bundled includes; it rejects ambient PROTOC_INCLUDE and configures no
plugins. Native compiler execution and generated authority code require trusted
ArchCert checkout/dependency supply chain. Candidate ingress never triggers compiler
execution or influences its inputs. No tonic, database, scheduler, remote worker,
production RPC, signer service, JSON mapping library, or cryptographic algorithm
was added. The protocol crate has no policy/certificate/crypto adapter edge.

The new gateway export activates the codec for source inspection only. SSH receive,
quarantine, pack validation, accepted source artifacts, canonical hashing,
resolution credential destruction, materialization, OCI execution, policy,
certificate signing, and offline verification retain their existing boundaries.

The bundled Google timestamp.proto header was also inspected: its Google BSD-style
three-clause redistribution notice covers the included well-known schema source;
the packaging crate's MIT metadata is not a substitute for upstream notices.
Retain upstream compiler/schema notices when redistributing those artifacts.

Primary upstream references:

- [prost source and maintenance](https://github.com/tokio-rs/prost)
- [prost 0.14.4 API](https://docs.rs/prost/0.14.4/prost/)
- [prost-build explicit compiler API](https://docs.rs/prost-build/0.14.4/prost_build/struct.Config.html#method.protoc_executable)
- [vendored compiler packaging](https://github.com/stepancheg/rust-protoc-bin-vendored)
- [foldhash upstream](https://github.com/orlp/foldhash)

Final cargo-deny results and exact executed gates are in
[the focused completion report](../MILESTONE_5_PROTOBUF_REPORT.md).
