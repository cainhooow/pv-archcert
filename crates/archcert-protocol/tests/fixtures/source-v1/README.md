# Source submission v1 golden protocol fixture

Package: archcert.source.v1, using archcert.common.v1. Contract version: 1.
Source canonicalization schema: 1. Encoded artifact: submission.pb (356 bytes).
Semantic input: submission.textproto. Independently decoded representation:
decoded.textproto. Both text files use Google's diagnostic text format, not JSON.

This fixed fixture tests Protobuf wire compatibility. It does **not** define
cryptographic canonicalization, source identity, certificate signing, or a canonical
wire hash. Valid encodings with different field order can represent the same values.
The fixture uses Northgate's historical controlled source identity with synthetic
public operational IDs/fingerprint, not a claim of authentication or certification.

| Value | Recorded semantics |
| --- | --- |
| Submission | 00000000-0000-4000-8000-000000000006 |
| Project | 00000000-0000-4000-8000-000000000004 |
| Repository | archcert/northgate-fixture |
| Actor | 00000000-0000-4000-8000-000000000005 |
| Device fingerprint | 32 bytes, each 0x22 |
| Transport | SSH_PUBLIC_KEY |
| Submitted ref | refs/heads/fixture, mutable provenance only |
| Object algorithm | SHA1, 20-byte commit/tree |
| Commit | 67085b42fe02ff0832641629a31634338214be00 |
| Tree | c6365ec31116a8e66e83f91b058c472fe0064df7 |
| Source SHA-256 | 5241a6ce473582f26aa1c6ffab22f9082ecedc26cf11d09a6e641ad79cc5d8af |
| State | ACCEPTED, COMPLETE; zero unresolved dependencies, no resolution summary |
| Received/accepted UTC Unix seconds | 1760000000 / 1760000001 |

The fixture was encoded and decoded with protoc-bin-vendored 3.3.0's compiler
(libprotoc 36.2), independently of the Rust encoder. To reproduce from repository
root, select that exact package's host executable and bundled include directory
from the Cargo registry cache (see build.rs). With those paths in task-specific
PROTOC_FIXTURE_BIN and PROTOC_FIXTURE_INCLUDE shell variables:

```sh
"$PROTOC_FIXTURE_BIN" -Iproto -I"$PROTOC_FIXTURE_INCLUDE" \
  --encode=archcert.source.v1.SourceSubmission proto/archcert/source/v1/source.proto \
  < crates/archcert-protocol/tests/fixtures/source-v1/submission.textproto > /tmp/submission.pb
"$PROTOC_FIXTURE_BIN" -Iproto -I"$PROTOC_FIXTURE_INCLUDE" \
  --decode=archcert.source.v1.SourceSubmission proto/archcert/source/v1/source.proto \
  < /tmp/submission.pb > /tmp/decoded.textproto
cargo test -p archcert-protocol --test protobuf_compatibility --locked
```

Keep the committed artifact as an older supported producer's bytes. Tests decode
it into recorded typed semantics; encoder byte equality is not a canonicality
requirement. Intentional incompatible changes require a new package/fixture,
rather than overwriting this historical v1 artifact to conceal incompatibility.
