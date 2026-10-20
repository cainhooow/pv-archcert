# Eldermark development certificates

**DEVELOPMENT CERTIFICATE / NOT PRODUCTION AUTHORITY.** Engineering self-validation,
not independent certification or a production trust anchor. No semantic AI takes
part in the authoritative issuance pipeline.

The retained controlled case uses the same exact Veridian passing fixture, commit
67085b42fe02ff0832641629a31634338214be00, tree
c6365ec31116a8e66e83f91b058c472fe0064df7, source SHA-256
5241a6ce473582f26aa1c6ffab22f9082ecedc26cf11d09a6e641ad79cc5d8af.
All seven pinned development policy requirements are PROVEN. Typecheck/test/build
mean completion of those selected commands, not coverage or absence of defects.

```bash
cargo run -p archcert-cli -- verify \
  docs/certificates/development/controlled/certificate.json \
  --public-key docs/certificates/development/controlled/public-key.hex
```

The public key is explicit: reviewing and trusting an authority key is a separate
administrative decision. Copy the certificate and public key to any directory;
verification needs no repository, runtime, workspace, network, database or private
key. A different selected key fails without fallback. Modified signature and
wrong-key results are retained beside the controlled and Bottle bundles.

Certificate scope is EXACT_SOURCE, never a branch/latest/future source or artifact.
NO EXPIRATION SEMANTICS YET. Revocation is NOT IMPLEMENTED. Signature validity
authenticates the signed claims under the selected key; it does not say software
is secure in every respect.

The controlled directory contains the signed envelope, exact canonical signing
bytes, detached signature, public hex/PEM, deterministic manifest, detailed canonical
evidence bundle, development execution report, ArchCert offline verification and
OpenSSL verification. The manifest binds the canonical bundle by SHA-256; observations,
findings, execution records and bounded log prefixes remain outside the certificate.
The unsigned evidence.json is additional diagnostic presentation, not a certificate.

Bottle's exact version-command scenario remains NOT_ELIGIBLE: typecheck/test/build
are NOT_PROVEN. Its directory retains execution/evaluation evidence and rejection,
with no certificate/signature. The demonstration deletes its temporary private
key before Bottle to prove rejection precedes key loading; a counting-signer test
separately proves signer invocation remains zero.

Reproduce on the already provisioned rootless environment:

```bash
cargo build -p archcert-cli --locked
ARCHCERT_TEST_DOCKER=/absolute/path/docker \
ARCHCERT_TEST_ENDPOINT=unix:///absolute/path/rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
./scripts/demo-certificate-issuance
```

The script requires system Git to construct the fixture, the existing externally
prepared target/m3-bottle loose objects, OpenSSL with Ed25519 support for independent
signature reproduction, and the existing rootless runtime. No external tool is a
runtime dependency of offline verification. It refuses to overwrite existing retained
evidence. Move old output aside explicitly before repeating; each run generates a
new development key and new execution identities/timestamp, so certificate instances
differ. Fixed deterministic vectors do not read clocks or generate keys at test time.
Private keys exist only in a private temporary authority directory outside targets
and evidence; the script destroys that directory and retains no secret key.
