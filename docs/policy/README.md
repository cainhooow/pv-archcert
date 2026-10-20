# Development policy evaluation

**UNSIGNED POLICY EVALUATION — NOT A CERTIFICATE**

`archcert evaluate` runs the established exact-source/plan/rootless-execution path,
then interprets typed observations. It does not call a signer or issue a certificate.
The single embedded authority profile is `archcert-development-v1`, version 1.0.0,
SHA-256 `e128e7a0cfeaf0f11917a35cc655b0e9fe6ea96dcf550bea5d25898ea8f7b9ae`.
Its seven mandatory properties require complete/exact source, established sandbox
and denied network, plus explicitly selected typecheck/test/build commands.
It is a development baseline, not a production assurance standard.

Project `--config` requests cannot select policy, change requirements/severity,
supply authority provenance or declare non-applicability. `--authority-config` is
an explicit trusted operator input using the existing bounded command grammar;
the operator supplies it separately from target requests. Its commands get
AuthorityRequired provenance before project steps compose. Never populate this
argument from a target's claimed authority file. The CLI is not a remote
multi-tenant authentication boundary. Production bundles/command catalogs must
live in separate or access-controlled authority storage. Target source snapshots
are copied into isolated source-only layers and cannot overwrite authority files.

Run `cargo run -p archcert-cli -- evaluate --help`. It uses `run` source/runtime
arguments, with optional `--authority-config docs/policy/CONTROLLED_AUTHORITY.toml`
and additional `--config FILE`. Direct argv still has project-requested provenance.
The operator owns runtime/profile/image flags. No policy downgrade, waiver or
signing flag exists. Exit 0 means execution/cleanup and evaluation completed;
read JSON `evaluation.eligibility` for the policy result. A nonzero target/runtime
can emit its complete evaluation and then return exit 1.

Retained results from actual development invocations:

| Report | Test property | Eligibility |
| --- | --- | --- |
| [Controlled success](CONTROLLED_PROVEN.json) | PROVEN | ELIGIBLE_FOR_CERTIFICATION |
| [Controlled genuine exit 1](CONTROLLED_FAILED.json) | FAILED | NOT_ELIGIBLE |
| [Controlled unavailable runtime client](CONTROLLED_INCONCLUSIVE.json) | INCONCLUSIVE | NOT_ELIGIBLE (other required isolation facts missing) |
| [Bottle version command](BOTTLE_NOT_PROVEN.json) | NOT_PROVEN | NOT_ELIGIBLE |

The successful fixture uses commit `67085b42fe02ff0832641629a31634338214be00`, tree
`c6365ec31116a8e66e83f91b058c472fe0064df7`, snapshot SHA-256
`5241a6ce473582f26aa1c6ffab22f9082ecedc26cf11d09a6e641ad79cc5d8af`.
The failed-test commit is `44d8bba2c0d305b4aa2870c6caafa74dbbe77fd1`, tree
`feb95c6e8174316a51197c83cb8d739940c2831f`, snapshot SHA-256
`81597c168e33b10fd28ca51aedac8612e9b65ab20f608d87049de9061abf8bf5`.
The retained source [checks.py](../../tests/fixtures/policy-target/checks.py) is a
tiny controlled fixture. Its typecheck checks annotations and a fixture result
type; it is not a general Python type checker. Its build compiles that source to
bounded `/work`; its unittest checks addition. The failure commit changes addition
to return an incorrect integer. It prints TESTS PASSED before unittest fails,
demonstrating stdout has no policy authority. No coverage/absence-of-defects or
artifact-security claim follows from these property names or this fixture.

Bottle remains exactly commit `8ec5fe29420d14998c0d86885083983eaea8b839`, tree
`e0851c0b9e8f8c96e3d3bf2a1eb6bc07d9ed1667`, snapshot SHA-256
`e3f098f88ca986831b531f2f055c76513ad55360785d81f5f43c34a4d98c92b0`.
Only `python3 /source/bottle.py --version` ran. The four source/isolation properties
are PROVEN; TYPECHECK_COMPLETES, TEST_SUITE_COMPLETES and BUILD_COMPLETES are
NOT_PROVEN. No policy was weakened to make Bottle eligible.

Each report retains exact source evidence, whole plan representation and digest,
expected controller execution IDs, observations consumed, execution/cleanup
payloads, policy identity, property selectors/references, findings and eligibility.
Policy result references resolve to typed observation payload digests; tests check
these links. Timestamps/UUIDs are operational records, not signatures. The reports
remain editable unsigned development artifacts, not authenticated evidence storage.

Reproduce after separately provisioning the existing rootless environment and
pinned Python image; source fixture preparation uses system Git, with no target
Python executed on the host:

```bash
cargo build -p archcert-cli --locked
ARCHCERT_TEST_DOCKER=/absolute/trusted/docker \
ARCHCERT_TEST_ENDPOINT=unix:///absolute/rootless.sock \
ARCHCERT_TEST_IMAGE=python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
./scripts/demo-policy-evaluation
```

The script uses a fresh temporary repository under ignored target/m4a, deterministic
Git metadata, the passing/failing exact commits, and the existing supported loose
Bottle objects at target/m3-bottle/.git. It fails explicitly if Bottle is absent;
it does not clone/fetch/convert packs. It deliberately uses `/usr/bin/false` as an
unavailable runtime client for the infrastructure case. Real passing/failing
commands run in rootless OCI; the infrastructure case never starts a target.
It writes only retained development reports under docs/policy and temporary
fixture data; source/sandbox cleanup is checked. See ADRs
[0022](../adr/0022-deterministic-policy-authority-and-verdicts.md),
[0023](../adr/0023-canonical-policy-identity.md),
[0024](../adr/0024-unsigned-eligibility-and-findings.md) and the
[threat model](../threat-model/POLICY_EVALUATION.md).
