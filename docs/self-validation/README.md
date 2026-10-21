# Pre-Genesis source self-validation

A validator build may consume one exact ArchCert commit as ordinary untrusted
source. This is engineering self-validation by the same implementation/authority,
not independent certification, Genesis / Firstwarden, a production trust root or
an N-1 certification chain. See [ADR 0004](../adr/0004-self-certification-bootstrap.md)
and [roadmap reconciliation](../adr/0045-roadmap-reconciliation.md).

## Reproduce the bounded preparation probe

Build the workspace with `cargo build --workspace --locked`. Provision a dedicated
development PostgreSQL database and apply the existing migrations explicitly; see
[Ravenport operations](../architecture/RAVENPORT_OPERATIONS.md). Real SSH ingress
uses the same prerequisites as `scripts/test-northgate`. The probe temporarily
creates private SSH keys/token/configuration outside source and removes them on
exit. It does not generate a signing key or issue a certificate.

Commit reconciliation before selecting the full commit SHA. Use an unchanged
tracked source tree. Untracked files are reported separately and never enter the
exact Git-object source. Select authority inputs explicitly, outside target
execution. For the existing controlled profile, copy the reviewed
`docs/policy/CONTROLLED_AUTHORITY.toml` example into a private authority directory;
passing this copy is an operator choice, not repository policy discovery.
The Python recipe and settlement challenge are a controlled demonstration contract,
not a Rust project build/test profile. Do not replace missing checks with pass-only
commands or add settlement code to ArchCert to force a successful self-test.

```sh
ARCHCERT_DATABASE_URL=postgres://postgres@127.0.0.1:55432/DEDICATED_DATABASE \
  ./scripts/test-self-source \
  --source-repo /absolute/archcert \
  --commit FULL_RECONCILED_COMMIT_SHA \
  --authority-recipe /private/authority/controlled.toml \
  --profile python \
  --image 'python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f' \
  --docker /absolute/docker \
  --endpoint unix:///authority/rootless.sock \
  --output /absolute/archcert/target/pre-genesis/NEW_RUN
```

The output path must be new and beneath ignored `target/`. The probe uses real
Northgate authentication/quarantine, pushes only the explicit immutable commit,
checks commit/tree identity, independently inspects/materializes/verifies/destroys
the same source, and opens/prepares a normal durable controlled review session.
No target code runs on the host. No `target == archcert` branch or policy exception
exists. Authority selects no baseline, so impact handling must use full review.

This is deliberately a source/preparation probe. Runtime flags record the intended
authority environment; the probe does not launch execution. It creates no fabricated
CLEAR response. If preparation succeeds, the unavailable reviewer exercises the
normal fail-closed gate. It never bypasses review to reach a worker. Exit 2 and
`result.json` with INCONCLUSIVE mean the experiment did not establish eligibility;
this must not be summarized as a successful certification. Setup errors also exit
nonzero; inspect command exit codes and retained diagnostics.

Record exact commit, tree and independent snapshot SHA-256; source/materialization
status; policy/profile/registry/base-plan pins; every reached/unreached stage; and
whether any final plan, manifest, certificate or offline verification exists. Do
not invent digests for unreached stages. A runtime doctor result or a fixture run
is not execution of the self-test target. All runtime observations must identify
their actual scope.

## Current support boundary

The first reconciled-source experiment accepted and materialized the full ArchCert
repository but normal durable preparation failed before publishing review roles.
A separate diagnostic using the same source identity, project, approved bundles,
extractor and unchanged default limits produced 1,616,710 bytes of knowledge and
580,549 bytes of full-review impact. The semantic request embeds both complete
artifacts and has a hard 1,048,576-byte ceiling, so preparation rejects with
`KnowledgeError::LimitExceeded`, flattened to `invalid durable input` by current
controller composition. These diagnostic artifacts are not accepted durable review
evidence. The source was not modified and bounds were not raised.

The excerpt budgets also require honest completeness handling for large full
reviews. Even after request packaging is addressed, the only integrated challenge
registry/profile remains settlement-specific, and no general Rust authority
challenge or live semantic provider is provisioned. Increasing a byte limit or
manufacturing a fixture replay would not demonstrate self-hosted certification.
A future separately reviewed change should design bounded large-source review and
appropriate project-independent authority composition while preserving these gates.
It is not part of this experiment.

## Self-reference sanity checks

Use existing regressions to check the capability boundaries independently of the
full-source outcome. Retain commands/results under `target/`; distinguish synthetic
fixtures from the immutable self-test source.

| Concern | Existing executable checks |
| --- | --- |
| Documentation cannot assert its own verdict; policy-looking files have no authority | `archcert-knowledge` test `target_approval_policy_prompt_exception_provider_and_certificate_files_have_zero_authority`; `archcert-semantic` test `injection_text_and_fake_certification_are_data_only` |
| Repository semantic instructions cannot replace authority review | `archcert-semantic` tests `project_cannot_select_provider_or_challenge_authority` and `context_truncation_partial_response_and_explicit_blind_spot_never_continue` |
| Target cannot choose runtime socket | Strict configuration tests and runner endpoint tests; live OCI `host_files_source_mutation_and_runtime_socket_are_blocked` |
| Target cannot access signing material | Architecture capability guard; certificate `target_config_cannot_select_signer_key_algorithm_or_authority`; live OCI clean-environment canary and filesystem/socket checks (harmless canaries, no actual private keys exposed) |
| Target cannot rewrite accepted authority evidence | Live filesystem isolation and confirmed cleanup; storage `immutable_objects_reject_mismatch_truncation_substitution_and_cross_scope`; certificate mutation/recomputed-evaluation tests |
| Semantic CLEAR cannot replace deterministic proof | Semantic gate/typed proposal tests; opt-in `archcert-cli --test ironcrest_challenge` executes good and defective settlement fixtures under CONTINUE and rejects the defective final state |

These establish bounded software controls and observed fixture isolation, not
universal injection prevention, sandbox escape resistance, host-compromise safety
or independent correctness. A complete future eligible run must separately retain
its manifest/certificate public identities and offline verification. Any such
certificate remains a DEVELOPMENT / ENGINEERING SELF-VALIDATION ARTIFACT.

## Genesis comparison

A successful engineering self-test could demonstrate ordinary target consumption,
trust-boundary behavior and a deterministic result, plus development signing and
offline verification if eligible. An inconclusive preparation probe establishes
only its reached stages and fail-closed limitation. Neither establishes absence of
defects, independent implementation/policy/signing authority, first trusted root
establishment or N-1 continuity. Genesis / Firstwarden retains responsibility for
high-assurance bootstrap and independent trust establishment; it is not started.
