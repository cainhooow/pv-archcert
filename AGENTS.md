# ArchCert engineering requirements

All repository content must use US English. Preserve the inward architecture:
application/domain own business models and ports; adapters own HTTP, Protobuf,
PostgreSQL, object storage, OCI and signing integrations. Read the current
architecture snapshot, relevant ADRs and threat models before changing boundaries.

## Git hygiene for every milestone

One coherent, independently understandable engineering change is one commit.
After each unit, inspect the diff, run its relevant focused checks, explicitly
stage its files and commit. Do not accumulate a milestone into one final commit
or commit every save. Use concise US English messages such as
`feat(storage): add PostgreSQL job repository`.

Before each commit run `git status --short` and `git diff`. Stage explicit file
paths; do not use `git add .` or `git add -A` as the normal workflow. Then run
`git diff --cached --name-status`, `git diff --cached --stat` and
`git diff --cached`. Inspect for unrelated files, secrets, private keys, tokens,
credentials, transient logs/runtime output and unnecessary working reports.
After committing run `git status --short`; report intentionally untracked files.
Never commit files just to obtain a clean working tree.

Commit source, manifests/lockfiles, schemas, migrations, policy, tests, required
scripts/configuration examples, CI and architecture guards. Commit authoritative
ADRs, architecture, threat-model/security/policy docs and current README/developer
requirements with the same logical implementation change. Prefer durable ADRs
with context, decision, security implications, alternatives and consequences.

New docs/MILESTONE_*_BASELINE.md, *_REPORT.md and *_PROTOBUF_REPORT.md are
engineering working records and remain untracked unless explicitly requested.
Do not delete historical tracked reports. Do not blanket-ignore milestone docs
without reviewing tracked history. Classify preexisting untracked files before
implementation: source/protocol/test/architecture artifacts belong in Git;
working records and local demonstration output normally do not.

Never commit private signing/SSH keys, tokens, passwords, object-store credentials,
.env secrets, local runtime snapshots/sockets, temporary source stores, logs or
ordinary generated execution output. Deterministic regression fixtures are an
exception only when their purpose and reproducibility are documented before
committing. Retained development certificates are not automatically fixtures.

Each final task response must include COMMITS CREATED (SHA, message, purpose)
and INTENTIONALLY UNTRACKED FILES with an explanation for each category.

## Validation

Run focused checks per commit. At milestone completion run formatting, locked
workspace/all-target/all-feature check, Clippy with warnings denied, workspace
tests, rustdoc with warnings denied, cargo-deny and scripts/check-architecture.
Run scripts/test-ravenport against real PostgreSQL for database concurrency and
recovery changes; mocks do not establish locking semantics. Object, protocol and
Northgate regressions remain required. Changes affecting execution need live OCI
regression under an independently provisioned rootless daemon and pinned image.
Keep execution evidence under ignored target/ and report commands actually run.
