# Private readiness request qualification

This development harness exercises [ADR 0061](../adr/0061-private-readiness-request-evaluation.md)
and [ADR 0062](../adr/0062-readiness-request-entrypoint.md) through actual controller
processes, real PostgreSQL and the shared selected-key M6 verifier. It does not add
a browser readiness action or execute a new release build.

Build the selected source:

```sh
cargo build -p archcert-controller --locked
cargo build -p archcert-control-plane --example glassmere-command-fixture --locked
```

Provision a private owned mode-0600 selection JSON outside version control:

```json
{
  "project": "<exact historical project UUID>",
  "invocation": "<exact 64-character historical invocation digest>",
  "query_config": "/private/selected-public-trust-and-recipes.json"
}
```

The selected development database's public schema must retain that exact complete
M6 invocation and its original registered evidence. The explicitly selected query
configuration must trust its source and release public keys and exact recipe. Its
private artifact root must retain original bytes. No private signing key is needed.
A nonexistent, invalid or denied baseline cannot qualify the positive case.

Set `ARCHCERT_TEST_DATABASE_URL` privately to a disposable development administrator
connection to that database. Set `ARCHCERT_TEST_READINESS_IMPORT` to the private
selection path. Run:

```sh
GLASSMERE_READINESS_OUTPUT=target/readiness-selected-run \
  ./scripts/test-glassmere-readiness
```

The output path must be new and under this repository's ignored `target/`. The
harness creates a new schema/SELECT-only login through the existing command
fixture and imports only the explicitly selected historical release. Original
authority rows and artifact bytes remain untouched. Available bytes are rehashed
and create-only copied into a separate private store. Historical non-expiring
claims remain unchanged; the import audit is explicitly development fixture data.
This is not authority database recovery or new certificate/permit issuance.

The separate controller request credential is random, scoped only to readiness,
and delivered through an owned mode-0600 file without a newline. The CLI accepts
identifiers and an expected authority-context digest; it accepts no actor, recipe,
execution selector or posted readiness fact. A request can be inspected/retried
with the same command and key. Schema-2 receipts explicitly say
`observation_freshness: HISTORICAL_OBSERVATION`.

The harness checks original-key replay, explicit new-key observation, exact source
and artifact/permit bindings, project/object/context/private-file denials, artifact
loss, unavailable observation capability and actual SIGKILL after claim/publication.
It verifies exact journal/audit counts, no new job/attempt/certificate, and unchanged
imported release/admission/claim/evidence state. The original allowed receipt must
remain labeled history during outage; a fresh question must deny readiness.

Only task-owned dispatcher children are killed. Database schemas/roles, private
configuration, credentials, copied evidence and logs remain under the selected
private output for inspection. Retained names are in `resources.json`; resource
retirement requires explicit selection of that test schema/role on the development
database. The harness exposes no authority deletion or repair endpoint.

`results.json` records source HEAD/diff identity, executable/script digests and
actual outcomes. A working-tree run is not exact committed-source validation.
Executable overrides are `ARCHCERT_TEST_CONTROLLER_BINARY` and
`ARCHCERT_TEST_COMMAND_FIXTURE_BINARY`; separately build their selected source.
This scope establishes no new execution containment, native qualification,
production signer custody or independent certification. Full M9 readiness/security/
large-history/transport/browser qualification and final gates remain separate.

## Browser question qualification

`scripts/test-glassmere-readiness-browser` additionally exercises
[ADR 0064](../adr/0064-glassmere-readiness-browser-request.md) through real Chrome,
panel, daemon, dispatcher, SELECT-only observation and retained M6 bytes. Build the
same selected source's fixture/controller plus the daemon and optimized panel:

```sh
cargo build -p archcert-controller -p archcertd --locked
cargo build -p archcert-control-plane --example glassmere-command-fixture --locked
cargo build --release -p archcert-panel --locked
```

Use the same explicit private `ARCHCERT_TEST_DATABASE_URL` and
`ARCHCERT_TEST_READINESS_IMPORT` selection described above. Provision the existing
Playwright 1.56.1 tooling and a trusted Chrome executable separately; neither is an
application dependency. Set an absolute `GLASSMERE_CHROME_EXECUTABLE`, or use the
installed Chrome channel. Run:

```sh
GLASSMERE_READINESS_BROWSER_OUTPUT=target/readiness-browser-selected-run \
  node scripts/test-glassmere-readiness-browser
```

The output path must be new, canonical and under ignored target/. The harness
creates its own schema/SELECT-only login and copied artifact store, then starts
task-owned loopback panel/daemon processes on ephemeral ports. The independently
running preview is unchanged. Database URLs, panel/backend credentials, private
configuration, copied bytes and logs stay in this private output. The same four
executable override variables as the workflow browser harness are supported.

One externally provisioned principal is assigned Viewer, Reviewer, Operator and
Administrator in separate audited grant generations. This qualifies each role's
permission while preserving one exact original release actor; it does not assert
independent operator identities or governance separation. Viewer/Reviewer can read
live readiness but cannot submit a question. Operator and Administrator additionally
need the separate backend credential/operation grant. Administrator still cannot
sign or administer users through a browser. Revocation/restoration must invalidate
the older session.

The browser exercises rapid double-click, same-key HTTP retry, receipt refresh,
a new second-tab key, forged facts, CSRF, missing backend credentials and artifact
loss/recovery. Readiness deliberately creates a fresh question for another explicit
key, while creating no certification or build workflow. Historical receipts must
have no live-confirmation attributes. During artifact loss the past allowed
receipt remains explicitly historical, and both the live query and new question
deny readiness. Restoring bytes must not rewrite the retained denial.

Initial page evaluation and pageshow each request freshness confirmation. The
harness waits for the existing UI confirmation before adding a manual API request,
preserving the production two-verification bound. Immediate additional requests
may correctly receive 503; qualification never raises the bound or retries an
assertion until it passes. Retained response timing and live-API observations make
this scheduling boundary inspectable.

Require exactly four questions, four key bindings and four applied evaluations,
with original fixture jobs/attempts, zero certificates and unchanged imported
release/admission/claim/evidence state. Retain historical source and all executable/
script/source-diff identities. An untracked harness or working-tree run is not an
exact committed-source qualification. Failed runs remain separate outputs.
The final result covers this bounded integration, not the complete 22-case
readiness corpus, active target execution, native containment or M9 closure.

> This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.
