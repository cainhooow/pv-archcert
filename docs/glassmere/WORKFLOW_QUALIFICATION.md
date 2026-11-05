# Browser workflow qualification

`scripts/test-glassmere-workflows` exercises the three job operations from
[ADR 0059](../adr/0059-glassmere-browser-command-broker.md) through a real browser,
panel, daemon, command dispatcher and PostgreSQL. It is development test tooling;
Node and Playwright are not application runtime dependencies.

Build the selected source and separately provision the documented test browser:

```sh
cargo build --release -p archcert-panel --locked
cargo build -p archcertd -p archcert-controller --locked
cargo build -p archcert-control-plane --example glassmere-command-fixture --locked
node scripts/test-glassmere-workflows
```

Set `ARCHCERT_TEST_DATABASE_URL` privately to an explicitly selected disposable
development PostgreSQL administrator connection. The tool creates one new isolated
schema and a new SELECT-only login. It changes no global administrator search path
and never reuses existing authority rows. A PostgreSQL host with coherent time is
required. Both exported connection URLs must independently resolve the intended
schema and its exact initial job count before any service starts.

`GLASSMERE_WORKFLOW_OUTPUT` selects a new canonical directory under `target/`;
the default is `target/glassmere-workflows`. Existing output is refused so failed
runs are retained. The directory is private. Credentials, database URLs, source
fixtures, private service configuration and logs must remain there and must never
be committed. Browser credentials are random and provisioned through the audited
external tool. Backend command credentials are separate for each acting principal
and use distinct authority actors; browser roles grant no backend permissions.

The tool uses the separately installed Playwright 1.56.1. It accepts an explicitly
provisioned absolute `GLASSMERE_CHROME_EXECUTABLE`, or the installed Chrome channel.
The four selected executable paths can be supplied through
`ARCHCERT_TEST_PANEL_BINARY`, `ARCHCERT_TEST_DAEMON_BINARY`,
`ARCHCERT_TEST_CONTROLLER_BINARY` and `ARCHCERT_TEST_COMMAND_FIXTURE_BINARY`.
Defaults refer to the preceding builds in the ordinary workspace target directory.
Select those trusted tools outside target-controlled project inputs.

The harness starts only owned loopback panel/daemon processes on selected ephemeral
ports. The panel receives the SELECT-only URL; the daemon and trusted test
dispatcher receive the isolated authority URL. Neither receives runtime or signing
configuration. Dispatcher invocations are fixed trusted test-harness operations,
not browser commands. The harness stops its service children on ordinary success
or failure and retains their logs. The separately running development preview is
not restarted, modified or stopped by this test.

## Fixture and assertions

The Rust fixture example provisions two accepted source metadata fixtures and four
initial jobs through existing application/repository interfaces. Ingress metadata
is a test fixture; it does not establish actual SSH acquisition. Two jobs have
ordinary five-second worker claims that were never started. They have no target
process, runtime resource or execution result. Recovery waits for database-time
expiry without changing clocks, leases, timeout semantics or attempt limits.
Two other jobs remain queued for bounded cancellation.

The browser journey checks Viewer/Reviewer mutation denial and Operator/Administrator
requests for certification, queued cancellation and exact-attempt recovery. Each
permitted operation exercises two rapid browser form clicks, repeated HTTP POSTs,
the original key, a distinct second-tab key and receipt refresh. Two concurrent
real dispatcher processes must produce one applied request and one idle response.
The first accepted request also survives panel/daemon loss and independent
dispatch; restarted presentation refuses the old session. Removing backend
credential availability must deny submission without duplicating durable work.
An audited role downgrade/restoration cannot revive the old browser session.

Final PostgreSQL counts require exactly six command records, twelve key aliases,
six jobs, two original attempts and zero certificates. Domain and command audit
counts must show each creation, cancellation and recovery once. An APPLIED receipt
must retain the explanation that it is not a certificate or Release Permit.

`results.json` retains source HEAD, tracked-diff identity, test-source identities,
executable digests, browser/tool versions and actual check outcomes. A working-tree
test is not exact committed-source validation; rebuild and rerun after the final
commit when claiming that scope. Failures and partial setup remain separate runs.
Retained schema/role names are in `resources.json`; archive evidence and stop any
interrupted owned processes before explicitly retiring those resources on the
selected development database. The tool provides no authority-data deletion API.

This scope establishes no target execution, native containment, deterministic
policy result, certificate issuance, release workflow or production IAM assurance.
Full readiness/security/large-history/outage corpora and milestone gates remain
separate M9 requirements. M10, M11 and Genesis remain NOT STARTED.

> This is engineering self-validation under a shared implementation/authority context. It is not independent certification and does not replace Genesis / Firstwarden.
