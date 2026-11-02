# External Glassmere provisioning

Use `scripts/glassmere-provision` from the trusted operator environment. Read
[ADR 0052](../adr/0052-glassmere-provisioning-audit.md) for the audit/recovery
boundary. This tool provisions panel access only. It does not grant certification,
runtime, signing, repository, policy or governance authority.

Create a private owned directory outside target source and workspaces. Supply its
canonical absolute path; resolve symlinked ancestors before invocation. The
directory must have mode 0700. The examples below use an operator-selected
`/private/authority/glassmere` directory that must already exist.

```sh
scripts/glassmere-provision \
  --config /private/authority/glassmere/panel.json \
  --operator provisioner \
  bootstrap --principal initial-admin \
  --origin https://glassmere.internal \
  --project 10000000-0000-4000-8000-000000000001 \
  --credential-file /private/authority/glassmere/initial-access.json
```

The UUID is an illustrative explicit scope, not a default project. Select actual
authorized projects. Bootstrap refuses an existing configuration. It generates
one 256-bit random credential, stores its hash in panel configuration and writes
the credential only to the selected new mode-0600 delivery file. Deliver it
privately to the named principal. Never commit or copy it into source, browser
storage, logs, arguments or environment variables. The tool prints no credential.

Production bootstrap rejects HTTP origins. A local preview can explicitly add
`--development-http --demonstration-data` and select an exact origin such as
`http://127.0.0.1:8090`. Preview access is still authenticated and private. Stop
the preview and revoke or rotate its credential when its access is no longer
needed. Process restart invalidates sessions but does not revoke a credential.

All subsequent commands use the same `--config` and non-secret `--operator`:

| Action | Required arguments | Effect |
| --- | --- | --- |
| `add` | `--principal`, `--role`, repeated `--project`, new `--credential-file` | Create a new explicit principal and random credential |
| `set-grant` | `--principal`, `--role`, repeated `--project` | Replace the exact role/project grant; omitting projects grants no project access |
| `rotate` | `--principal`, new `--credential-file` | Replace the credential hash; old credentials and sessions stop authenticating |
| `revoke` | `--principal` | Remove the principal; existing sessions stop authenticating |

Roles are `VIEWER`, `OPERATOR`, `REVIEWER` and `ADMINISTRATOR`. None implies
cross-project or signing authority. The tool refuses duplicate principal names,
credential-file overwrite and revocation of the last principal. Provision a
replacement before removing that principal. Grant changes take effect on the next
request; the panel rechecks its session's exact principal revision.

Retain `panel.json.provisioning.jsonl` and `panel.json.provisioning.lock` beside
configuration. The panel's own operational audit uses the separate
`panel-audit.jsonl`. Provisioning records contain the operator, action, principal,
public old/new grants, configuration digests and durable local sequence. They
contain no credential. Archive private audit under operator-controlled procedures
before its 16-MiB ceiling; this tool provides no audit deletion/rotation command.

A successful operation ends in COMMITTED. If publication was interrupted, the next
operation first appends RECOVERED_COMMIT or RECOVERED_ABORT after comparing exact
configuration digests. A delivery file alone never proves an active credential.
Keep it private and inspect the journal before retrying with a new delivery path.
Unknown configuration identity, partial audit, out-of-band edits, public file
permissions and capacity exhaustion fail closed and require investigation. Do not
delete the journal or alter digests to bypass recovery.

Run `python3 scripts/test-glassmere-provisioning` for the file/locking regression.
The Rust authentication tests separately establish session revision invalidation.
These are development engineering checks, not production IAM or independent
certification. M9 remains INCOMPLETE until its separate closure criteria pass.
