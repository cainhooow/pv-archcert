# ADR-0020: Strict project requests and authority-owned execution profiles

Status: Accepted for Milestone 3.5; refines ADR-0003 and the M3 CLI catalog.

ProjectConfiguration is a validated, bounded request parsed through one production
parser in application. Schema 1 is explicit; unknown schema/fields, invalid names,
duplicate step names, malformed literal commands/cwd/categories and oversized input
reject. Private wire types cannot construct AuthorityConfiguration or
RuntimeConfiguration. The complete supported contract is config/archcert.toml.example,
which default CI parses through that same parser. No legacy fields remain.

AuthorityConfiguration owns an in-memory registry of AuthorityExecutionProfile and
mandatory steps. Profiles bind ID, approved executable set, immutable OCI image,
default/maximum limits, denied network and fixed sandbox environment. Constructors
are trusted code, not project deserialization. Every limit selection checks every
ceiling. Development defaults equal maxima, so project input cannot raise them;
project resource requests are unsupported and reject rather than being ignored.

RuntimeConfiguration holds operator Docker path/endpoint/workspace root. DockerRuntime
validates runtime settings and creates a private temporary client configuration.
The project supplies none of these fields. Runtime temporary files use the existing
trusted tempfile facility; no project-selected temporary path is accepted.

Development operator CLI --profile/--image provisions a single registry entry using
the static executable catalog. This interface is for a trusted operator; giving a
project control of the CLI process/arguments would give it operator authority.
Project TOML can only select an already-provisioned profile. Unknown profiles reject
at authority resolution. config-check checks against the same development catalog
without selecting an image/runtime; it does not establish that an image is available.

Version-suggesting node22 is removed; catalog IDs are python, rust and node.
They identify approved executable families, not installed toolchain proof.
ExecutionEvidence explicitly records ToolchainObservation::NotObserved. No probes
or claims of toolchain/version attestation are introduced. Arbitrary mismatched
operator image provisioning is still possible and fails operationally if the binary
is absent; it never silently becomes a proven version. Image approval remains an
operator supply-chain responsibility.

Moving TOML parsing from CLI to application keeps a single executable contract.
It changes package placement, not the parser dependency/version in the active CLI
trust path. No database, dynamic plugins, network-enabled profile or policy verdict
is added.
