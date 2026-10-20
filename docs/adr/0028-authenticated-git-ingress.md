# ADR-0028: Authenticated Git ingress without certification authority

Status: Accepted for Northgate, October 20, 2026.

Use the maintained operator-provisioned OpenSSH server for public-key possession
verification and restricted authorized_keys commands. Do not embed SSH crypto.
Each enabled public-key fingerprint maps to a GitActorId and explicit authority
ProjectId/RepositoryId grants. DeviceKeyId is SHA-256 of the public SSH wire-key
blob, compatible with a future device registry. Actor identity is a UUID, not a
login/display name. Disabled mappings reject even after SSH authentication.

The fixed forced command supplies the fingerprint; SSH_ORIGINAL_COMMAND is parsed
as one exact `git-receive-pack 'authority/route.git'` request. No request text is
passed to a shell. The route selects an existing grant; it is never a storage
path or an implicit authorization. Calling the executable directly is authority
access, not an alternate network authentication mechanism.

The Git account must have only authority-owned restricted keys, public-key-only
authentication, no user environment/rc/PTY, no subsystem, tunnel, agent, TCP/Unix
socket or X11 forwarding. `restrict` plus `DisableForwarding yes`, `PermitUserRC no`
and the fixed command deny shell/SCP/SFTP/arbitrary commands. The development
fixture binds only loopback, uses temporary harness client/host keys outside
ArchCert source storage, pins the host key, and removes all private test material.
Deployment uses a dedicated OS identity and separately managed OpenSSH host keys.
ArchCert stores public identity/configuration only; it never stores private client
SSH keys. A compromised SSH host is not cryptographically attested.

archcert-gateway and its standalone executable depend only inward on source,
application/domain and transport/storage infrastructure. Guards reject direct and
transitive runner/materializer/policy/evidence/certificate/signing dependencies.
The CLI separately composes certification. Push success means source received or
accepted, never a policy result. No private certificate key is present in ingress.

One nonblocking store lease admits one session. Pack/object/source/decode budgets,
finite retained attempts, stdin polling deadlines, bounded subprocess output and
OpenSSH MaxAuthTries/MaxStartups/LoginGraceTime prevent unlimited ingress. These
are development admission controls, not a distributed rate-limiting service.

See [OpenSSH server configuration](https://man.openbsd.org/sshd_config.5) and
[authorized_keys restrictions](https://man.openbsd.org/sshd.8).
