# Native Linux rootless runner qualification

Status: **NOT YET QUALIFIED**. M3 and M3.5 development observations use a macOS
controller and Colima Linux VM. A Linux guest is not native deployment qualification.
Run this checklist on the actual dedicated Linux controller/runner configuration;
retain commands, versions, raw bounded evidence and deviations with the report.

- [ ] Record host distribution, kernel build/config/security updates, architecture,
      filesystem/mount options, Docker client path/version, server/runtime versions,
      image repository digest, ArchCert producer version and deployment configuration.
      These are observed identities, not cryptographic executable attestation.
- [ ] Record cgroup v2 mount and systemd user delegation for memory, swap, CPU and
      PIDs. Verify rootless preflight accepts; independently inspect effective target
      cgroup memory.max, memory.swap.max, cpu.max and pids.max values.
- [ ] Use a dedicated unprivileged rootless daemon/worker account with subordinate
      UID/GID ranges and user namespaces; record daemon user, uid_map/gid_map,
      unprivileged-userns policy and rootlesskit/runtime versions. Rootful daemon
      must reject, with no override/fallback. No signing/control-plane secrets.
- [ ] Confirm builtin seccomp availability and live Seccomp/NoNewPrivs state;
      target UID:GID 10001:10001, capabilities zero, private PID/cgroup namespaces,
      no host IPC/userns/network, no added devices or runtime socket.
- [ ] Use a trusted local byte-preserving filesystem/private mode-0700 root, inspect
      inherited ACLs and mount behavior. Run materialization tests for symlinks,
      inode swaps/hardlinks, directory substitution, parent rename, read-only modes,
      retained-writer mutation, identity roundtrip and all budgets.
- [ ] Independently confirm stopped target source identity, read-only root/source,
      no host bind mounts, bounded private HOME/tmp/work/output and no unexpected
      volumes. Confirm runtime-managed proc/dev/etc behavior matches assumptions.
- [ ] Provision harmless host-only file, environment/credential and HTTP canaries.
      Verify each is observable by the trusted harness outside isolation, absent
      from the image and inaccessible from targets. Retain no actual secrets.
- [ ] Confirm network none: only loopback, DNS/TCP/HTTP/metadata/gateway denial,
      including numeric no-route assertions independent of public Internet state.
- [ ] Exercise actual OOM, PID exhaustion, CPU ceilings, tmpfs ENOSPC, timeouts,
      ignored signals, detached children and parent-exit descendants. Confirm whole
      sandbox termination, bounded binary output/digests/truncation and deadlines.
- [ ] Run every default gate and `./scripts/check-architecture`, then run all 11
      opt-in `./scripts/test-live-oci` tests using explicit endpoint/pinned image.
      No ignored test counts as exercised. Capture runtime identity with a CLI run.
- [ ] Independently query job-labelled containers/images after success, nonzero
      exits and injected failures; require none remain. Check source workspace
      deletion and unchanged accepted bytes. Exercise disconnected-daemon failure
      reporting. Document crash/orphan recovery as unimplemented, never successful.
- [ ] Execute the documented Bottle request on the same native Linux deployment,
      recording exact commit/tree/source digest and both cleanup outcomes.
- [ ] Review all results/deviations. Only then update status for that exact host/
      runtime/image/worker configuration. Shared-kernel escape resistance, formal
      proof and independent certification remain separate claims.

## Future dedicated CI workflow

Standard CI is STATIC / DEFAULT GATES. **LIVE OCI GATES — NOT RUN IN STANDARD CI**.
The default suite deliberately reports eleven ignored runtime-dependent tests.

A future isolated, ephemeral, dedicated Linux runner should receive only a pinned
credential-free image and explicit rootless endpoint. Preflight and canary setup
must run first; then default gates, the serial live suite and an independent
label/workspace cleanup query. Retain bounded logs/evidence and fail on unavailable
prerequisites. Tear down the worker/daemon after each workflow, reconcile labels
on crashes, and never expose deployment/signing credentials or the host socket to
targets. Do not run arbitrary untrusted PR code on a long-lived privileged public
runner. This document specifies a workflow; no such live CI job is enabled here.
