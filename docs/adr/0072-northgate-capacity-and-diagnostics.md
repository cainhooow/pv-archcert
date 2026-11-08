# ADR 0072: Authority-owned Northgate capacity and actionable rejection evidence

Status: Accepted for bounded development ingress; real-repository qualification is
recorded separately. Extends ADRs 0028–0030 and 0071.
Date: November 7, 2026.

## Context

A real ArchSite push authenticated successfully and reached source reception.
Historical evidence stopped after the ref and retained neither a pack digest nor a
failure reason. Its first failing condition cannot be recovered from that record.
An isolated traced push reproduces the 30-second deadline before pack arrival.
A replay of the 95,281,675-byte, 21,271-object pack instead reaches the 64 MiB pack
cap first. The old capture adapter classified byte exhaustion as malformed data.
The selected source also exceeds the separate 64 MiB snapshot budget. These are
distinct blockers; local packed storage size is not transmitted pack size.

## Decision

Keep the existing authenticated Northgate pipeline. Add strict host-selected
`IngressCapacity`: pack transport/decoder limits, selected-source limits, total
session seconds and finite retained attempts. Historical omitted source limits
and host capacity select the original defaults. Explicit source ceilings are
128 MiB content, 10,000 leaves, 8 MiB blob, depth 32, 25,000 visits, 9 MiB object
and 512 MiB source work. Existing pack ceilings remain 256 MiB pack, 100,000
objects, 32 MiB object, 1 GiB work, depth 64 and expansion ratio 4096. Zero,
negative, overflowing, unknown and inconsistent selections reject. Session and
retention ceilings remain 120 seconds and 32 submissions. No unlimited mode exists.

The host provisioning helper validates a private capacity file through the installed
gateway, records it in private `platform.json`, and regenerates `gateway.json`.
`archcertd` validates the same typed selection before publishing it. Restart, update,
credential/grant changes and publication preserve the host selection. Browsers,
Git requests, source configuration and project provisioning cannot select capacity.
System Git's `receive.maxInputSize` follows the selected pack byte cap. Input,
framing, pack decoding and Git share an absolute session deadline; bounded selected
source and storage phases check it before publication. Individual blocking OS
operations still require deployment containment; this is not kernel cancellation.

Each new submission retains the exact capacity independently of source identity.
Accepted-source readers use that validated retained selection, with the original
budgets for historical records. The development artifact envelope remains bounded
by retained content plus the unchanged 8 MiB metadata ceiling and framing. Changing
current admission capacity never reinterprets earlier source or certificate bytes.
No certificate, source schema, canonicalization, hash preimage or signature changes.

Use the existing bounded ingress evidence for last reached stage, elapsed time,
pack prefix/count/inflation, complete pack digest, decoder work, source content and
classified failure. Missing measurements remain unknown. Client stderr contains a
closed code and safe numeric budget details; stdout remains Git packet-line data.
Unavailable infrastructure, generic Git rejection, malformed objects, real budget
exhaustion and timeout must not be conflated. Retention/lease exhaustion may prevent
a new per-submission record; report it directly without evicting existing evidence.
A failure after publication preserves accepted state and cannot rewrite it rejected.

A single shallow declaration equal to the submitted commit remains supported.
A process-local `GIT_SHALLOW_FILE` can omit unnecessary ancestry without changing
commit, tree or repository storage. Independent object/hash/path/checksum/delta
validation and Git strict receive still apply. Missing selected-closure objects,
other shallow boundaries and cross-submission thin bases remain unsupported.
No clone fallback, fabricated ancestors, history rewriting or target hooks.

## Security implications

Increasing a bounded deployment budget changes resource exposure, not authority.
One store lease, private quarantine, explicit SSH grants, no-follow immutable
publication, independent hashes, path rules, external-source incompleteness and
signer/runtime exclusions remain required. Candidate input cannot raise any budget.
Production still needs separate OS identities and CPU/memory/disk containment;
this development implementation is not production custody or a native runner
requalification. Detailed hostile text, paths, keys and credentials remain excluded
from client messages and diagnostic evidence.

## Alternatives and consequences

Hard-coding larger global defaults, silently skipping checks, rewriting the candidate,
processing arbitrary historical clones and adding another service were rejected.
The selected commit is source provenance; ancestry is not certification scope.
Source acceptance does not establish a suitable policy, runner, supported language,
passing checks or certification. The existing product onboarding selects controlled
Python authority; JavaScript/TypeScript/Next.js/Bun needs separately authorized
policy, pinned toolchain/dependencies, runner commands and qualification.
M9 remains in progress; M10, M11 and Genesis / Firstwarden remain not started.
