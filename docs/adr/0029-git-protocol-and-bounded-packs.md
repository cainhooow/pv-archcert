# ADR-0029: Isolated Git receive adapter and gitoxide pack validation

Status: Accepted for Northgate. Extends ADR-0005 without changing schema 1.

Evaluated a full Rust Git stack (gitoxide), a libgit2 binding, an embedded Rust SSH
server and a restricted OpenSSH/system Git adapter. Select OpenSSH for SSH and Git
receive-pack for maintained Smart Protocol advertisements and final report-status.
Select pinned gitoxide gix-pack 0.76.0 for pack entry/header and OFS/REF delta
interpretation. No handwritten SSH cryptography, delta instructions or pack header
parser is introduced. ArchCert's small ingress filter uses gix-packetline 0.21.0,
checks a single create-only branch command and bounds stream framing before Git.

The complete live pack is captured under a byte cap without waiting for client
EOF. gitoxide parses each entry header; fixed-buffer zlib inflation immediately
rejects excess output and size mismatch, and the complete pack checksum is
verified. Owned bytes back gix-pack::data::File, avoiding mmap mutation races.
All entries (including unreachable ones) are size/work bounded. Resolution checks
known bases and ancestry before decoding; missing/cyclic/out-of-pack bases fail.
Self-contained normal pushes support OFS_DELTA and REF_DELTA. Since each receiver
advertises an empty repository, honest clients send the complete required graph;
no cross-submission thin-pack base or alternate-object trust is needed.

Bounds: default 64 MiB pack, 25,000 objects, 9 MiB individual object, 256 MiB
aggregate decode work, depth 32 and expansion ratio 4096 plus 1 KiB. Gitoxide
allocation limits bound combined delta work buffers. Existing SourceLimits still
bound selected closure visits, files, bytes, blob size and tree depth. Upper
configuration ceilings are explicit; no unlimited mode exists. Hash every
resolved raw Git preimage independently, then use the original M1 commit/tree/
path/mode/hash validator. Git SHA-1/SHA-256 are compatibility provenance, not the
ArchCert SHA-256 source security identity.

Only after independent selected-source validation does isolated receive-pack see
the buffered request. Its strict fsck also checks object grammar before acceptance.
Git runs structurally through Command, under a cleared constructed environment,
fresh private cwd/HOME, null global/system config, empty template, disabled hooks,
filters-by-no-checkout, credential helpers, fsmonitor, replacements, protocol
fetches, auto-GC and maintenance. A configured absolute Git path and bounded
reported version enter evidence; neither is executable attestation.

A single shallow declaration equal to the submitted commit is supported so the
historical depth-1 Bottle repository can push normally. Git receives the same
validated shallow declaration; history is not certified. Other shallow declarations,
multiple refs, updates/deletes, tags, symbolic names and unexpected namespaces
reject. Status output is buffered until source acceptance/storage succeeds.

The minimal framing filter is necessary to enforce decoded-size/depth limits
before Git's decoder, rather than exposing unbounded receive-pack decoding first.
Git remains a trusted infrastructure executable and must run under a dedicated
service identity with OS resource containment for production deployment.

References: [Git receive-pack](https://git-scm.com/docs/git-receive-pack),
[gitoxide pack API](https://docs.rs/gix-pack/0.76.0/gix_pack/),
[bounded pack backing storage](https://docs.rs/gix-pack/0.76.0/gix_pack/data/struct.File.html).
