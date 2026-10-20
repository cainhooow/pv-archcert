# Ravenport persistence dependency review

Reviewed October 20, 2026. This is focused engineering review, not a full upstream
audit. Cargo.lock pins registry checksums and all transitive versions.

Select SQLx =0.9.0 (MIT OR Apache-2.0, Rust 1.94 minimum) for maintained async
PostgreSQL support, explicit transactions, pooling and checksum-checked migrations.
The workspace uses Rust 1.99.1. Use only runtime-tokio, postgres, json and migrate;
default features, query macros, other database backends and ORM machinery are off.
SQLx and its PostgreSQL protocol parser enter infrastructure TCB only. Application
and domain remain independent, including transitive normal/build graphs.

Runtime queries always bind external values. Query syntax/types/locking are
checked by real PostgreSQL integration tests, rather than compile-time query!
macros requiring a build database or cached query metadata. Migrations use the
explicit SQLx Migrator API; failures are fatal and never silently ignored. Building
or starting HTTP does not require permission to mutate the schema.

The development connection is loopback-only, with separate explicit configuration.
This narrow adapter currently has no TLS feature: remote production connections
are not qualified. Production requires TLS verification and independently managed
credentials/roles. The provided development database uses trust authentication on
an explicitly bound loopback port and contains development data only. Never expose
that deployment to another host. No database credential enters a worker assignment
or target execution.

SQLx adds PostgreSQL framing/authentication, URL parsing/Unicode, CRC, pooling,
async scheduling and migration SHA-384 dependencies. Upstream MD5/HMAC/password
mechanisms implement PostgreSQL authentication; they are not used for ArchCert
artifact/certificate identity. Existing SHA-256 canonical identities remain intact.
Third-party unsafe in buffer/concurrency/OS libraries remains part of the TCB;
workspace unsafe_code=forbid covers owned code, not all dependencies. Exact graph
is reproducible with `cargo tree -p archcert-storage --locked`.

async-trait 0.1.92 is a proc-macro dependency for object-safe application async
ports; generated futures convey no database/wire types. Its build graph uses
existing proc-macro2/quote and syn. The dependency is locked, with no target-code
generation inputs. No TLS signing library, broker, ORM or S3 SDK is introduced.

Primary sources: [SQLx 0.9.0](https://docs.rs/sqlx/0.9.0/sqlx/),
[SQLx features](https://docs.rs/crate/sqlx/0.9.0/features),
[PostgreSQL locking](https://www.postgresql.org/docs/current/sql-select.html).

foldhash =0.2.0 (SQLx -> hashlink -> hashbrown) uses Zlib. Its upstream LICENSE
was inspected: retain its notice, do not misrepresent origin, and mark altered
sources. Add an exact-version exception, preserving all advisory/source checks.
Its unsafe unaligned loads support noncryptographic table hashing; they confer
no source/certificate/artifact identity. Earlier foldhash =0.1.5 remains a separate
build dependency with its existing exception. No global Zlib allowance is added.
