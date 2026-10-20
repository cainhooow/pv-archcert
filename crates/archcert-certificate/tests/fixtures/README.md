# Independent certificate regression vectors

The fixed `openssl-vector.*` files are deterministic public format and signature
fixtures consumed by the certificate tests. They preserve an independently
constructed canonical payload, signed envelope, SHA-256 digest, and OpenSSL public
verification key. They are required regression inputs, not demonstration output.
No private key is retained. Tests must continue to verify these historical bytes
without regenerating them through the implementation being tested.

Default issuance tests construct their relational evidence fixtures in memory.
They never require untracked `docs/certificates/development` milestone output.
The durable native demonstration separately checks public exported certificate,
manifest/bundle bindings and Bottle rejection against actual execution evidence.
No temporary demonstration certificate becomes a committed regression fixture.
