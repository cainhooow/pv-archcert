# Independent certificate regression vectors

The fixed `openssl-vector.*` files are deterministic public format and signature
fixtures consumed by the certificate tests. They preserve an independently
constructed canonical payload, signed envelope, SHA-256 digest, and OpenSSL public
verification key. They are required regression inputs, not demonstration output.
No private key is retained. Tests must continue to verify these historical bytes
without regenerating them through the implementation being tested.
