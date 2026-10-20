# ADR-0023: Immutable schema-1 policy identity

Status: Accepted for Milestone 4A.

Policy authors use bounded strict TOML. `PolicyBundle::read` validates and freezes
an internal normalized representation; it exposes immutable properties, canonical
bytes and an independent SHA-256 identity. No mutable/deserialization bundle API
exists. The separately supplied authority selection pins ID, version and digest;
a mismatch returns an error with no eligibility result. The development CLI embeds
one fixed profile and checks its independently reproduced digest. There is no
project field or CLI option to choose a weaker bundle.

Canonical JSON follows the applicable subset of [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785),
not a new general cryptographic serializer. Schema 1 contains only fixed ASCII
object keys, Unicode scalar strings, booleans, arrays and the integer schema=1.
There are no floating numbers, arbitrary maps, timestamps or OS-native values.
UTF-8 is unchanged, including description strings; Unicode normalization is not
performed. Authoring whitespace outside strings, comments and field order have
no identity. Description whitespace inside a string is policy content.

Algorithm:

1. Reject unknown fields at every level, unknown schemas/IDs/rules and duplicates.
   Internally tagged empty struct variants are used because tagged unit variants
   in Serde can ignore unknown fields despite deny_unknown_fields.
2. Require every field explicitly; there are no implicit policy-strength defaults.
3. Sort properties by their SCREAMING_SNAKE_CASE ID spelling. Sort producers,
   command step sets and applicability authority policy-profile sets by ASCII bytes; reject duplicates.
4. Recursively sort all JSON object keys. Fixed ASCII keys have identical UTF-8
   and UTF-16 order. Emit compact JSON with no BOM, whitespace or trailing newline,
   standard JSON string escaping (lowercase control escapes), unescaped UTF-8
   elsewhere and unchanged array order after the schema-specific sorting above.
   The implementation explicitly sorts Value object keys recursively, including
   when serde_json/preserve_order is enabled by feature unification.
5. SHA-256 exactly those bytes; display 64 lowercase hexadecimal digits. The
   bundle ID, version, schema, descriptions, severity, requirements, applicability,
   rules and allowed producer versions all participate. No self-reported digest
   is accepted from the authoring file.

This is deliberately scoped to policy schema 1. Changing semantics/serialization
requires a new schema/evaluator and reviewed authority version/digest. It does
not define a certificate serialization or claim a general JCS implementation.

Fixed vectors, independently produced with Python 3.14 tomllib/json/hashlib and
rechecked by Node JSON.stringify/crypto:

| Canonical file | SHA-256 |
| --- | --- |
| policies/archcert-development-v1.canonical.json | e128e7a0cfeaf0f11917a35cc655b0e9fe6ea96dcf550bea5d25898ea8f7b9ae |
| crates/archcert-policy/tests/fixtures/canonical-unicode.json | d16b30957bbec71442b24289730df4e209e20e6b4b01885c081d5afe4b564357 |

Tests compare exact bytes and digests, including Unicode/control/quote/backslash
escaping, and exhaust all 5,040 property orderings. No file-order/mtime/host input
enters identity. Canonical fixture files intentionally have no terminal newline.

Limits: 64 KiB authoring bytes before decode (read one sentinel byte), 32 property
entries (seven fixed IDs currently possible), 16 producers, 128 UTF-8 bytes per
identifier/version/producer, 2,048 bytes per description, 32 required step IDs per
command property and 16 applicability profiles. The grammar has no recursive
expressions. TOML's own recursion protection plus the byte limit constrains
malformed nesting; only fixed-depth typed objects are accepted. Evaluation caps
160 executions, 4,096 observations and observation strings at 128 bytes. The plan
already caps 128 mandatory + 32 project steps. Work is approximately
O(P × S × (O + S + E) × B), plus bounded sorting, where P is properties,
S required steps, O observations, E expected executions and B the bounded
observation encoding size. Stored output references are
bounded by these same counts. Source completeness is O(1) over derived status;
source parsing/materialization never runs in the evaluator.
