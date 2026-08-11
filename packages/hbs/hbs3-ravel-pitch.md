# Ravel

Ravel is a compact, canonical, streaming-friendly structured value encoding format designed for recoverable partial decoding, tamper detection, and per-slot integrity.

It is built for large, repetitive structured data where plain JSON-like formats become bulky, fragile, and hard to verify. The more repeated keys and scalar values a payload has, the more Ravel benefits from its key dictionary, scalar slot deduplication, compact structure encoding, and separated value stream.

## Why Ravel

Most text formats optimize for readability or simple serialization. Ravel optimizes for robust structured value transport.

Ravel preserves enough structure to recover useful data even when the value stream is incomplete. It can report typed holes for missing or damaged values, verify the complete body with a global integrity tag, and optionally verify individual scalar slots with per-slot guards.

That makes it useful for agent systems, streaming pipelines, signed payloads, long-context transport, archival data, and any environment where payloads may be truncated, copied, compressed, transformed, or inspected by untrusted tooling.

## What Ravel provides

Ravel combines several properties in one format:

- canonical deterministic encoding
- compact key and value deduplication
- object and array structure preservation
- recoverable partial decoding
- typed holes for missing, truncated, or invalid values
- global integrity verification
- optional HMAC-backed tamper resistance
- optional per-slot integrity guards
- streaming-friendly schema/value separation
- JSON-compatible structured value domain without requiring JSON text input

The input is structured JavaScript values in the JSON data model. The output is not JSON; it is a purpose-built text encoding with a compact schema, key dictionary, optional guards, and value stream.

## Recovery-first design

Ravel separates structure from scalar values.

The schema records the shape of the value: objects, arrays, booleans, nulls, key references, scalar slot references, and encoded slot lengths. String and number values live in a separate value stream.

This means a decoder can often recover the object/array shape even when part of the value stream is missing. Instead of failing completely, it can return the recovered value plus precise holes:

```txt
/items/42/name       missing string slot
/items/42/price      truncated number slot
/meta/checksum       invalid string slot
```

For agent workflows, this matters. An agent can reason about what survived, what is missing, and whether recovered values are trustworthy.

## Integrity and tamper detection

Every Ravel payload includes a global integrity tag over the body. When the payload is complete, decoders can report whether the body matches the committed tag.

With plain SHA-256 this provides corruption/tamper detection. With HMAC-SHA-256 and a secret, it provides tamper resistance against parties that cannot forge the tag.

Ravel can also enable per-slot guards. These allow individually recovered scalar values to be verified even when the full payload is truncated and global integrity cannot be checked.

Unguarded mode is smaller and still has global integrity. Guarded mode costs more bytes/tokens but gives stronger local trust for recovered slots.

## Compactness at scale

Ravel is especially effective on large, repetitive structured values.

Repeated object keys are stored once in the key dictionary. Repeated string and number values can be stored once in the value stream and referenced multiple times from the schema. The result improves as payloads grow and repeat.

For a basic demo with an array of 100 nested objects:

- Ravel without per-slot guards produced about 44 KB / 27k tokens
- Ravel with 6-character guards produced about 51 KB / 31.8k tokens
- TOON produced about 26k tokens for the same input, without Ravel's recovery and integrity features

The important point is not that Ravel is always the smallest text representation. It is that Ravel stays close to compact data formats while carrying enough structure to recover, verify, and explain partially available data.

## Comparison to other formats

**JSON** is universal and readable, but it is not canonical by default, repeats every key, has no built-in integrity, and fails as a whole when truncated or malformed.

**Stable JSON/canonical JSON** fixes deterministic ordering and scalar representation, but it remains plain JSON. It does not provide typed holes, partial value recovery, slot-level verification, or structural/value-stream separation.

**TOON** is excellent for compact, readable structured data in LLM contexts. It can be very token efficient, especially for tabular arrays. Ravel targets a different layer: robust structured value transport. It gives up a small amount of compactness to gain canonicalization, recovery, verification, and tamper-aware decoding.

**Binary formats** like MessagePack, CBOR, and protobuf can be very compact and fast, but they are not text-native, are less convenient for prompt/context transport, and typically do not provide Ravel-style typed partial recovery and slot integrity as part of the envelope.

**Ravel** is for cases where text-native compactness is not enough and payload also needs to be deterministic, recoverable, and verifiable.

## Positioning

Ravel is not just another JSON alternative.

It is a recoverable structured value format for systems that need compact text output, deterministic encoding, partial decoding, and integrity guarantees.

Short version:

> Ravel is a compact, canonical, recoverable structured value format.

Full version:

> Ravel is a compact, canonical, streaming-friendly structured value encoding format designed for recoverable partial decoding, tamper detection, and per-slot integrity.

Competitive version:

> TOON is smaller. Ravel is safer.

More precise:

> Ravel stays close to compact text formats while adding canonical encoding, partial recovery, typed holes, global integrity, optional HMAC tamper resistance, and per-slot verification.
