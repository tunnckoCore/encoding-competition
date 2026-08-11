# @tunnckocore/hbs

HBS3 is a compact, deterministic text encoding for JSON-shaped data. It separates schema, key dictionary, optional slot guards, and scalar value stream so decoders can recover structure, report typed holes, and verify complete or partially available payloads.

Spec: [../../docs/hbs3-spec.md](../../docs/hbs3-spec.md)

## API

```ts
import {
  createHbs,
  decodeHbs,
  encodeHbs,
  encodeRef,
  decodeRef,
  isValidHbsKey,
} from "@tunnckocore/hbs";
```

- `encodeHbs(value, options)` encodes a plain object or dense array root.
- `decodeHbs(token, options)` returns a `DecodeResult` with `value`, `checksum`, `truncated`, `holes`, `slotGuards`, and `guardIssues`.
- `createHbs(options)` returns pre-bound `encode` and `decode` helpers.
- `encodeRef` / `decodeRef` expose the base62 HBS3 reference encoding.
- `isValidHbsKey` validates strict HBS3 key names.

The package also exports `canonicalizeString`, `canonicalizeNumber`, and `sortObjectKeys` for tests, tooling, and conformance utilities that need the same scalar/key profile as the encoder.

## Input Domain

The encoder accepts the JSON data model with a container root: plain objects, dense arrays, strings, finite numbers, booleans, and null. Host-language values that cannot be represented as JSON are rejected, including class instances, dates, null-prototype objects, sparse arrays, custom array prototypes, symbols, functions, accessors, non-enumerable properties, BigInts, `NaN`, and infinities.
