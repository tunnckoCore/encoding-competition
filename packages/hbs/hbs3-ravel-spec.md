# HBS3 — JSON Typed Schema Text Encoding, Draft Spec

## 1. Features

HBS3 is a streaming-friendly, compact, text-native, and deterministic encoding with schema types, structural recovery, fault-tolerant partial decoding, integrity checks, optional tamper-resistance, and optional per-slot guards.

It is designed for cases where Base64/Base-N encodings are undesirable because they add proportional size inflation, and where plain JSON is insufficient because it does not provide structural recovery, slot-level integrity, or graceful partial decoding.

### Text-native encoding

- HBS3 wire output is text-native and UTF-8 serializable.
- HBS3 framing, schema tokens, references, lengths, guards, and hashes use ASCII characters.
- String and number slot material uses the HBS3 canonical JSON scalar profile.
- No binary serialization.
- No Base64/Base32/Base58/Base-N wrapping of the full payload.

### Built-in canonicalization

- Encoder canonicalizes supported JSON input during HBS3 encoding.
- Canonicalization follows the HBS3 canonical JSON scalar profile.
- Object properties are traversed in lexicographic key order.
- In strict mode, keys are ASCII-only, so key ordering is ASCII lexicographic order.
- Array order is preserved.
- Sparse arrays are rejected because holes are not JSON values.
- String and number slot values are serialized by the HBS3 canonical JSON scalar profile.
- Encoded value length refers to the canonical serialized JSON representation.

### Minimal overhead

- The payload is structurally transformed, not base-encoded.
- Overhead is primarily header, schema, key dictionary, optional guards, and integrity hash/tag.
- Repeated keys and repeated scalar values can be referenced rather than duplicated.
- Homogeneous object arrays may use table mode to avoid repeating the same object shape for every row.

### Integrity and tamper-resistance

- The header contains a leading integrity hash/tag.
- The integrity hash/tag commits to the canonical payload: declared lengths plus `<T><K><G><V>`.
- The integrity hash/tag does not include its own field.
- The decoder can determine whether the received complete payload matches the committed payload.
- Integrity status is represented as `true | false | null`.

### Per-slot integrity

- Per-slot guards are optional.
- Small objects, non-truncation-sensitive payloads, or environments where global integrity is sufficient may omit guards.
- When omitted, `guardsLen` is `0` and `G` is empty.
- When present, guards allow individual recovered slots to be checked even when the full body is truncated.

### Truncation detection

- The header contains the expected body length.
- If fewer body bytes are available than declared, the decoder reports `truncated: true`.

### Partial decoding

- The decoder attempts to recover as much data as possible even if the body is truncated.
- If the schema survives, the decoder can recover available structure, complete key entries, booleans, nulls, and any fully available scalar slots.
- Missing keys or values are reported as typed holes where their paths can be determined.

### Structural recoverability

- JSON shape and scalar types are encoded in a schema tape.
- `true`, `false`, and `null` are fully recoverable from the schema alone when their paths can be determined.
- Objects and arrays can still be reconstructed structurally even when some scalar values are missing.

### Typed holes & Guard issue reporting

- Missing values are reported with their JSON path, expected type, slot reference, expected encoded length, and available length where applicable.

### Deduplicate scalar slots

- Repeated strings and numbers may be stored once and referenced multiple times from the schema.
- Arrays of homogeneous objects may use table mode for repeated object shapes.
- If a shared slot is recovered once, all fields referencing that slot can be reconstructed.

### Strict keys

- Keys must match a strict bare-key grammar.
- Unsupported keys cause encoding to fail fast.
- No escaped-key fallback is required in strict mode.
- Key validation applies to every object key, including keys in nested objects.

## 2. Terminology

### Body

The concatenation of `<T><K><G><V>`.

### T / Schema Tape

- Structural representation of the JSON tree.
- Contains object/array shape, key references, scalar type markers, slot references, encoded value lengths, and optional homogeneous object-array table forms.

### K / Key Dictionary

Comma-separated list of unique JSON object keys in canonical encounter order. Encounter order is determined by sorting each object's own keys in ascending ASCII lexicographic order, appending new keys to `K`, then descending into values in that same sorted order.

### G / Guard Section

- Optional ordered list of per-slot integrity guards.
- Empty when guards are disabled.

### V / Value Stream

- Concatenation of encoded scalar slot values.
- Contains only string and number slot material.
- Booleans and nulls are encoded directly in the schema and do not appear in `V`.

### Slot

- A deduplicated scalar value referenced from the schema.
- String slots use `'`.
- Number slots use `"`.

### Hole

A missing or damaged value that the decoder can describe because the schema survived.

## 3. Wire Format

```text
hbs3.<integrityHash>.<bodyLen>.<schemaLen>.<keysLen>.<guardsLen>:<T><K><G><V>
```

Fields:

```text
hbs3            format + version marker
integrityHash   leading integrity hash/tag over the canonical payload
bodyLen         decimal length of <T><K><G><V>
schemaLen       decimal length of <T>
keysLen         decimal length of <K>
guardsLen       decimal length of <G>
:               header/body separator
T               schema tape
K               key dictionary
G               optional guard section
V               value stream
```

The body is:

```text
body = <T><K><G><V>
```

The canonical payload committed by `integrityHash` is:

```text
payload = <bodyLen>.<schemaLen>.<keysLen>.<guardsLen>:<body>
```

The final HBS3 text is:

```text
hbsPayload = "hbs3.<integrityHash>.<payload>"
```

The body is sliced as:

```text
T = body.slice(0, schemaLen)
K = body.slice(schemaLen, schemaLen + keysLen)
G = body.slice(schemaLen + keysLen, schemaLen + keysLen + guardsLen)
V = body.slice(schemaLen + keysLen + guardsLen)
```

If guards are disabled:

```text
guardsLen = 0
G = ""
```

Header and body length rules:

- `bodyLen`, `schemaLen`, `keysLen`, and `guardsLen` MUST be canonical unsigned decimal integers.
- A canonical unsigned decimal integer is either `0` or a non-zero digit followed by zero or more digits.
- Leading zeroes are malformed.
- Header lengths, schema slot lengths, table counts, table column lengths, and decoded references MUST fit in the implementation's safe integer range.
- Decimal length/count fields MUST be rejected before numeric conversion when their digit count exceeds the implementation limit. The reference TypeScript implementation caps decimal length/count fields at 16 digits.
- All lengths count UTF-8 bytes of the encoded HBS3 payload segments, not host-language string code units or decoded JSON semantic length.
- Byte-range slicing MUST reject ranges that split a UTF-8 scalar value. Decoders MUST NOT silently insert U+FFFD replacement characters for malformed byte boundaries.
- `schemaLen + keysLen + guardsLen` MUST NOT exceed `bodyLen`.
- `availableBody.length < bodyLen` means the body is truncated.
- `availableBody.length === bodyLen` means the complete body is available.
- `availableBody.length > bodyLen` is a malformed envelope and MUST be rejected.
- If `availableBody.length < schemaLen`, `T` is incomplete and the decoder MUST reject the envelope as structurally undecodable.
- If `schemaLen <= availableBody.length < schemaLen + keysLen`, `T` is complete but `K` is truncated. The decoder SHOULD attempt partial structural recovery using the complete schema tape and any complete key dictionary entries. `G` and `V` are unavailable.
- If `schemaLen + keysLen <= availableBody.length < schemaLen + keysLen + guardsLen`, `G` is truncated and `V` is unavailable.
- If `schemaLen + keysLen + guardsLen <= availableBody.length < bodyLen`, `V` is missing or truncated according to the schema-declared slot lengths.

## 4. Decode Flow

A decoder SHOULD follow this order:

```text
1. Parse the header.
2. Read the available body.
3. Compare available body length against bodyLen.
4. Set truncated:
    - `true` if availableBody.length < bodyLen
    - `false` if availableBody.length === bodyLen
5. Validate integrity and guard options, including algorithm names, secrets, and tag lengths.
6. If the complete body is available, verify integrityHash against `<bodyLen>.<schemaLen>.<keysLen>.<guardsLen>:<body>`
    - `true` - complete payload is available and matches integrityHash
    - `false` - complete payload is available but does not match integrityHash
    - `null` - body is truncated, so complete-payload integrity cannot be verified
7. Slice the available T, K, G, and V regions using schemaLen, keysLen, and guardsLen.
8. Decode T. If T is truncated or structurally invalid, reject.
9. Decode K fully or partially.
10. Determine slot encounter order from T.
11. Decode V according to slot lengths declared in T.
12. If G is present, verify available slot guards.
13. Reconstruct JSON value.
14. Report holes for missing keys, missing slots, truncated slots, or invalid slots.
```

## 5. Key Dictionary

In strict mode, keys MUST match:

```ts
/^[A-Za-z0-9_$][A-Za-z0-9_$@.-]*(?: [A-Za-z0-9_$@.-]+)*$/;
```

This allows keys such as:

```text
id
0
123abc
block_hash
$schema
token.id
token-id
_meta
token@id
token id
token id v2
```

This rejects:

```
" foo"
"foo "
"foo  bar"
"_ "
"0 "
"z "
","
"foo,bar"
"@id"
```

Rules:

- No empty keys.
- No commas.
- No leading space.
- No trailing space.
- No consecutive spaces.
- No arbitrary escaping.
- Key MUST start with `A-Z`, `a-z`, `0-9`, `_`, or `$`.
- Remaining non-space characters MAY be `A-Z`, `a-z`, `0-9`, `_`, `$`, `@`, `.`, or `-`.
- `@` MAY appear inside a key but MUST NOT be the first character.
- A single space MAY appear only between two non-space key character runs.
- Encoder MUST throw if a key does not match the strict key regex.
- Key dictionary entries MUST be unique. Duplicate keys in `K` are malformed.
- A complete `K` that violates the key grammar, contains duplicate entries, contains malformed separators, differs from canonical first-encounter order, or contains unreferenced extra entries MUST be rejected.
- A truncated `K` is recoverable when the schema tape is complete.
- A schema key reference that points past the decoded key dictionary SHOULD be reported as a `missing-key` hole when the schema can otherwise be decoded.

Canonical key dictionary construction:

```text
collectKeys(value):
  if value is an object:
    keys = object's own keys sorted in ascending ASCII lexicographic order

    for key in keys:
      if key is not already present in K:
        append key to K

    for key in keys:
      collectKeys(value[key])

  else if value is an array:
    for element in value, in array order:
      collectKeys(element)

  else:
    do nothing
```

Because strict keys are ASCII-only, this ordering matches JavaScript `Object.keys(obj).sort()` for accepted keys.

A decoder MAY partially decode a truncated `K`. Only complete key entries may be used. An entry followed by an observed comma is complete. The final entry is complete only when the declared `keysLen` is available; otherwise the final entry MUST be treated as incomplete.

The strict regex may be expanded in a future profile, but v1 should keep the key grammar intentionally small and unambiguous.

Key references in the schema use `@`.

Examples:

```text
@0
@A
@z
@{10}
@{11}
```

## 6. Reference Encoding

HBS3 uses compact references for keys and slots.

Single-character references use the base62 alphabet:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```

Indexes:

```text
0  -> 0
1  -> 1
...
9  -> 9
10 -> A
35 -> Z
36 -> a
61 -> z
```

Indexes above 61 use extended references:

```text
62   -> {10}
63   -> {11}
...
3843 -> {zz}
3844 -> {100}
```

Canonical reference rules:

- References MUST be canonical.
- Indexes `0` through `61` MUST be encoded as exactly one base62 character.
- Indexes `62` and above MUST be encoded as an extended reference: `{` + base62(index) + `}`.
- Extended references MUST NOT contain leading zeroes.
- Extended references MUST NOT be used for indexes `0` through `61`.
- `{}`, `{0}`, `{00}`, `{01}`, and `{z}` are malformed.
- Decoded reference indexes MUST fit in the implementation's safe integer range. The reference TypeScript implementation caps extended references at 9 base62 digits.
- Key references, string slot references, and number slot references use separate namespaces.
- For example, `'0` and `"0` are different scalar slots.

Examples:

```text
@0        key ref 0
@A        key ref 10
@z        key ref 61
@{10}     key ref 62
@{11}     key ref 63

'0_26     string slot 0, encoded length 26
'z_44     string slot 61, encoded length 44
'{10}_68  string slot 62, encoded length 68
'{11}_68  string slot 63, encoded length 68

"0_8      number slot 0, encoded length 8
"{10}_14  number slot 62, encoded length 14
"{11}_14  number slot 63, encoded length 14
```

## 7. Schema Tape

The schema tape encodes the JSON tree.

Tokens:

```text
{          object start
}          object end
[          array start
]          array end
~<columnCount>.<rowCount>: homogeneous object-array table mode inside an array

@x         key reference

'x_len     string slot reference with encoded value length
"x_len     number slot reference with encoded value length

t          true
f          false
z          null
```

Object entries are encoded as:

```text
@<keyRef><valueToken>
```

The root schema MUST be an object or array. Encoders MUST reject scalar roots. Decoders MUST reject schema tapes whose root value is a scalar.

Schema validity rules:

- Objects and arrays MUST be closed.
- Object entries MUST contain a key reference followed by a value token.
- Complete object schemas MUST encode entries in ascending key-name order. Decoders MUST reject non-canonical object entry order when all referenced keys are available.
- Key and slot references MUST use the canonical reference encoding from section 6.
- Slot lengths MUST be canonical unsigned decimal integers: either `0` or a non-zero digit followed by zero or more digits.
- Slot lengths, table counts, and table column lengths MUST fit in the implementation's safe integer range and MUST be rejected before numeric conversion when their digit count exceeds the implementation limit.
- Reusing a slot reference with the same sigil and length is valid.
- Reusing a slot reference with a different sigil or length is malformed.
- Trailing data after the root schema value is malformed.
- Homogeneous object-array table mode MAY be used for arrays whose items are plain objects with the same canonical sorted key list.
- Table mode MUST preserve array item order.
- Table-mode columns MUST follow the shared canonical sorted key list. Decoders MUST reject non-canonical table column order when all referenced keys are available.
- Encoders and decoders MUST reject inputs whose object/array nesting depth exceeds the implementation limit before relying on host stack exhaustion. The reference TypeScript implementation caps nesting depth at 256.

Examples:

```text
@0f         key 0 -> false
@1z         key 1 -> null
@2'0_26     key 2 -> string slot 0, encoded length 26
@A"1_12     key A -> number slot 1, encoded length 12
@D{...}        key D -> nested object
@Q[...]        key Q -> array
@{10}{...}     key 62 -> nested object
@{11}[...]     key 63 -> array
@{11}"{11}_14  key 63 -> number slot 63, encoded length 14
```

Arrays contain value tokens directly:

```text
['0_5"0_2tz]
```

Meaning:

```text
["...", 66, true, null]
```

Arrays of homogeneous objects MAY use table mode:

```text
[~2.3:@0"1@1"1:012345]
```

Meaning:

```json
[
  { "a": 1, "b": 2 },
  { "a": 3, "b": 4 },
  { "a": 5, "b": 6 }
]
```

In table mode:

- `~` marks the optimized array form.
- `2` is the number of columns in each row object.
- `3` is the number of rows.
- The first `:` separates the table metadata from column descriptors.
- `@0"1@1"1` declares two number columns with encoded value length `1`. Column descriptors are emitted in the shared canonical sorted key order.
- The second `:` separates column descriptors from row cells.
- `012345` is encoded by iterating array items in array order and, within each row object, iterating the shared canonical sorted key list. Because both columns are fixed-length number columns, cells contain slot references only.

For table mode, array item order is preserved. Each array item is treated as one row object. The column order is the shared canonical sorted key list for those row objects. Because strict keys are ASCII-only, this is ascending ASCII lexicographic order, matching `Object.keys(obj).sort()` for accepted keys.

Column descriptors are encoded as `@<keyRef><shape>`:

```text
@0'44      key 0 -> fixed-length string column, encoded length 44; row cells are slot refs
@0'        key 0 -> variable-length string column; row cells are ref_len
@0"8       key 0 -> fixed-length number column, encoded length 8; row cells are slot refs
@0"        key 0 -> variable-length number column; row cells are ref_len
@0t        key 0 -> constant true column; no row cells
@0f        key 0 -> constant false column; no row cells
@0z        key 0 -> constant null column; no row cells
@0{        key 0 -> object column; row cells are normal value tokens
@0[        key 0 -> array column; row cells are normal value tokens
@0*        key 0 -> mixed/fallback column; row cells are normal value tokens
```

Object column cells MUST be object schemas. Array column cells MUST be array or table schemas. Mixed/fallback column cells MAY be any normal value schema. Duplicate key refs within one object schema or one table column descriptor list are malformed.

A homogeneous object array is an array where every item is a plain object with the same canonical sorted key list. Array item order is preserved. Each row reconstructs to an object using that shared sorted key list. Hole paths include the array index and key, such as `/items/7/name`.

## 8. Value Stream

- The value stream is a concatenation of encoded string and number slot values.
- There are no separators and no per-value length prefixes in `V`.
- The schema declares slot order and encoded lengths.
- String and number values are canonical JSON scalar material produced by the HBS3 canonical JSON scalar profile.
- `V` MUST contain exactly the concatenation of unique scalar slot encodings in slot encounter order.
- If complete `V` contains bytes beyond the sum of schema-declared slot lengths, the decoder MUST reject the envelope.
- Slot byte ranges that split a multi-byte UTF-8 scalar MUST be treated as invalid slot material or a hard envelope failure. Decoders MUST NOT recover by inserting U+FFFD.
- A fully available scalar slot whose bytes do not match the canonical spelling of the parsed string or finite number MUST be reported as `invalid-slot`.

Example schema fragment:

```text
@2'0_26@3'1_68@4"0_8
```

Example value stream:

```text
"2026-05-20T04:16:35.000Z""0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76"25133995
```

The decoder consumes:

```text
'0 length 26 -> "2026-05-20T04:16:35.000Z"
'1 length 68 -> "0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76"
"0 length 8  -> 25133995
```

Encoded length refers to the HBS3 canonical JSON scalar representation.

The HBS3 scalar profile is JCS-compatible for valid Unicode strings and finite ECMAScript numbers, with two reference-profile details:

- finite numbers use the ECMAScript `Number.prototype.toString()` spelling after normalizing `-0` to `0`
- isolated surrogate code units in strings are preserved by emitting lowercase `\u00xx`/`\uxxxx` JSON escapes instead of inserting U+FFFD or dropping the code unit

## 9. Slot Encounter Order

Slot order is determined by first encounter in the schema tape.

For table mode, slot encounter follows the encoded cell order: array items are processed in array order, and each row object's cells are processed in the shared canonical sorted key order.

Given:

```text
{@0'0_5 @1'1_5 @2'0_5 @3"0_2 @{10}"{10}_14 @{11}"{11}_14}
```

_(spaces above are only for readability)_

Slot encounter order is:

```text
'0, '1, "0, "{10}, "{11}
```

String slots and number slots use separate namespaces. For example, `'0` and `"0` are different slots.

The repeated reference to `'0` does not create a new slot. The value stream contains one materialization per unique slot in encounter order.

If a reused slot is missing, truncated, or invalid, each path that references that slot SHOULD receive a hole.

## 10. Deduplication

Encoders MUST deduplicate identical canonical scalar slot values.

Example source:

```json
{
  "creator": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "receiver": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "current_owner": "0xdd756238f578440ee0093876f8f07dafacc88b46"
}
```

Schema may reference the same slot:

```text
{@0'0_44@1'0_44@2'0_44}
```

Value stream stores the value once:

```text
"0xdd756238f578440ee0093876f8f07dafacc88b46"
```

If `'0` is recovered, all three fields are recovered.

## 11. Guard Section

The guard section contains optional per-slot guard tags. Guards MAY be disabled.

When guards are disabled:

```text
guardsLen = 0
G = ""
```

When guards are enabled:

- Guard order follows slot encounter order.
- Each guard corresponds to one unique scalar slot.
- `G` is comma-separated.
- The expected number of guard entries is the unique scalar slot count.
- `guards.tagLength` defaults to `6` when guards are enabled and tagLength is omitted.
- `guards.tagLength` MUST be an integer greater than or equal to `2` and less than or equal to `64`.
- Guard algorithm and `guards.tagLength` are not encoded in `G`. They are decoder configuration supplied out-of-band. A decoder without the matching guard configuration MUST NOT claim guard status `true`.
- Guard entries MUST be lowercase hexadecimal strings with exactly the configured `guards.tagLength`.
- Valid-shaped guard comparisons SHOULD compare the full equal-length tag material without early-exit string comparison, especially when guards use HMAC.
- Missing, truncated, invalid, or extra guard entries MUST NOT make decoding fail.
- When a slot's guard cannot produce `true` or `false`, the corresponding slot guard status is `null` and details MUST be reported in `guardIssues`.

If slot encounter order is:

```text
'0, '1, "0, '2
```

Then G is comma-separated:

```text
tag0,tag1,tag2,tag3
```

Guard entry parsing rules:

- `missing-guard`: no guard entry is available for an expected slot. The slot guard status is `null`.
- `truncated-guard`: a guard entry is present but shorter than `tagLength`. The slot guard status is `null`.
- `invalid-guard`: a guard entry is present but has non-hex characters or is longer than `tagLength`. The slot guard status is `null`.
- `extra-guard`: a guard entry exists beyond the unique scalar slot count. It has no corresponding slot.
- A valid-shaped guard that matches the corresponding slot guard preimage produces slot guard status `true`.
- A valid-shaped guard that does not match the corresponding slot guard preimage produces slot guard status `false`.

Each guard corresponds to the slot identity, declared encoded length, and exact encoded slot value:

```text
slotId = slot sigil + canonical slot reference
encodedLength = declared slot encoded length as decimal UTF-8 byte count
slotValue = exact encoded slot bytes from V

slotGuardPreimage = "hbs3-slot:" + slotId + ":" + encodedLength + ":" + slotValue
```

For public corruption detection:

```text
slotGuard = SHA256_HEX(slotGuardPreimage).slice(0, tagLength)
```

For tamper resistance:

```text
slotGuard = HMAC_SHA256_HEX(secret, slotGuardPreimage).slice(0, tagLength)
```

If the slot value is unavailable, missing, truncated, or invalid, the slot guard status is `null`.

For tamper resistance, HMAC or a digital signature-derived tag SHOULD be used instead of a plain hash. If the body is truncated, a decoder may still verify individual recovered slots using guards that survived.

Recommended slot guard result:

```ts
// true  = valid-shaped guard is present and matches
// false = valid-shaped guard is present but does not match
// null  = guard is missing, truncated, invalid, extra, disabled, or slot is unavailable
type SlotGuardStatus = true | false | null;
```

Recommended guard issue type:

```ts
type GuardIssue = {
  index: number;
  kind: "missing-guard" | "truncated-guard" | "invalid-guard" | "extra-guard";
  slot?: string;
  expectedLength?: number;
  availableLength?: number;
};
```

Use cases:

- Disable guards for small objects.
- Disable guards when global integrity is sufficient.
- Enable guards when partial recovery must distinguish "parsed" from "locally verified".
- Enable guards when truncation is likely and recovered slots need independent confidence.

## 12. Integrity Hash / Tag

The `integrityHash` commits to the canonical payload, excluding only the `integrityHash` field itself.

```text
body = <T><K><G><V>

payload = <bodyLen>.<schemaLen>.<keysLen>.<guardsLen>:<body>

integrityHash = HASH_OR_TAG(payload)

hbsPayload = "hbs3.<integrityHash>.<payload>"
```

For default public corruption detection:

```text
integrityHash = SHA256_HEX(payload)
```

For tamper resistance:

```text
integrityHash = HMAC_SHA256_HEX(secret, payload)
```

Default HBS3 integrity settings:

```text
integrity.algorithm: sha256
integrity.tagLength: 16
output: lowercase hexadecimal SHA-256 digest
guards: disabled
```

`integrity.algorithm` MUST be `"sha256"` or `"hmac-sha256"`. `integrity.secret` is required for `"hmac-sha256"`. `integrity.tagLength` MUST be an integer greater than or equal to `2` and less than or equal to `64`.

Integrity algorithm and `integrity.tagLength` are not encoded as separate wire fields. They are decoder configuration supplied out-of-band. The default configuration is SHA-256 with a 16-character tag; any other integrity mode requires the caller to configure the decoder with the same algorithm, secret if required, and tag length used by the encoder.

The wire `integrityHash` field MUST be a lowercase hexadecimal string with exactly the configured `integrity.tagLength`. A malformed `integrityHash` field is a hard envelope failure. Complete-payload integrity comparisons SHOULD compare the full equal-length tag material without early-exit string comparison, especially when `integrity.algorithm` is `"hmac-sha256"`.

When guards are enabled:

```text
guards.algorithm: "sha256" | "hmac-sha256"
guards.secret: required for "hmac-sha256"
guards.tagLength: number of hexadecimal characters retained from the digest/tag; defaults to 6; MUST be an integer between 2 and 64
```

Recommended terminology:

```text
hash          public integrity / corruption detection
HMAC tag      authenticated integrity / tamper resistance
guard         per-slot local integrity tag
```

When the body is truncated, the complete-payload integrity hash/tag cannot verify. In that case:

- truncated = true
- checksum = null

If guards are enabled, recovered slots may still be individually verified.

## 13. Partial Decoding and Holes

Partial decoding applies only after the envelope and schema tape are structurally decodable.

There are two failure classes.

Hard envelope or schema failures MUST reject the envelope:

- invalid prefix
- invalid header
- malformed integrity hash/tag shape
- non-canonical length fields
- length/count fields or references outside the implementation's safe integer range
- `schemaLen + keysLen + guardsLen > bodyLen`
- `availableBody.length > bodyLen`
- truncated `T`
- grammatically invalid `T`
- scalar root schema
- unclosed object or array in `T`
- trailing schema data after the root schema value
- nesting depth beyond the implementation limit
- malformed or non-canonical complete `K`

Recoverable decode conditions SHOULD return `DecodeResult` with holes or guard issues:

- truncated `K`
- schema key reference points past the available key dictionary
- missing, truncated, invalid, or extra guard entries
- unavailable `V`
- missing slot
- truncated slot
- invalid fully available slot

If a value slot cannot be fully decoded, the decoder SHOULD still reconstruct the JSON tree using available data.

When `K` is truncated:

- only complete key entries may be used
- schema references to unavailable key indexes SHOULD produce `missing-key` holes
- `G` and `V` MUST be treated as unavailable
- string and number slots SHOULD be reported as `missing-slot` where their paths can be determined
- booleans and nulls MAY be recovered where their paths can be determined

Example hole type:

```ts
type Hole = {
  path: string;
  kind:
    | "missing-slot"
    | "truncated-slot"
    | "invalid-slot"
    | "missing-key"
    | "schema-error";
  slot?: string;
  expectedType?: "string" | "number" | "boolean" | "null" | "object" | "array";
  expectedLength?: number;
  availableLength?: number;
};
```

Example decode result:

```ts
type DecodeResult = {
  value: unknown;
  truncated: boolean;
  checksum: true | false | null;
  holes: Hole[];
  slotGuards?: Record<string, true | false | null>;
  guardIssues?: GuardIssue[];
};
```

If a slot is missing but referenced multiple times, the decoder SHOULD report all affected paths or report a shared-slot hole with path references.

Hole paths use JSON Pointer-style paths. Object keys are appended as `/<key>` and array indexes as `/<index>`, for example `/items/0/name`.

Slot failure rules:

- If zero bytes of a slot are available, report `missing-slot`.
- If some but fewer than the declared byte length are available, report `truncated-slot` and include `availableLength`.
- If the declared byte length is available but the slot cannot be parsed as the expected JSON type, report `invalid-slot`.

## 14. Boolean and Null Recovery

Booleans and null are encoded entirely in the schema.

Example:

```
{@0f@1t@2z}
```

Can recover:

```json
{
  "key0": false,
  "key1": true,
  "key2": null
}
```

even if the value stream is completely missing.

---

## 15. Nested Object Example

Source JSON:

```json
{
  "active": false,
  "attributes": null,
  "block_datetime": "2026-05-20T04:16:35.000Z",
  "block_hash": "0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76",
  "block_number": 25133995,
  "content_sha": "0xa960665f0ca9ab016428ca53a1c82496769f51e119681771b14809557a267f16",
  "content_type": "image/svg+xml",
  "creator": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "current_owner": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "ethscription_number": "15782020",
  "gas_price": 202326009,
  "gas_used": 264160,
  "is_esip8": true,
  "meta": {
    "chain": "ethereum",
    "confirmed": true,
    "indexer": {
      "name": "ethscriptions",
      "version": "1.2.0"
    },
    "network": "mainnet"
  },
  "previous_owner": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "receiver": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "transaction_fee": 53446438537440,
  "transaction_hash": "0xcdba232865e4d010b97928c182e6046212c845a73b5790f0436a3ce4e4dd8db1",
  "transaction_index": 66,
  "transaction_value": 0
}
```

Key dictionary:

```text
active,attributes,block_datetime,block_hash,block_number,content_sha,content_type,creator,current_owner,ethscription_number,gas_price,gas_used,is_esip8,meta,previous_owner,receiver,transaction_fee,transaction_hash,transaction_index,transaction_value,chain,confirmed,indexer,network,name,version
```

Schema tape:

```text
{@0f@1z@2'0_26@3'1_68@4"0_8@5'2_68@6'3_15@7'4_44@8'4_44@9'5_10@A"1_9@B"2_6@Ct@D{@K'6_10@Lt@M{@O'7_15@P'8_7}@N'9_9}@E'4_44@F'4_44@G"3_14@H'A_68@I"4_2@J"5_1}
```

Value stream:

```text
"2026-05-20T04:16:35.000Z""0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76"25133995"0xa960665f0ca9ab016428ca53a1c82496769f51e119681771b14809557a267f16""image/svg+xml""0xdd756238f578440ee0093876f8f07dafacc88b46""15782020"202326009264160"ethereum""ethscriptions""1.2.0""mainnet"53446438537440"0xcdba232865e4d010b97928c182e6046212c845a73b5790f0436a3ce4e4dd8db1"660
```

If the value stream is truncated after the shared owner address slot `'4`, the decoder can still recover all schema-only values (booleans and null), AND all fields referencing `'4`:

```json
{
  "active": false,
  "attributes": null,
  "block_datetime": "2026-05-20T04:16:35.000Z",
  "block_hash": "0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76",
  "block_number": 25133995,
  "content_sha": "0xa960665f0ca9ab016428ca53a1c82496769f51e119681771b14809557a267f16",
  "content_type": "image/svg+xml",
  "creator": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "current_owner": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "is_esip8": true,
  "previous_owner": "0xdd756238f578440ee0093876f8f07dafacc88b46",
  "receiver": "0xdd756238f578440ee0093876f8f07dafacc88b46"
}
```

Missing values are reported as holes.

## 16. Guarded vs Unguarded Mode

HBS3 supports both guarded and unguarded mode.

### Unguarded mode

Wire format still includes `guardsLen`, but it is zero:

```text
hbs3.<integrityHash>.<bodyLen>.<schemaLen>.<keysLen>.0:<T><K><V>
```

Logical body remains `<T><K><G><V>` where `G = ""`.

**Benefits:**

- Smaller output.
- Simpler encoding.
- Good for small objects.
- Good when truncation is unlikely.
- Good when only whole-payload integrity matters.

**Tradeoff:**

- If truncated, recovered slots are parsed but not individually authenticated.

### Guarded mode

Wire format:

```text
hbs3.<integrityHash>.<bodyLen>.<schemaLen>.<keysLen>.<guardsLen>:<T><K><G><V>
```

**Benefits:**

- Recovered slots can be individually verified.
- Better for partial decoding under truncation.
- Better when local trust is needed for recovered values.

**Tradeoff:**

- Adds guard overhead proportional to unique scalar slot count.

## 17. JSON Input Domain

The abstract HBS3 input domain is the JSON data model:

- object with string keys
- dense array
- string
- finite number
- boolean
- null

The root value MUST be an object or array.

Decoded values MUST be representable in the same JSON data model.

When an unrecovered array element has a corresponding hole, the decoded array MUST retain its index using `null` as the JSON placeholder. Object properties whose values are unrecovered MAY be omitted while reporting holes.

HBS3 does not encode host-language object identity, prototypes, classes, dates, maps, sets, undefined values, symbols, BigInts, `NaN`, `Infinity`, or `-Infinity`.

Encoder requirements:

- Object keys MUST be strings and MUST satisfy the strict key grammar from section 5.
- Arrays MUST be dense.
- Object properties and array elements visible to the encoder MUST be own enumerable data properties. Accessor properties MUST be rejected.
- Numbers MUST be finite JSON numbers.
- Sparse arrays MUST be rejected at root and nested positions.
- `undefined`, functions, symbols, symbol-keyed properties, non-enumerable properties, accessor properties, array expando properties, custom array prototypes, BigInt values, dates, class instances, `NaN`, and infinities MUST be rejected.
- Homogeneous object-array table mode MUST only be selected after each row object has passed host-value validation.

TypeScript implementation note:

- The reference TypeScript encoder accepts plain objects whose prototype is `Object.prototype`, and arrays.
- It rejects scalar roots, class instances, `Date` objects, null-prototype objects, sparse arrays, custom array prototypes, accessor properties, `undefined`, functions, symbols, BigInt values, `NaN`, `Infinity`, and `-Infinity`.
- Nested objects are expected to be plain objects in the reference TypeScript implementation.

## 18. Resource Limits and Security Guidance

HBS3 implementations MUST enforce finite resource limits. At minimum:

- Reject decimal length/count fields and decoded references that exceed the implementation's safe integer range.
- Reject decimal length/count fields before numeric conversion when the digit count exceeds the implementation limit.
- Reject schema or input nesting deeper than the implementation limit.
- Avoid allocation or iteration directly proportional to attacker-declared lengths until the envelope, schema, and safe-integer checks have passed.
- Compare valid-shaped integrity and HMAC guard tags using equal-length tag comparison that does not exit on the first differing character.

The reference TypeScript limits are:

- decimal length/count fields: at most 16 decimal digits and safe integer value
- extended references: at most 9 base62 digits and safe integer value
- nesting depth: at most 256 object/array levels

Deployments SHOULD also set an application-level maximum accepted HBS3 input byte length appropriate to their transport and memory budget.

## 19. Non-Goals

HBS3 does not attempt to:

- Support arbitrary binary payloads.
- Replace compression algorithms.
- Encode BigInt as a JSON type.
- Preserve original whitespace or object key order outside canonicalization.
- Accept arbitrary JSON object keys in strict mode.
- Provide confidentiality or encryption.
