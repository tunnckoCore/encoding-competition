#!/usr/bin/env bun

import {
  decodeHbs,
  encodeHbs,
  sliceUtf8,
  slotGuardPreimage,
  utf8ByteLength,
} from "@tunnckocore/hbs";
import type {
  ConformanceVectorSet,
  DecodeResult,
  EnvelopeParts,
  HbsOptions,
  PositiveVector,
  RejectVector,
} from "./types.ts";

const HASH16 = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: false,
} as const satisfies HbsOptions;

const HASH8 = {
  integrity: { algorithm: "sha256", tagLength: 8 },
  guards: false,
} as const satisfies HbsOptions;

const HASH2 = {
  integrity: { algorithm: "sha256", tagLength: 2 },
  guards: false,
} as const satisfies HbsOptions;

const DEFAULT_OPTIONS = {} as const satisfies HbsOptions;

const FULL_HASH = {
  integrity: { algorithm: "sha256", tagLength: 64 },
  guards: false,
} as const satisfies HbsOptions;

const GUARDED_SHA = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "sha256", tagLength: 6 },
} as const satisfies HbsOptions;

const GUARDED_SHORT = {
  integrity: { algorithm: "sha256", tagLength: 12 },
  guards: { algorithm: "sha256", tagLength: 2 },
} as const satisfies HbsOptions;

const INTEGRITY_TAG_TOO_SHORT = {
  integrity: { algorithm: "sha256", tagLength: 1 },
  guards: false,
} as const satisfies HbsOptions;

const GUARD_TAG_TOO_SHORT = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "sha256", tagLength: 1 },
} as const satisfies HbsOptions;

const INTEGRITY_TAG_FRACTIONAL = {
  integrity: { algorithm: "sha256", tagLength: 2.5 },
  guards: false,
} as const satisfies HbsOptions;

const GUARD_TAG_FRACTIONAL = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "sha256", tagLength: 2.5 },
} as const satisfies HbsOptions;

const INTEGRITY_TAG_TOO_LONG = {
  integrity: { algorithm: "sha256", tagLength: 65 },
  guards: false,
} as const satisfies HbsOptions;

const GUARD_TAG_TOO_LONG = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "sha256", tagLength: 65 },
} as const satisfies HbsOptions;

const INTEGRITY_UNKNOWN_ALGORITHM = {
  integrity: { algorithm: "sha512", tagLength: 16 },
  guards: false,
} as unknown as HbsOptions;

const GUARD_UNKNOWN_ALGORITHM = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "sha512", tagLength: 6 },
} as unknown as HbsOptions;

const HMAC_INTEGRITY = {
  integrity: {
    algorithm: "hmac-sha256",
    secret: "hbs3-conformance-integrity-secret",
    tagLength: 20,
  },
  guards: false,
} as const satisfies HbsOptions;

const HMAC_FULL = {
  integrity: {
    algorithm: "hmac-sha256",
    secret: "hbs3-conformance-integrity-secret",
    tagLength: 20,
  },
  guards: {
    algorithm: "hmac-sha256",
    secret: "hbs3-conformance-guard-secret",
    tagLength: 8,
  },
} as const satisfies HbsOptions;

const HMAC_INTEGRITY_WRONG_SECRET = {
  integrity: {
    algorithm: "hmac-sha256",
    secret: "wrong-integrity-secret",
    tagLength: 20,
  },
  guards: false,
} as const satisfies HbsOptions;

const HMAC_WRONG_GUARD_SECRET = {
  integrity: {
    algorithm: "hmac-sha256",
    secret: "hbs3-conformance-integrity-secret",
    tagLength: 20,
  },
  guards: {
    algorithm: "hmac-sha256",
    secret: "wrong-guard-secret",
    tagLength: 8,
  },
} as const satisfies HbsOptions;

const HMAC_INTEGRITY_MISSING_SECRET = {
  integrity: { algorithm: "hmac-sha256", tagLength: 16 },
  guards: false,
} as unknown as HbsOptions;

const HMAC_GUARD_MISSING_SECRET = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "hmac-sha256", tagLength: 8 },
} as unknown as HbsOptions;

const HMAC_INTEGRITY_EMPTY_SECRET = {
  integrity: { algorithm: "hmac-sha256", secret: "", tagLength: 16 },
  guards: false,
} as const satisfies HbsOptions;

const HMAC_GUARD_EMPTY_SECRET = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "hmac-sha256", secret: "", tagLength: 8 },
} as const satisfies HbsOptions;

const positives: PositiveVector[] = [
  roundtrip(
    "object-basic-unguarded",
    "Sorted object keys with booleans, null, number, and string slots.",
    ["object", "key-order", "unguarded", "sha256-integrity"],
    { name: "alice", count: 3, active: false, meta: null },
    HASH16,
  ),
  roundtrip(
    "default-options",
    "Default options produce SHA-256 integrity and no guards.",
    ["defaults", "sha256-integrity", "unguarded"],
    { name: "alice" },
    DEFAULT_OPTIONS,
  ),
  roundtrip(
    "empty-object",
    "Empty object root has an empty key dictionary and value stream.",
    ["object", "empty", "no-slots"],
    {},
    HASH16,
  ),
  roundtrip(
    "empty-array",
    "Empty array root has an empty key dictionary and value stream.",
    ["array", "empty", "no-slots"],
    [],
    HASH16,
  ),
  roundtrip(
    "array-scalar-order",
    "Array order is preserved for mixed scalar elements.",
    ["array", "order", "scalar-slots", "literals"],
    [2, 1, 0, "x", false, null, true],
    HASH16,
  ),
  roundtrip(
    "nested-mixed-objects-arrays",
    "Nested objects and arrays with lexicographic object key traversal.",
    ["object", "array", "nested", "key-order"],
    {
      z: [{ b: 2, a: 1 }],
      a: { deep: [true, null, "leaf"] },
      m: "middle",
    },
    HASH16,
  ),
  roundtrip(
    "deduplicated-scalar-slots",
    "Repeated canonical string and number scalar values share slot ids.",
    ["dedupe", "slot-reuse", "object"],
    { a: "same", b: "same", c: 42, d: 42, e: "same" },
    HASH16,
  ),
  roundtrip(
    "unicode-byte-length",
    "UTF-8 byte length handling for escaped text and non-ASCII scalar values.",
    ["utf8-lengths", "strings", "escapes", "unguarded"],
    { emoji: "😀", escaped: "line\nbreak", plain: "z" },
    HASH16,
  ),
  roundtrip(
    "control-character-escaping",
    "Canonical JSON string escaping for controls, quote, and backslash.",
    ["strings", "escapes", "control-characters"],
    {
      controls: "\u0000\u001f\b\t\n\f\r",
      quoteSlash: '"\\',
    },
    HASH16,
  ),
  roundtrip(
    "reserved-schema-characters-in-string",
    "Reserved schema and section delimiter characters inside strings are sliced only by declared byte length.",
    ["strings", "reserved-characters", "value-stream"],
    { text: "@{}[]'\"_:,\\\n" },
    HASH16,
  ),
  roundtrip(
    "multilingual-unicode-strings",
    "Multi-byte UTF-8 strings across scripts preserve exact scalar content.",
    ["strings", "utf8-lengths", "unicode"],
    { greek: "γειά", japanese: "こんにちは", arabic: "مرحبا", emoji: "🧪" },
    HASH16,
  ),
  roundtrip(
    "empty-string-slot",
    "Empty strings still occupy a two-byte canonical JSON slot.",
    ["strings", "empty-string", "slot-length"],
    { empty: "", nonempty: "x" },
    HASH16,
  ),
  roundtrip(
    "number-canonical-forms",
    "Finite JSON numbers use canonical JavaScript/JCS-compatible spelling.",
    ["numbers", "canonical-json"],
    {
      big: 1e21,
      fractional: -12.5,
      integer: 123,
      small: 0.000001,
      tiny: 1e-7,
      zero: 0,
    },
    HASH16,
  ),
  roundtrip(
    "negative-and-exponent-numbers",
    "Negative integers, negative fractions, and exponent notation survive as JSON numbers.",
    ["numbers", "negative", "exponent"],
    { neg: -1, negFraction: -0.125, exponent: 6200000000000000000000 },
    HASH16,
  ),
  roundtrip(
    "json-safe-integer-boundaries",
    "Large finite JSON integers near the safe-integer boundary keep their canonical spelling.",
    ["numbers", "integer-boundary"],
    { maxSafe: 9007199254740991, minSafe: -9007199254740991 },
    HASH16,
  ),
  roundtrip(
    "json-finite-number-extremes",
    "Finite JSON numbers at JavaScript's positive min/max boundaries keep canonical spelling.",
    ["numbers", "finite-boundary", "canonical-json"],
    { max: Number.MAX_VALUE, min: Number.MIN_VALUE },
    HASH16,
  ),
  roundtrip(
    "strict-key-characters",
    "Strict key grammar accepts selected punctuation and interior spaces.",
    ["keys", "strict-key-grammar", "key-order"],
    {
      "claim id v2": 1,
      "claim@id": 2,
      $schema: "x",
      "a.b-c_$@ 0": true,
      "0": null,
    },
    HASH16,
  ),
  roundtrip(
    "ascii-lexicographic-key-order",
    "ASCII lexicographic key order is visible in the key dictionary.",
    ["keys", "ascii-order", "key-order"],
    { a: 1, A: 2, _: 3, $: 4, "0": 5, z: 6, Z: 7 },
    HASH16,
  ),
  roundtrip(
    "nested-empty-containers",
    "Nested empty objects and arrays are structural schema material with no value stream entries.",
    ["object", "array", "empty", "nested", "no-slots"],
    { a: [], b: {}, c: [{ d: [] }] },
    HASH16,
  ),
  roundtrip(
    "extended-key-and-slot-refs",
    "More than 62 keys and scalar slots force extended reference encoding.",
    ["refs", "extended-refs", "many-keys", "many-slots"],
    manyKeyObject(66),
    HASH16,
  ),
  roundtrip(
    "single-char-ref-boundary",
    "Exactly 62 keys and slots still use single-character z refs, not extended refs.",
    ["refs", "single-char-ref-boundary", "many-keys", "many-slots"],
    manyKeyObject(62),
    HASH16,
  ),
  roundtrip(
    "homogeneous-object-array-table",
    "Homogeneous object array table mode with variable number/string slots and literals.",
    ["array", "table", "variable-slot", "literal"],
    [
      { a: 1, b: "x", ok: true },
      { a: 200, b: "yy", ok: true },
    ],
    HASH16,
  ),
  roundtrip(
    "table-empty-object-rows",
    "Homogeneous arrays of empty objects use zero-column table mode.",
    ["array", "table", "empty", "zero-column"],
    [{}, {}, {}],
    HASH16,
  ),
  roundtrip(
    "table-single-row",
    "A single plain-object row is still eligible for table mode.",
    ["array", "table", "single-row"],
    [{ a: 1, b: "x" }],
    HASH16,
  ),
  roundtrip(
    "table-fixed-slots",
    "Homogeneous table columns use fixed-width descriptors when every encoded slot has the same byte length.",
    ["array", "table", "fixed-slot"],
    [
      { a: 1, b: "x" },
      { a: 2, b: "y" },
      { a: 3, b: "z" },
    ],
    HASH16,
  ),
  roundtrip(
    "table-mixed-fixed-and-variable-columns",
    "One table can combine fixed-width and variable-width scalar columns.",
    ["array", "table", "fixed-slot", "variable-slot"],
    [
      { fixed: "x", variable: "p" },
      { fixed: "y", variable: "qq" },
      { fixed: "z", variable: "rrr" },
    ],
    HASH16,
  ),
  roundtrip(
    "table-nested-node-columns",
    "Homogeneous table columns can contain nested object and array nodes.",
    ["array", "table", "nested", "node-columns"],
    [
      { id: 1, tags: ["a"], meta: { ok: true } },
      { id: 2, tags: ["b", "c"], meta: { ok: false } },
    ],
    HASH16,
  ),
  roundtrip(
    "table-mixed-node-column",
    "Homogeneous table shape with a mixed-type column uses the generic node marker.",
    ["array", "table", "mixed-column"],
    [{ x: "a" }, { x: 1 }, { x: null }],
    HASH16,
  ),
  roundtrip(
    "table-literal-false-null-columns",
    "Table literal columns cover false and null descriptors, not only true.",
    ["array", "table", "literal", "false", "null"],
    [
      { f: false, n: null, x: 1 },
      { f: false, n: null, x: 2 },
    ],
    HASH16,
  ),
  roundtrip(
    "heterogeneous-object-array-fallback",
    "Object arrays with different key sets encode as normal array items, not table mode.",
    ["array", "object", "heterogeneous"],
    [{ a: 1 }, { a: 2, b: 3 }],
    HASH16,
  ),
  roundtrip(
    "full-length-integrity-hash",
    "SHA-256 integrity can use the full 64 hex character digest.",
    ["integrity", "sha256", "tag-length"],
    { hash: "full", n: 64 },
    FULL_HASH,
  ),
  roundtrip(
    "guarded-empty-object",
    "Guarded mode with no scalar slots has an empty guard section.",
    ["guards", "empty", "no-slots"],
    {},
    GUARDED_SHA,
  ),
  roundtrip(
    "guarded-sha256",
    "Public per-slot guards using SHA-256 with six hexadecimal characters.",
    ["guards", "sha256-guards", "slot-guard-preimage"],
    { name: "alice", count: 3 },
    GUARDED_SHA,
  ),
  roundtrip(
    "guarded-reused-slots",
    "Guard count follows unique scalar slot count, not schema reference count.",
    ["guards", "dedupe", "slot-reuse"],
    { a: "same", b: "same", c: 7, d: 7 },
    GUARDED_SHA,
  ),
  roundtrip(
    "hmac-integrity-only",
    "HMAC-SHA256 integrity tag without per-slot guards.",
    ["hmac-integrity", "unguarded"],
    { name: "alice", count: 3 },
    HMAC_INTEGRITY,
  ),
  roundtrip(
    "hmac-integrity-and-guards",
    "HMAC-SHA256 integrity tag and HMAC per-slot guards with explicit secrets.",
    ["hmac-integrity", "hmac-guards", "tag-length"],
    { name: "alice", count: 3 },
    HMAC_FULL,
  ),
];

const encodeVectors: PositiveVector[] = [
  encodeOnly(
    "encode-only-many-string-slot-refs",
    "More than sixty-two distinct string slots force extended string refs without key refs.",
    ["encode-only", "extended-refs", "strings", "array"],
    manyStringArray(70),
    HASH16,
  ),
  encodeOnly(
    "encode-only-many-number-slot-refs",
    "More than sixty-two distinct number slots force extended number refs without key refs.",
    ["encode-only", "extended-refs", "numbers", "array"],
    Array.from({ length: 70 }, (_, index) => index + 0.25),
    HASH16,
  ),
  encodeOnly(
    "encode-only-deep-object-chain",
    "Deep nested object encoding keeps schema refs deterministic.",
    ["encode-only", "object", "nested", "deep"],
    deepObject(12),
    HASH16,
  ),
  encodeOnly(
    "encode-only-deep-array-chain",
    "Deep nested array encoding keeps bracket structure deterministic.",
    ["encode-only", "array", "nested", "deep"],
    deepArray(12),
    HASH16,
  ),
  encodeOnly(
    "encode-only-short-integrity-tag",
    "SHA-256 integrity supports short deterministic tags.",
    ["encode-only", "integrity", "sha256", "short-tag"],
    { tag: "short", n: 8 },
    HASH8,
  ),
  encodeOnly(
    "encode-only-min-integrity-tag",
    "SHA-256 integrity supports the minimum valid two-hex-character tag.",
    ["encode-only", "integrity", "sha256", "min-tag"],
    { tag: "min", n: 2 },
    HASH2,
  ),
  encodeOnly(
    "encode-only-short-guard-tags",
    "Public per-slot guards can use the minimum valid two-hex-character tags.",
    ["encode-only", "guards", "short-tag", "slot-order"],
    { a: "same", b: "same", c: 9, d: 9, e: "other", f: 10 },
    GUARDED_SHORT,
  ),
  encodeOnly(
    "encode-only-hmac-extended-refs-and-guards",
    "HMAC integrity and HMAC guards combine with extended key and slot refs.",
    ["encode-only", "hmac-integrity", "hmac-guards", "extended-refs"],
    manyKeyObject(70),
    HMAC_FULL,
  ),
  encodeOnly(
    "encode-only-default-options-table",
    "Default options can still select table mode for homogeneous array roots.",
    ["encode-only", "defaults", "array", "table"],
    [{ a: 1 }, { a: 2 }],
    DEFAULT_OPTIONS,
  ),
  encodeOnly(
    "encode-only-literal-only-object",
    "Objects containing only true, false, and null have an empty scalar stream.",
    ["encode-only", "object", "literals", "no-slots"],
    { t: true, f: false, n: null },
    HASH16,
  ),
  encodeOnly(
    "encode-only-root-array-mixed-nodes",
    "A root array can mix containers, scalars, and literals without table mode.",
    ["encode-only", "array", "root", "mixed-nodes"],
    [{ a: 1 }, ["x"], true, null, "z"],
    HASH16,
  ),
  encodeOnly(
    "encode-only-single-row-node-table",
    "A single-row table can contain object and array node columns.",
    ["encode-only", "table", "single-row", "node-column"],
    [{ id: 1, meta: { ok: true }, tags: ["a", "b"] }],
    HASH16,
  ),
  encodeOnly(
    "encode-only-table-fixed-empty-string-column",
    "A table column of empty strings uses the fixed-width string descriptor.",
    ["encode-only", "table", "fixed-slot", "empty-string"],
    [{ text: "" }, { text: "" }],
    HASH16,
  ),
  encodeOnly(
    "encode-only-table-empty-array-column",
    "A table column of empty arrays uses the array node marker with empty child schemas.",
    ["encode-only", "table", "node-column", "empty-array"],
    [{ items: [] }, { items: [] }],
    HASH16,
  ),
];

const truncatedBodyFull = encodeHbs(
  { active: true, count: 12345, name: "alice" },
  HASH16,
);
const truncatedBodyParts = splitHbs(truncatedBodyFull);

const truncatedStringFull = encodeHbs({ name: "alice", next: 1 }, HASH16);
const truncatedStringParts = splitHbs(truncatedStringFull);

const truncatedKeyFull = encodeHbs({ a: 1, beta: 2 }, HASH16);
const truncatedKeyParts = splitHbs(truncatedKeyFull);

const guardedFull = encodeHbs({ name: "alice", count: 3 }, GUARDED_SHA);
const guardedParts = splitHbs(guardedFull);
const hmacIntegrityFull = encodeHbs(
  { name: "alice", count: 3 },
  HMAC_INTEGRITY,
);
const hmacGuardedFull = encodeHbs({ name: "alice", count: 3 }, HMAC_FULL);
const missingWholeBodyFull = encodeHbs(
  { active: true, count: 12345, name: "alice" },
  HASH16,
);
const missingWholeBodyParts = splitHbs(missingWholeBodyFull);
const nestedArrayFull = encodeHbs({ items: ["a", "b"] }, HASH16);
const nestedArrayParts = splitHbs(nestedArrayFull);
const validShortGuardFull = makeHbs({
  T: '{@0"0_1}',
  K: "count",
  G: sha256Hex(slotGuardPreimage('"0', 1, "1")).slice(0, 4),
  V: "1",
});
const guardedInvalidNumberSlot = makeHbs({
  T: '{@0"0_4}',
  K: "n",
  G: sha256Hex(slotGuardPreimage('"0', 4, "true")).slice(0, 6),
  V: "true",
});

const decodeVectors: PositiveVector[] = [
  decodeOnly(
    "truncated-value-stream",
    "Truncated body after one complete value slot keeps checksum null and reports a missing slot.",
    ["partial-decode", "truncated-body", "missing-slot"],
    hbsWithBody(
      truncatedBodyFull,
      `${truncatedBodyParts.T}${truncatedBodyParts.K}${sliceUtf8(truncatedBodyParts.V, 0, 5)}`,
    ),
    HASH16,
  ),
  decodeOnly(
    "truncated-string-slot",
    "Truncated string slot reports available byte length.",
    ["partial-decode", "truncated-slot", "available-length"],
    hbsWithBody(
      truncatedStringFull,
      `${truncatedStringParts.T}${truncatedStringParts.K}${sliceUtf8(truncatedStringParts.V, 0, 3)}`,
    ),
    HASH16,
  ),
  decodeOnly(
    "truncated-key-comma-boundary",
    "K truncated exactly after a comma uses only complete key entries and reports missing key/slot holes.",
    ["partial-decode", "truncated-keys", "missing-key"],
    hbsWithBody(truncatedKeyFull, `${truncatedKeyParts.T}a,`),
    HASH16,
  ),
  decodeOnly(
    "truncated-key-final-entry-without-comma",
    "A truncated key dictionary final entry without an observed comma is incomplete.",
    ["partial-decode", "truncated-keys", "missing-key"],
    hbsWithBody(truncatedKeyFull, `${truncatedKeyParts.T}a`),
    HASH16,
  ),
  decodeOnly(
    "missing-entire-value-stream",
    "When V is unavailable, booleans/nulls recover and scalar slots become holes.",
    ["partial-decode", "missing-slot", "schema-literals"],
    hbsWithBody(
      missingWholeBodyFull,
      `${missingWholeBodyParts.T}${missingWholeBodyParts.K}`,
    ),
    HASH16,
  ),
  decodeOnly(
    "nested-array-missing-slot-placeholder",
    "Missing array elements decode as null placeholders while still reporting holes.",
    ["partial-decode", "array", "missing-slot", "json-placeholder"],
    hbsWithBody(
      nestedArrayFull,
      `${nestedArrayParts.T}${nestedArrayParts.K}${sliceUtf8(nestedArrayParts.V, 0, 3)}`,
    ),
    HASH16,
  ),
  decodeOnly(
    "reused-slot-missing-multiple-holes",
    "A missing reused slot reports a hole for every referencing path.",
    ["missing-slot", "slot-reuse", "holes"],
    makeHbs({ T: "{@0'0_3@1'0_3}", K: "a,b" }),
    HASH16,
  ),
  decodeOnly(
    "reused-slot-invalid-multiple-holes",
    "An invalid reused slot reports invalid-slot at every referencing path.",
    ["invalid-slot", "slot-reuse", "holes"],
    makeHbs({ T: '{@0"0_4@1"0_4}', K: "a,b", V: "true" }),
    HASH16,
  ),
  decodeOnly(
    "missing-key-reference",
    "Schema key reference beyond the available dictionary becomes a missing-key hole.",
    ["partial-decode", "missing-key"],
    makeHbs({ T: '{@1"0_1}', K: "a", V: "1" }),
    HASH16,
  ),
  decodeOnly(
    "truncated-guard-section",
    "Truncated guard entry is reported while value stream is unavailable.",
    ["guards", "partial-decode", "truncated-guard"],
    hbsWithBody(
      guardedFull,
      `${guardedParts.T}${guardedParts.K}${sliceUtf8(guardedParts.G, 0, 4)}`,
    ),
    GUARDED_SHA,
  ),
  decodeOnly(
    "truncated-guard-entry-complete-body",
    "A short guard entry in a complete body reports truncated-guard without making the whole decode fail.",
    ["guards", "truncated-guard", "complete-body"],
    validShortGuardFull,
    GUARDED_SHA,
  ),
  decodeOnly(
    "uppercase-guard-entry",
    "Uppercase hexadecimal guard text is invalid because guard entries are lowercase hex.",
    ["guards", "invalid-guard", "lowercase-hex"],
    makeHbs({
      T: guardedParts.T,
      K: guardedParts.K,
      G: guardedParts.G.toUpperCase(),
      V: guardedParts.V,
    }),
    GUARDED_SHA,
  ),
  decodeOnly(
    "missing-guard-entry",
    "Missing guard entry reports guard issue but still decodes available values.",
    ["guards", "missing-guard"],
    makeHbs({
      T: "{@0\"0_1@1'0_7}",
      K: "count,name",
      G: "e98a2f",
      V: '3"alice"',
    }),
    GUARDED_SHA,
  ),
  decodeOnly(
    "invalid-guard-entry",
    "Non-hex guard entry is an invalid guard issue, not a hard decode failure.",
    ["guards", "invalid-guard"],
    makeHbs({ T: '{@0"0_1}', K: "count", G: "zzzzzz", V: "3" }),
    GUARDED_SHA,
  ),
  decodeOnly(
    "extra-guard-entry",
    "Extra guard entries are reported separately.",
    ["guards", "extra-guard"],
    makeHbs({ T: '{@0"0_1}', K: "count", G: "e98a2f,abcdef", V: "3" }),
    GUARDED_SHA,
  ),
  decodeOnly(
    "trailing-comma-guard-entry",
    "A trailing comma in G creates an empty extra guard entry.",
    ["guards", "extra-guard", "empty-guard"],
    makeHbs({
      T: '{@0"0_1}',
      K: "count",
      G: `${sha256Hex(slotGuardPreimage(`"0`, 1, "3")).slice(0, 6)},`,
      V: "3",
    }),
    GUARDED_SHA,
  ),
  decodeOnly(
    "tampered-guarded-body",
    "Full-body tampering gives checksum false and a false slot guard.",
    ["guards", "checksum-false", "slot-guard-false"],
    guardedFull.replace('"alice"', '"blice"'),
    GUARDED_SHA,
  ),
  decodeOnly(
    "tampered-unguarded-body",
    "Full unguarded body tampering gives checksum false but can still decode structurally.",
    ["checksum-false", "unguarded"],
    encodeHbs({ name: "alice" }, HASH16).replace('"alice"', '"blice"'),
    HASH16,
  ),
  decodeOnly(
    "wrong-hmac-integrity-secret",
    "Decoding with the wrong HMAC integrity secret produces checksum false.",
    ["hmac-integrity", "checksum-false"],
    hmacIntegrityFull,
    HMAC_INTEGRITY_WRONG_SECRET,
  ),
  decodeOnly(
    "wrong-hmac-guard-secret",
    "Decoding with the wrong HMAC guard secret produces false slot guard statuses.",
    ["hmac-guards", "slot-guard-false"],
    hmacGuardedFull,
    HMAC_WRONG_GUARD_SECRET,
  ),
  decodeOnly(
    "invalid-number-slot-json",
    "Fully available slot with valid JSON but wrong expected scalar type reports invalid-slot.",
    ["invalid-slot", "number-slot"],
    makeHbs({ T: '{@0"0_4}', K: "n", V: "true" }),
    HASH16,
  ),
  decodeOnly(
    "guarded-invalid-slot-guard-null",
    "A valid-shaped guard for bytes that are not a valid slot value reports a null slot guard.",
    ["guards", "invalid-slot", "slot-guard-null"],
    guardedInvalidNumberSlot,
    GUARDED_SHA,
  ),
  decodeOnly(
    "invalid-string-slot-json",
    "Fully available slot with valid JSON but wrong expected string type reports invalid-slot.",
    ["invalid-slot", "string-slot"],
    makeHbs({ T: "{@0'0_2}", K: "s", V: "42" }),
    HASH16,
  ),
  decodeOnly(
    "noncanonical-number-slot-json",
    "A number slot with non-canonical JSON spelling reports invalid-slot.",
    ["invalid-slot", "canonical-json", "number-slot"],
    makeHbs({ T: '{@0"0_3}', K: "n", V: "1.0" }),
    HASH16,
  ),
  decodeOnly(
    "noncanonical-negative-zero-slot",
    "A number slot spelling negative zero reports invalid-slot.",
    ["invalid-slot", "canonical-json", "number-slot", "negative-zero"],
    makeHbs({ T: '{@0"0_2}', K: "n", V: "-0" }),
    HASH16,
  ),
  decodeOnly(
    "noncanonical-string-slot-json",
    "A string slot with non-canonical escape spelling reports invalid-slot.",
    ["invalid-slot", "canonical-json", "string-slot"],
    makeHbs({ T: "{@0'0_8}", K: "s", V: '"\\u0061"' }),
    HASH16,
  ),
  decodeOnly(
    "nonfinite-number-slot-json",
    "A non-finite number spelling is not valid canonical JSON and reports invalid-slot.",
    ["invalid-slot", "canonical-json", "number-slot", "non-finite"],
    makeHbs({ T: '{@0"0_8}', K: "n", V: "Infinity" }),
    HASH16,
  ),
  decodeOnly(
    "malformed-number-slot-json",
    "Fully available number slot with malformed JSON reports invalid-slot.",
    ["invalid-slot", "number-slot", "malformed-json"],
    makeHbs({ T: '{@0"0_2}', K: "n", V: "01" }),
    HASH16,
  ),
  decodeOnly(
    "malformed-string-slot-json",
    "Fully available string slot with malformed JSON reports invalid-slot.",
    ["invalid-slot", "string-slot", "malformed-json"],
    makeHbs({ T: "{@0'0_2}", K: "s", V: '"x' }),
    HASH16,
  ),
  decodeOnly(
    "zero-length-number-slot",
    "A structurally valid zero-length number slot cannot parse as JSON and reports invalid-slot.",
    ["invalid-slot", "zero-length-slot", "number-slot"],
    makeHbs({ T: '{@0"0_0}', K: "n" }),
    HASH16,
  ),
  decodeOnly(
    "zero-length-string-slot",
    "A structurally valid zero-length string slot cannot parse as JSON and reports invalid-slot.",
    ["invalid-slot", "zero-length-slot", "string-slot"],
    makeHbs({ T: "{@0'0_0}", K: "s" }),
    HASH16,
  ),
];

const rejects: RejectVector[] = [
  rejectEncode(
    "reject-encode-string-root",
    "String roots are outside the HBS3 JSON input domain.",
    "not-a-root-container",
    HASH16,
    "root",
  ),
  rejectEncode(
    "reject-encode-number-root",
    "Number roots are outside the HBS3 JSON input domain.",
    1,
    HASH16,
    "root",
  ),
  rejectEncode(
    "reject-encode-null-root",
    "Null roots are outside the HBS3 JSON input domain.",
    null,
    HASH16,
    "root",
  ),
  rejectEncode(
    "reject-encode-true-root",
    "Boolean roots are outside the HBS3 JSON input domain.",
    true,
    HASH16,
    "root",
  ),
  rejectEncode(
    "reject-encode-false-root",
    "Boolean roots are outside the HBS3 JSON input domain.",
    false,
    HASH16,
    "root",
  ),
  rejectEncode(
    "reject-encode-invalid-key-slash",
    "Strict keys cannot contain slash characters.",
    { "bad/key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-leading-at",
    "Strict keys cannot start with @.",
    { "@bad": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-empty",
    "Strict keys cannot be empty strings.",
    { "": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-leading-space",
    "Strict keys cannot start with a space.",
    { " bad": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-trailing-space",
    "Strict keys cannot end with a space.",
    { "bad ": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-consecutive-spaces",
    "Strict keys cannot contain consecutive spaces.",
    { "bad  key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-tab",
    "Strict keys cannot contain tab characters.",
    { "bad\tkey": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-newline",
    "Strict keys cannot contain newline characters.",
    { "bad\nkey": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-comma",
    "Strict keys cannot contain comma characters.",
    { "bad,key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-colon",
    "Strict keys cannot contain colon characters.",
    { "bad:key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-open-brace",
    "Strict keys cannot contain open brace characters.",
    { "bad{key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-close-brace",
    "Strict keys cannot contain close brace characters.",
    { "bad}key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-open-bracket",
    "Strict keys cannot contain open bracket characters.",
    { "bad[key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-close-bracket",
    "Strict keys cannot contain close bracket characters.",
    { "bad]key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-quote",
    "Strict keys cannot contain quote characters.",
    { 'bad"key': 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-backslash",
    "Strict keys cannot contain backslash characters.",
    { "bad\\key": 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-unicode",
    "Strict keys are ASCII-only.",
    { café: 1 },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-nested",
    "Strict key validation applies recursively.",
    { ok: { "bad/key": 1 } },
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-invalid-key-table-row",
    "Strict key validation applies inside table rows.",
    [{ ok: 1, "bad/key": 2 }],
    HASH16,
    "key",
  ),
  rejectEncode(
    "reject-encode-hmac-integrity-missing-secret",
    "HMAC integrity requires a secret when encoding.",
    { name: "alice" },
    HMAC_INTEGRITY_MISSING_SECRET,
    "secret",
  ),
  rejectEncode(
    "reject-encode-hmac-guard-missing-secret",
    "HMAC guards require a secret when encoding scalar slots.",
    { name: "alice" },
    HMAC_GUARD_MISSING_SECRET,
    "secret",
  ),
  rejectEncode(
    "reject-encode-hmac-integrity-empty-secret",
    "HMAC integrity requires a non-empty secret when encoding.",
    { name: "alice" },
    HMAC_INTEGRITY_EMPTY_SECRET,
    "secret",
  ),
  rejectEncode(
    "reject-encode-hmac-guard-empty-secret",
    "HMAC guards require a non-empty secret when encoding scalar slots.",
    { name: "alice" },
    HMAC_GUARD_EMPTY_SECRET,
    "secret",
  ),
  rejectEncode(
    "reject-encode-integrity-tag-too-short",
    "Integrity tagLength must be at least two hex characters.",
    { name: "alice" },
    INTEGRITY_TAG_TOO_SHORT,
    "tagLength",
  ),
  rejectEncode(
    "reject-encode-guard-tag-too-short",
    "Guard tagLength must be at least two hex characters.",
    { name: "alice" },
    GUARD_TAG_TOO_SHORT,
    "tagLength",
  ),
  rejectEncode(
    "reject-encode-integrity-tag-fractional",
    "Integrity tagLength must be an integer.",
    { name: "alice" },
    INTEGRITY_TAG_FRACTIONAL,
    "tagLength",
  ),
  rejectEncode(
    "reject-encode-guard-tag-fractional",
    "Guard tagLength must be an integer.",
    { name: "alice" },
    GUARD_TAG_FRACTIONAL,
    "tagLength",
  ),
  rejectEncode(
    "reject-encode-integrity-tag-too-long",
    "Integrity tagLength cannot exceed the SHA-256 hex digest length.",
    { name: "alice" },
    INTEGRITY_TAG_TOO_LONG,
    "tagLength",
  ),
  rejectEncode(
    "reject-encode-guard-tag-too-long",
    "Guard tagLength cannot exceed the SHA-256 hex digest length.",
    { name: "alice" },
    GUARD_TAG_TOO_LONG,
    "tagLength",
  ),
  rejectEncode(
    "reject-encode-integrity-algorithm-unknown",
    "Unknown integrity algorithms are rejected at runtime.",
    { name: "alice" },
    INTEGRITY_UNKNOWN_ALGORITHM,
    "algorithm",
  ),
  rejectEncode(
    "reject-encode-guard-algorithm-unknown",
    "Unknown guard algorithms are rejected at runtime.",
    { name: "alice" },
    GUARD_UNKNOWN_ALGORITHM,
    "algorithm",
  ),
  rejectDecode(
    "reject-decode-invalid-prefix",
    "Only hbs3 prefix is valid.",
    "hbs4.abc.0.0.0.0:",
    HASH16,
    "header",
  ),
  rejectDecode(
    "reject-decode-invalid-header",
    "Header must contain integrity plus four length fields.",
    "hbs3.abc.0.0.0:",
    HASH16,
    "header",
  ),
  rejectDecode(
    "reject-decode-leading-zero-length",
    "Canonical unsigned decimal length fields forbid leading zeroes.",
    "hbs3.abc.01.0.0.0:",
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-leading-zero-schema-length",
    "Canonical schemaLen forbids leading zeroes.",
    "hbs3.abc.1.01.0.0:{}",
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-leading-zero-keys-length",
    "Canonical keysLen forbids leading zeroes.",
    "hbs3.abc.1.0.01.0:x",
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-leading-zero-guards-length",
    "Canonical guardsLen forbids leading zeroes.",
    "hbs3.abc.1.0.0.01:x",
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-nondigit-body-length",
    "Length fields must contain only decimal digits.",
    "hbs3.abc.x.0.0.0:",
    HASH16,
    "header",
  ),
  rejectDecode(
    "reject-decode-empty-integrity-field",
    "The integrity field must be present.",
    "hbs3..0.0.0.0:",
    HASH16,
    "header",
  ),
  rejectDecode(
    "reject-decode-length-sum-exceeds-body",
    "schemaLen + keysLen + guardsLen cannot exceed bodyLen.",
    "hbs3.abc.1.1.1.0:",
    HASH16,
    "exceed",
  ),
  rejectDecode(
    "reject-decode-body-too-long",
    "Available body longer than bodyLen is a malformed envelope.",
    "hbs3.abc.0.0.0.0:x",
    HASH16,
    "body length",
  ),
  rejectDecode(
    "reject-decode-schema-truncated",
    "A body shorter than schemaLen is structurally undecodable.",
    hbsWithBody(makeHbs({ T: "{}" }), "{"),
    HASH16,
    "schema",
  ),
  rejectDecode(
    "reject-decode-scalar-root-schema",
    "Scalar root schema is not a valid HBS3 root.",
    makeHbs({ T: "z" }),
    HASH16,
    "root",
  ),
  rejectDecode(
    "reject-decode-unclosed-object-schema",
    "Unclosed object in schema tape is a hard schema failure.",
    makeHbs({ T: "{@0z", K: "a" }),
    HASH16,
    "closed",
  ),
  rejectDecode(
    "reject-decode-trailing-schema-data",
    "Trailing schema data after the root value is malformed.",
    makeHbs({ T: "{}z" }),
    HASH16,
    "trailing",
  ),
  rejectDecode(
    "reject-decode-duplicate-key-dictionary-entry",
    "Duplicate key dictionary entries are malformed.",
    makeHbs({ T: "{}", K: "a,a" }),
    HASH16,
    "duplicate",
  ),
  rejectDecode(
    "reject-decode-noncanonical-key-dictionary-order",
    "A complete key dictionary must match canonical first-encounter order.",
    makeHbs({ T: "{@1z@0z}", K: "b,a" }),
    HASH16,
    "canonical",
  ),
  rejectDecode(
    "reject-decode-unreferenced-extra-key-dictionary-entry",
    "A complete key dictionary cannot contain unreferenced extra entries.",
    makeHbs({ T: "{}", K: "unused" }),
    HASH16,
    "canonical",
  ),
  rejectDecode(
    "reject-decode-noncanonical-object-entry-order",
    "Object entries must appear in canonical sorted key order.",
    makeHbs({ T: "{@1z@0z}", K: "a,b" }),
    HASH16,
    "canonical",
  ),
  rejectDecode(
    "reject-decode-noncanonical-table-column-order",
    "Table column descriptors must follow the shared canonical sorted key list.",
    makeHbs({ T: "[~2.1:@1z@0z:]", K: "a,b" }),
    HASH16,
    "canonical",
  ),
  rejectDecode(
    "reject-decode-malformed-key-dictionary-entry",
    "Key dictionary entries must satisfy strict key grammar.",
    makeHbs({ T: "{}", K: "bad/key" }),
    HASH16,
    "key",
  ),
  rejectDecode(
    "reject-decode-leading-comma-key-dictionary",
    "A complete key dictionary cannot start with a comma separator.",
    makeHbs({ T: "{}", K: ",a" }),
    HASH16,
    "key",
  ),
  rejectDecode(
    "reject-decode-trailing-comma-key-dictionary",
    "A complete key dictionary cannot end with a comma separator.",
    makeHbs({ T: "{}", K: "a," }),
    HASH16,
    "key",
  ),
  rejectDecode(
    "reject-decode-consecutive-comma-key-dictionary",
    "A complete key dictionary cannot contain empty entries.",
    makeHbs({ T: "{}", K: "a,,b" }),
    HASH16,
    "key",
  ),
  rejectDecode(
    "reject-decode-malformed-extended-ref",
    "Extended refs must be canonical and at least two base62 digits.",
    makeHbs({ T: "{@{0}z}" }),
    HASH16,
    "ref",
  ),
  rejectDecode(
    "reject-decode-extended-ref-leading-zero",
    "Extended refs must not contain leading zeroes.",
    makeHbs({ T: "{@{010}z}" }),
    HASH16,
    "ref",
  ),
  rejectDecode(
    "reject-decode-extended-ref-unsafe-integer",
    "Extended refs must decode to safe integer indexes.",
    makeHbs({ T: "{@{zzzzzzzzzz}z}" }),
    HASH16,
    "safe integer",
  ),
  rejectDecode(
    "reject-decode-header-length-too-many-digits",
    "Header lengths must be bounded before numeric conversion.",
    `hbs3.${"0".repeat(16)}.${"9".repeat(17)}.0.0.0:`,
    HASH16,
    "safe integer",
  ),
  rejectDecode(
    "reject-decode-invalid-single-char-ref",
    "Single-character refs must be base62.",
    makeHbs({ T: "{@!z}" }),
    HASH16,
    "ref",
  ),
  rejectDecode(
    "reject-decode-conflicting-slot-declaration",
    "A reused slot id cannot declare conflicting lengths.",
    makeHbs({ T: "['0_1'0_2]", V: "12" }),
    HASH16,
    "conflicting",
  ),
  rejectDecode(
    "reject-decode-missing-slot-length-separator",
    "Scalar slot schema tokens require an underscore length separator.",
    makeHbs({ T: "{@0'0}", K: "s" }),
    HASH16,
    "separator",
  ),
  rejectDecode(
    "reject-decode-noncanonical-slot-length",
    "Schema slot lengths must be canonical unsigned decimal integers.",
    makeHbs({ T: '{@0"0_01}', K: "n", V: "1" }),
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-slot-length-unsafe-integer",
    "Schema slot lengths must fit in a safe integer.",
    makeHbs({ T: '{@0"0_9007199254740992}', K: "n" }),
    HASH16,
    "safe integer",
  ),
  rejectDecode(
    "reject-decode-slot-length-too-many-digits",
    "Schema slot lengths must be bounded before numeric conversion.",
    makeHbs({ T: `{@0"0_${"9".repeat(17)}}`, K: "n" }),
    HASH16,
    "safe integer",
  ),
  rejectDecode(
    "reject-decode-trailing-value-stream",
    "Value stream bytes beyond declared slot lengths are malformed.",
    makeHbs({ T: '{@0"0_1}', K: "n", V: "12" }),
    HASH16,
    "value stream",
  ),
  rejectDecode(
    "reject-decode-split-multibyte-utf8-slot-boundary",
    "Slot lengths that split a multi-byte UTF-8 scalar are malformed.",
    makeHbs({ T: "{@0'0_1@1'1_3}", K: "a,b", V: "😀" }),
    HASH16,
    "UTF-8 boundary",
  ),
  rejectDecode(
    "reject-decode-duplicate-object-key-ref",
    "Object schema entries cannot reuse the same key ref.",
    makeHbs({ T: "{@0t@0f}", K: "x" }),
    HASH16,
    "duplicate",
  ),
  rejectDecode(
    "reject-decode-table-duplicate-column-key-ref",
    "Table column descriptors cannot reuse the same key ref.",
    makeHbs({ T: "[~2.1:@0t@0f:]", K: "x" }),
    HASH16,
    "duplicate",
  ),
  rejectDecode(
    "reject-decode-table-key-count-unsafe-integer",
    "Table key count must fit in a safe integer.",
    makeHbs({ T: "[~9007199254740992.0::]" }),
    HASH16,
    "safe integer",
  ),
  rejectDecode(
    "reject-decode-table-row-count-unsafe-integer",
    "Table row count must fit in a safe integer.",
    makeHbs({ T: "[~1.9007199254740992:@0t:]", K: "x" }),
    HASH16,
    "safe integer",
  ),
  rejectDecode(
    "reject-decode-table-column-length-too-many-digits",
    "Fixed table column slot lengths must be bounded before numeric conversion.",
    makeHbs({ T: `[~1.0:@0'${"9".repeat(17)}:]`, K: "a" }),
    HASH16,
    "safe integer",
  ),
  rejectDecode(
    "reject-decode-table-object-column-scalar-cell",
    "Object table columns must contain object cells.",
    makeHbs({ T: '[~1.1:@0{:"0_1]', K: "x", V: "1" }),
    HASH16,
    "object column",
  ),
  rejectDecode(
    "reject-decode-table-array-column-object-cell",
    "Array table columns must contain array cells.",
    makeHbs({ T: "[~1.1:@0[:{}]", K: "x" }),
    HASH16,
    "array column",
  ),
  rejectDecode(
    "reject-decode-invalid-schema-marker",
    "Reserved or unknown schema marker is malformed.",
    makeHbs({ T: "x" }),
    HASH16,
    "schema",
  ),
  rejectDecode(
    "reject-decode-hmac-integrity-missing-secret",
    "HMAC integrity requires a secret when decoding.",
    makeHbs({ T: "{}", tagLength: 16 }),
    HMAC_INTEGRITY_MISSING_SECRET,
    "secret",
  ),
  rejectDecode(
    "reject-decode-hmac-guard-missing-secret",
    "HMAC guards require a secret when verifying guards.",
    encodeHbs({ name: "alice" }, GUARDED_SHA),
    HMAC_GUARD_MISSING_SECRET,
    "secret",
  ),
  rejectDecode(
    "reject-decode-integrity-tag-too-short",
    "Integrity tagLength must be at least two hex characters when decoding.",
    encodeHbs({ name: "alice" }, HASH16),
    INTEGRITY_TAG_TOO_SHORT,
    "tagLength",
  ),
  rejectDecode(
    "reject-decode-guard-tag-too-short",
    "Guard tagLength must be at least two hex characters when decoding.",
    encodeHbs({ name: "alice" }, GUARDED_SHA),
    GUARD_TAG_TOO_SHORT,
    "tagLength",
  ),
  rejectDecode(
    "reject-decode-integrity-tag-fractional",
    "Integrity tagLength must be an integer when decoding.",
    encodeHbs({ name: "alice" }, HASH16),
    INTEGRITY_TAG_FRACTIONAL,
    "tagLength",
  ),
  rejectDecode(
    "reject-decode-guard-tag-fractional",
    "Guard tagLength must be an integer when decoding.",
    encodeHbs({ name: "alice" }, GUARDED_SHA),
    GUARD_TAG_FRACTIONAL,
    "tagLength",
  ),
  rejectDecode(
    "reject-decode-integrity-tag-too-long",
    "Integrity tagLength cannot exceed the SHA-256 hex digest length when decoding.",
    encodeHbs({ name: "alice" }, HASH16),
    INTEGRITY_TAG_TOO_LONG,
    "tagLength",
  ),
  rejectDecode(
    "reject-decode-integrity-field-wrong-length",
    "The integrity field length must match the configured tagLength.",
    hbsWithIntegrity(encodeHbs({ name: "alice" }, HASH16), "f".repeat(15)),
    HASH16,
    "integrity",
  ),
  rejectDecode(
    "reject-decode-integrity-field-non-hex",
    "The integrity field must be lowercase hexadecimal.",
    hbsWithIntegrity(encodeHbs({ name: "alice" }, HASH16), "g".repeat(16)),
    HASH16,
    "integrity",
  ),
  rejectDecode(
    "reject-decode-guard-tag-too-long",
    "Guard tagLength cannot exceed the SHA-256 hex digest length when decoding.",
    encodeHbs({ name: "alice" }, GUARDED_SHA),
    GUARD_TAG_TOO_LONG,
    "tagLength",
  ),
  rejectDecode(
    "reject-decode-integrity-algorithm-unknown",
    "Unknown integrity algorithms are rejected at runtime when decoding.",
    encodeHbs({ name: "alice" }, HASH16),
    INTEGRITY_UNKNOWN_ALGORITHM,
    "algorithm",
  ),
  rejectDecode(
    "reject-decode-guard-algorithm-unknown",
    "Unknown guard algorithms are rejected at runtime when decoding.",
    encodeHbs({ name: "alice" }, GUARDED_SHA),
    GUARD_UNKNOWN_ALGORITHM,
    "algorithm",
  ),
  rejectDecode(
    "reject-decode-truncated-hmac-integrity-missing-secret",
    "HMAC integrity secret requirements are validated even when the body is truncated.",
    hbsWithBody(encodeHbs({ name: "alice" }, HASH16), ""),
    HMAC_INTEGRITY_MISSING_SECRET,
    "secret",
  ),
  rejectDecode(
    "reject-decode-truncated-integrity-tag-too-short",
    "Integrity tagLength requirements are validated even when the body is truncated.",
    hbsWithBody(encodeHbs({ name: "alice" }, HASH16), ""),
    INTEGRITY_TAG_TOO_SHORT,
    "tagLength",
  ),
  rejectDecode(
    "reject-decode-object-entry-missing-key-ref",
    "Object entries must start with @ key references.",
    makeHbs({ T: "{z}" }),
    HASH16,
    "key ref",
  ),
  rejectDecode(
    "reject-decode-unclosed-array-schema",
    "Arrays must be closed.",
    makeHbs({ T: "[z" }),
    HASH16,
    "closed",
  ),
  rejectDecode(
    "reject-decode-table-key-count-leading-zero",
    "Table column counts must be canonical decimal integers.",
    makeHbs({ T: "[~01.0::]" }),
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-table-row-count-leading-zero",
    "Table row counts must be canonical decimal integers.",
    makeHbs({ T: "[~0.01::]" }),
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-table-fixed-column-length-leading-zero",
    "Fixed table column slot lengths must be canonical decimal integers.",
    makeHbs({ T: "[~1.0:@0'01:]", K: "a" }),
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-table-variable-cell-length-leading-zero",
    "Variable table cell slot lengths must be canonical decimal integers.",
    makeHbs({ T: "[~1.1:@0':0_03;]", K: "a", V: '"x"' }),
    HASH16,
    "non-canonical",
  ),
  rejectDecode(
    "reject-decode-table-header-separator-missing",
    "Table schema requires a header separator after row count.",
    makeHbs({ T: "[~0.0;:]" }),
    HASH16,
    "separator",
  ),
  rejectDecode(
    "reject-decode-table-body-separator-missing",
    "Table schema requires a body separator after column descriptors.",
    makeHbs({ T: "[~0.0:]" }),
    HASH16,
    "separator",
  ),
  rejectDecode(
    "reject-decode-table-not-closed",
    "Table schemas must be closed by the enclosing array.",
    makeHbs({ T: "[~0.0::" }),
    HASH16,
    "closed",
  ),
  rejectDecode(
    "reject-decode-table-invalid-column-marker",
    "Table column markers must be slot, literal, object, array, or generic node markers.",
    makeHbs({ T: "[~1.0:@0?:]", K: "a" }),
    HASH16,
    "marker",
  ),
  rejectDecode(
    "reject-decode-table-variable-cell-missing-terminator",
    "Variable table cell lengths must end with a semicolon.",
    makeHbs({ T: "[~1.1:@0':0_3]", K: "a", V: '"x"' }),
    HASH16,
    "terminator",
  ),
  rejectDecode(
    "reject-decode-table-row-cell-missing",
    "A table declaring more rows than available cells is malformed.",
    makeHbs({ T: "[~1.2:@0':0_3;]", K: "a", V: '"x"' }),
    HASH16,
    "ref",
  ),
  rejectDecode(
    "reject-decode-table-fixed-cell-missing-ref",
    "A fixed table cell must contain a slot reference.",
    makeHbs({ T: "[~1.1:@0'3:]", K: "a" }),
    HASH16,
    "ref",
  ),
  rejectDecode(
    "reject-decode-nesting-depth-limit",
    "Decoders must reject schema nesting deeper than the implementation limit.",
    makeHbs({ T: `${"[".repeat(258)}z${"]".repeat(258)}` }),
    HASH16,
    "nesting",
  ),
];

const vectorSet: ConformanceVectorSet = {
  format: "hbs3-conformance-v1",
  spec: "HBS3 draft",
  generatedBy: "@tunnckocore/hbs",
  notes: [
    "All length fields are UTF-8 byte counts.",
    "integrityHash commits to <bodyLen>.<schemaLen>.<keysLen>.<guardsLen>:<body>.",
    "The Bun conformance CLI can run external encode/decode commands against every vector.",
  ],
  commandContract: {
    encode: {
      stdin: {
        id: "vector id",
        options: "HBS3 encode options",
        input: "JSON input to encode",
      },
      stdout: "HBS3 text",
    },
    decode: {
      stdin: {
        id: "vector id",
        options: "HBS3 decode options",
        hbs: "HBS3 text",
      },
      stdout: "DecodeResult JSON",
    },
    expectedFailure:
      "Exit non-zero and write an error message to stderr/stdout.",
  },
  vectors: [...positives, ...encodeVectors, ...decodeVectors],
  rejects,
};

await Bun.write(
  new URL("./vectors.json", import.meta.url),
  `${JSON.stringify(vectorSet, null, 2)}\n`,
);

console.log(
  `generated ${vectorSet.vectors.length} positive and ${vectorSet.rejects.length} reject HBS3 conformance vectors`,
);

function roundtrip(
  id: string,
  description: string,
  features: string[],
  input: unknown,
  options: HbsOptions,
): PositiveVector {
  const hbs = encodeHbs(input, options);

  return {
    id,
    kind: "roundtrip",
    description,
    features,
    options,
    input,
    hbs,
    envelope: splitHbs(hbs),
    expectedDecode: decodeHbs(hbs, options) as DecodeResult,
  };
}

function encodeOnly(
  id: string,
  description: string,
  features: string[],
  input: unknown,
  options: HbsOptions,
): PositiveVector {
  const hbs = encodeHbs(input, options);

  return {
    id,
    kind: "encode",
    description,
    features,
    options,
    input,
    hbs,
    envelope: splitHbs(hbs),
  };
}

function decodeOnly(
  id: string,
  description: string,
  features: string[],
  hbs: string,
  options: HbsOptions,
): PositiveVector {
  return {
    id,
    kind: "decode",
    description,
    features,
    options,
    hbs,
    envelope: splitHbs(hbs),
    expectedDecode: decodeHbs(hbs, options) as DecodeResult,
  };
}

function rejectEncode(
  id: string,
  description: string,
  input: unknown,
  options: HbsOptions,
  expectedError: string,
): RejectVector {
  return {
    id,
    kind: "reject-encode",
    description,
    options,
    input,
    expectedError,
  };
}

function rejectDecode(
  id: string,
  description: string,
  hbs: string,
  options: HbsOptions,
  expectedError: string,
): RejectVector {
  return {
    id,
    kind: "reject-decode",
    description,
    options,
    hbs,
    expectedError,
  };
}

function splitHbs(hbs: string): EnvelopeParts {
  const match = /^hbs3\.([^.]+)\.(\d+)\.(\d+)\.(\d+)\.(\d+):(.*)$/s.exec(hbs);

  if (!match) {
    throw new Error(`bad HBS3 text: ${hbs}`);
  }

  const [
    ,
    integrityHash,
    bodyLenRaw,
    schemaLenRaw,
    keysLenRaw,
    guardsLenRaw,
    body,
  ] = match as RegExpExecArray &
    [string, string, string, string, string, string, string];
  const bodyLen = Number(bodyLenRaw);
  const schemaLen = Number(schemaLenRaw);
  const keysLen = Number(keysLenRaw);
  const guardsLen = Number(guardsLenRaw);

  return {
    integrityHash,
    bodyLen,
    schemaLen,
    keysLen,
    guardsLen,
    body,
    T: sliceUtf8(body, 0, schemaLen),
    K: sliceUtf8(body, schemaLen, schemaLen + keysLen),
    G: sliceUtf8(body, schemaLen + keysLen, schemaLen + keysLen + guardsLen),
    V: sliceUtf8(body, schemaLen + keysLen + guardsLen),
    payload: `${bodyLen}.${schemaLen}.${keysLen}.${guardsLen}:${body}`,
  };
}

function makeHbs(args: {
  T: string;
  K?: string;
  G?: string;
  V?: string;
  tagLength?: number;
}): string {
  const { T, K = "", G = "", V = "", tagLength = 16 } = args;
  const body = `${T}${K}${G}${V}`;
  const payload = `${utf8ByteLength(body)}.${utf8ByteLength(T)}.${utf8ByteLength(K)}.${utf8ByteLength(G)}:${body}`;
  const tag = sha256Hex(payload).slice(0, tagLength);

  return `hbs3.${tag}.${payload}`;
}

function hbsWithBody(fullHbs: string, body: string): string {
  return `${fullHbs.slice(0, fullHbs.indexOf(":") + 1)}${body}`;
}

function hbsWithIntegrity(fullHbs: string, integrity: string): string {
  return fullHbs.replace(/^hbs3\.[^.]+\./, `hbs3.${integrity}.`);
}

function sha256Hex(input: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex");
}

function manyKeyObject(count: number): Record<string, unknown> {
  const out: Record<string, unknown> = {};

  for (let index = count - 1; index >= 0; index -= 1) {
    out[`k${index.toString().padStart(2, "0")}`] = `v${index
      .toString()
      .padStart(2, "0")}`;
  }

  return out;
}

function manyStringArray(count: number): string[] {
  return Array.from(
    { length: count },
    (_, index) => `s${index.toString().padStart(2, "0")}`,
  );
}

function deepObject(depth: number): unknown {
  let value: unknown = "leaf";

  for (let index = depth; index >= 1; index -= 1) {
    value = { [`k${index}`]: value };
  }

  return value;
}

function deepArray(depth: number): unknown {
  let value: unknown = "leaf";

  for (let index = 0; index < depth; index += 1) {
    value = [value];
  }

  return value;
}
