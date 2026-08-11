import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vite-plus/test";

import {
  createHbs,
  decodeHbs,
  decodeRef,
  encodeHbs,
  encodeRef,
  isValidHbsKey,
  sliceUtf8,
  slotGuardPreimage,
  utf8ByteLength,
  type SlotRef,
} from "../src/index.ts";

/**
 * HBS3 TDD test suite.
 *
 * Assumed public API:
 *
 *   encodeHbs(value, options) -> string
 *   decodeHbs(token, options) -> DecodeResult
 *   isValidHbsKey(key) -> boolean
 *   encodeRef(index) -> string
 *   decodeRef(ref) -> number
 *
 * Adjust only the import path/names if your implementation uses different names.
 */

type IntegrityStatus = true | false | null;
type SlotGuardStatus = true | false | null;

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

type GuardIssue = {
  index: number;
  kind: "missing-guard" | "truncated-guard" | "invalid-guard" | "extra-guard";
  slot?: string;
  expectedLength?: number;
  availableLength?: number;
};

type DecodeResult = {
  value: unknown;
  truncated: boolean;
  checksum: IntegrityStatus;
  holes: Hole[];
  slotGuards?: Record<string, SlotGuardStatus>;
  guardIssues?: GuardIssue[];
};

const HASH16_OPTIONS = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: false,
} as const;

const GUARDED_HASH16_OPTIONS = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: { algorithm: "sha256", tagLength: 6 },
} as const;

const HMAC16_OPTIONS = {
  integrity: {
    algorithm: "hmac-sha256",
    secret: "hbs3-test-secret",
    tagLength: 16,
  },
  guards: false,
} as const;

const HMAC16_WRONG_SECRET_OPTIONS = {
  integrity: {
    algorithm: "hmac-sha256",
    secret: "wrong-secret",
    tagLength: 16,
  },
  guards: false,
} as const;

const HMAC_GUARDED_HASH16_OPTIONS = {
  integrity: { algorithm: "sha256", tagLength: 16 },
  guards: {
    algorithm: "hmac-sha256",
    secret: "hbs3-guard-secret",
    tagLength: 8,
  },
} as const;

const OWNER = "0xdd756238f578440ee0093876f8f07dafacc88b46";

const FIXTURE = {
  active: false,
  attributes: null,
  block_datetime: "2026-05-20T04:16:35.000Z",
  block_hash:
    "0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76",
  block_number: 25133995,
  content_sha:
    "0xa960665f0ca9ab016428ca53a1c82496769f51e119681771b14809557a267f16",
  content_type: "image/svg+xml",
  creator: OWNER,
  current_owner: OWNER,
  ethscription_number: "15782020",
  gas_price: 202326009,
  gas_used: 264160,
  is_esip8: true,
  meta: {
    chain: "ethereum",
    confirmed: true,
    indexer: {
      name: "ethscriptions",
      version: "1.2.0",
    },
    network: "mainnet",
  },
  previous_owner: OWNER,
  receiver: OWNER,
  transaction_fee: 53446438537440,
  transaction_hash:
    "0xcdba232865e4d010b97928c182e6046212c845a73b5790f0436a3ce4e4dd8db1",
  transaction_index: 66,
  transaction_value: 0,
} as const;

const FIXTURE_K =
  "active,attributes,block_datetime,block_hash,block_number,content_sha,content_type,creator,current_owner,ethscription_number,gas_price,gas_used,is_esip8,meta,previous_owner,receiver,transaction_fee,transaction_hash,transaction_index,transaction_value,chain,confirmed,indexer,network,name,version";

const FIXTURE_T = `{@0f@1z@2'0_26@3'1_68@4"0_8@5'2_68@6'3_15@7'4_44@8'4_44@9'5_10@A"1_9@B"2_6@Ct@D{@K'6_10@Lt@M{@O'7_15@P'8_7}@N'9_9}@E'4_44@F'4_44@G"3_14@H'A_68@I"4_2@J"5_1}`;

const FIXTURE_V =
  `"2026-05-20T04:16:35.000Z"` +
  `"0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76"` +
  `25133995` +
  `"0xa960665f0ca9ab016428ca53a1c82496769f51e119681771b14809557a267f16"` +
  `"image/svg+xml"` +
  `"${OWNER}"` +
  `"15782020"` +
  `202326009` +
  `264160` +
  `"ethereum"` +
  `"ethscriptions"` +
  `"1.2.0"` +
  `"mainnet"` +
  `53446438537440` +
  `"0xcdba232865e4d010b97928c182e6046212c845a73b5790f0436a3ce4e4dd8db1"` +
  `66` +
  `0`;

const FIXTURE_SLOT_VALUES: Array<[slot: SlotRef, encodedValue: string]> = [
  [`'0`, `"2026-05-20T04:16:35.000Z"`],
  [
    `'1`,
    `"0x6044631bc6fca8f6ac9a0e6c2836b890618e2dca0d52528e89376b3e2fa28d76"`,
  ],
  [`"0`, `25133995`],
  [
    `'2`,
    `"0xa960665f0ca9ab016428ca53a1c82496769f51e119681771b14809557a267f16"`,
  ],
  [`'3`, `"image/svg+xml"`],
  [`'4`, `"${OWNER}"`],
  [`'5`, `"15782020"`],
  [`"1`, `202326009`],
  [`"2`, `264160`],
  [`'6`, `"ethereum"`],
  [`'7`, `"ethscriptions"`],
  [`'8`, `"1.2.0"`],
  [`'9`, `"mainnet"`],
  [`"3`, `53446438537440`],
  [
    `'A`,
    `"0xcdba232865e4d010b97928c182e6046212c845a73b5790f0436a3ce4e4dd8db1"`,
  ],
  [`"4`, `66`],
  [`"5`, `0`],
];

const FIXTURE_G = FIXTURE_SLOT_VALUES.map(([slot, encodedValue]) =>
  sha256Hex(
    slotGuardPreimage(slot, utf8ByteLength(encodedValue), encodedValue),
  ).slice(0, 6),
).join(",");

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function hmacSha256Hex(input: string, secret: string): string {
  return createHmac("sha256", secret).update(input, "utf8").digest("hex");
}

function integrityPayload(parts: {
  bodyLen: number;
  schemaLen: number;
  keysLen: number;
  guardsLen: number;
  body: string;
}): string {
  return `${parts.bodyLen}.${parts.schemaLen}.${parts.keysLen}.${parts.guardsLen}:${parts.body}`;
}

function makeToken(args: {
  T: string;
  K: string;
  G?: string;
  V: string;
  tagLength?: number;
  hmacSecret?: string;
}): string {
  const { T, K, V, G = "", tagLength = 16, hmacSecret } = args;
  const body = `${T}${K}${G}${V}`;
  const payload = `${utf8ByteLength(body)}.${utf8ByteLength(T)}.${utf8ByteLength(K)}.${utf8ByteLength(G)}:${body}`;
  const tag = (
    hmacSecret ? hmacSha256Hex(payload, hmacSecret) : sha256Hex(payload)
  ).slice(0, tagLength);

  return `hbs3.${tag}.${payload}`;
}

type SplitTokenResult = {
  bodyLen: number;
  integrity: string;
  schemaLen: number;
  keysLen: number;
  guardsLen: number;
  body: string;
  T: string;
  K: string;
  G: string;
  V: string;
};

function splitToken(token: string): SplitTokenResult {
  const match =
    /^hbs3\.(?<integrity>[^.]+)\.(?<bodyLen>\d+)\.(?<schemaLen>\d+)\.(?<keysLen>\d+)\.(?<guardsLen>\d+):(?<body>.*)$/s.exec(
      token,
    );

  const groups = match?.groups;
  if (!groups) {
    throw new Error(`not a HBS3 token: ${token}`);
  }

  const {
    bodyLen: bodyLenRaw,
    integrity,
    schemaLen: schemaLenRaw,
    keysLen: keysLenRaw,
    guardsLen: guardsLenRaw,
    body,
  } = groups;

  if (
    bodyLenRaw === undefined ||
    integrity === undefined ||
    schemaLenRaw === undefined ||
    keysLenRaw === undefined ||
    guardsLenRaw === undefined ||
    body === undefined
  ) {
    throw new Error(`malformed HBS3 header groups: ${token}`);
  }

  const bodyLen = Number(bodyLenRaw);
  const schemaLen = Number(schemaLenRaw);
  const keysLen = Number(keysLenRaw);
  const guardsLen = Number(guardsLenRaw);

  const T = sliceUtf8(body, 0, schemaLen);
  const K = sliceUtf8(body, schemaLen, schemaLen + keysLen);
  const G = sliceUtf8(
    body,
    schemaLen + keysLen,
    schemaLen + keysLen + guardsLen,
  );
  const V = sliceUtf8(body, schemaLen + keysLen + guardsLen);

  return {
    bodyLen,
    integrity,
    schemaLen,
    keysLen,
    guardsLen,
    body,
    T,
    K,
    G,
    V,
  };
}

function tokenWithTruncatedBody(
  fullToken: string,
  availableBody: string,
): string {
  return `${fullToken.slice(0, fullToken.indexOf(":") + 1)}${availableBody}`;
}

function tokenWithIntegrity(fullToken: string, integrity: string): string {
  return fullToken.replace(/^hbs3\.[^.]+\./, `hbs3.${integrity}.`);
}

function countOccurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

function expectHole(result: DecodeResult, expected: Partial<Hole>): void {
  expect(result.holes).toEqual(
    expect.arrayContaining([expect.objectContaining(expected)]),
  );
}

describe("HBS3 key validation", () => {
  it("accepts strict keys with numbers, dollar-prefixes, dots, dashes, underscores, and single interior spaces", () => {
    const validKeys = [
      "id",
      "0",
      "123abc",
      "block_hash",
      "$schema",
      "token.id",
      "token-id",
      "_meta",
      "token@id",
      "token id",
      "token id v2",
      "a.b-c_$@ 0",
    ];

    for (const key of validKeys) {
      expect(isValidHbsKey(key), `failed valid key: ${key}`).toBe(true);
    }
  });

  it("rejects empty keys, commas, leading/trailing spaces, consecutive spaces, and unsupported characters", () => {
    const invalidKeys = [
      "",
      " foo",
      "foo ",
      "foo  bar",
      "_ ",
      "0 ",
      "z ",
      ",",
      "foo,bar",
      "foo/bar",
      "foo:bar",
      "@foo",
      "foo#bar",
      "foo'bar",
      'foo"bar',
      "foo\\bar",
      "foo\nbar",
      "foo\tbar",
    ];

    for (const key of invalidKeys) {
      expect(isValidHbsKey(key), `failed invalid key: ${key}`).toBe(false);
    }
  });

  it("throws during encoding when a key violates strict key grammar", () => {
    expect(() => encodeHbs({ "foo,bar": 1 }, HASH16_OPTIONS)).toThrow(
      /key|strict|invalid/i,
    );
    expect(() => encodeHbs({ "foo/bar": 1 }, HASH16_OPTIONS)).toThrow(
      /key|strict|invalid/i,
    );
    expect(() => encodeHbs({ "foo ": 1 }, HASH16_OPTIONS)).toThrow(
      /key|strict|invalid/i,
    );
  });

  it("supports keys that would collide with old slot sigils because string and number slots no longer use $ or #", () => {
    const token = encodeHbs({ $schema: "x", $id: 1 }, HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.K).toBe("$id,$schema");
    expect(parts.T).toBe(`{@0"0_1@1'0_3}`);
    expect(parts.V).toBe(`1"x"`);
  });

  it("supports @ inside keys but not as the first character", () => {
    const token = encodeHbs({ "token@id": "x" }, HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.K).toBe("token@id");
    expect(parts.T).toBe(`{@0'0_3}`);
    expect(parts.V).toBe(`"x"`);
    expect(() => encodeHbs({ "@id": "x" }, HASH16_OPTIONS)).toThrow(
      /key|strict|invalid/i,
    );
  });
});

describe("HBS3 reference encoding", () => {
  it("encodes single-character base62 references", () => {
    const cases: Array<[number, string]> = [
      [0, "0"],
      [1, "1"],
      [9, "9"],
      [10, "A"],
      [35, "Z"],
      [36, "a"],
      [61, "z"],
    ];

    for (const [index, ref] of cases) {
      expect(encodeRef(index)).toBe(ref);
      expect(decodeRef(ref)).toBe(index);
    }
  });

  it("encodes extended references for indexes above the single-character alphabet", () => {
    const cases: Array<[number, string]> = [
      [62, "{10}"],
      [63, "{11}"],
      [3843, "{zz}"],
      [3844, "{100}"],
    ];

    for (const [index, ref] of cases) {
      expect(encodeRef(index)).toBe(ref);
      expect(decodeRef(ref)).toBe(index);
    }
  });

  it("rejects invalid reference indexes and malformed reference strings", () => {
    expect(() => encodeRef(-1)).toThrow(/ref|index|negative/i);
    expect(() => encodeRef(Number.NaN)).toThrow(/ref|index|number/i);
    expect(() => encodeRef(1.5)).toThrow(/ref|index|integer/i);
    expect(() => encodeRef(Number.MAX_SAFE_INTEGER + 1)).toThrow(
      /safe integer/i,
    );
    expect(() => encodeRef(62 ** 9)).toThrow(/safe integer/i);

    expect(() => decodeRef("")).toThrow(/ref/i);
    expect(() => decodeRef("{")).toThrow(/ref/i);
    expect(() => decodeRef("{10")).toThrow(/ref/i);
    expect(() => decodeRef("10")).toThrow(/ref/i);
    expect(() => decodeRef("{01}")).toThrow(/extended ref/i);
    expect(() => decodeRef("{zzzzzzzzzz}")).toThrow(/safe integer/i);
  });
});

describe("HBS3 unguarded encoding layout", () => {
  it("emits the exact schema, key dictionary, value stream, lengths, and hash for the nested fixture", () => {
    const token = encodeHbs(FIXTURE, HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.T).toBe(FIXTURE_T);
    expect(parts.K).toBe(FIXTURE_K);
    expect(parts.G).toBe("");
    expect(parts.V).toBe(FIXTURE_V);

    expect(parts.body).toBe(`${FIXTURE_T}${FIXTURE_K}${FIXTURE_V}`);
    expect(parts.bodyLen).toBe(utf8ByteLength(parts.body));
    expect(parts.schemaLen).toBe(utf8ByteLength(FIXTURE_T));
    expect(parts.keysLen).toBe(utf8ByteLength(FIXTURE_K));
    expect(parts.guardsLen).toBe(0);
    expect(parts.integrity).toBe(
      sha256Hex(
        `${parts.bodyLen}.${parts.schemaLen}.${parts.keysLen}.${parts.guardsLen}:${parts.body}`,
      ).slice(0, 16),
    );
  });

  it("uses apostrophe for string slots and double-quote for number slots, not the old $ and # slot sigils", () => {
    const token = encodeHbs(FIXTURE, HASH16_OPTIONS);
    const { T } = splitToken(token);

    expect(T).toContain(`@2'0_26`);
    expect(T).toContain(`@4"0_8`);
    expect(T).toContain(`@H'A_68`);
    expect(T).not.toContain("$0_");
    expect(T).not.toContain("#0_");
  });

  it("deduplicates repeated scalar values and reuses one recovered slot for multiple paths", () => {
    const token = encodeHbs(FIXTURE, HASH16_OPTIONS);
    const { T, V } = splitToken(token);

    expect(T).toContain(`@7'4_44@8'4_44`);
    expect(T).toContain(`@E'4_44@F'4_44`);
    expect(countOccurrences(V, OWNER)).toBe(1);
  });

  it("uses base62 slot references, so slot index 10 is A, not 10", () => {
    const token = encodeHbs(FIXTURE, HASH16_OPTIONS);
    const { T } = splitToken(token);

    expect(T).toContain(`@H'A_68`);
    expect(T).not.toContain("@H'10_68");
    expect(T).not.toContain("@H$10_68");
  });

  it("encodes arrays, nested objects, booleans, nulls, numbers, strings, and deduplicated values in one schema tape", () => {
    const value = {
      items: ["a", 1, true, null, { same: "a" }],
    };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.K).toBe("items,same");
    expect(parts.T).toBe(`{@0['0_3"0_1tz{@1'0_3}]}`);
    expect(parts.V).toBe(`"a"1`);
  });

  it("encodes empty objects and empty arrays structurally without value slots", () => {
    const value = {
      empty_array: [],
      empty_object: {},
    };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.K).toBe("empty_array,empty_object");
    expect(parts.T).toBe(`{@0[]@1{}}`);
    expect(parts.V).toBe("");
  });

  it("canonicalizes object traversal by sorted key order", () => {
    const first = encodeHbs({ b: 2, a: 1 }, HASH16_OPTIONS);
    const second = encodeHbs({ a: 1, b: 2 }, HASH16_OPTIONS);
    const parts = splitToken(first);

    expect(first).toBe(second);
    expect(parts.K).toBe("a,b");
    expect(parts.T).toBe(`{@0"0_1@1"1_1}`);
    expect(parts.V).toBe("12");
  });

  it("canonicalizes nested object traversal by sorted key order", () => {
    const first = encodeHbs({ outer: { b: 2, a: 1 } }, HASH16_OPTIONS);
    const second = encodeHbs({ outer: { a: 1, b: 2 } }, HASH16_OPTIONS);
    const parts = splitToken(first);

    expect(first).toBe(second);
    expect(parts.K).toBe("outer,a,b");
    expect(parts.T).toBe(`{@0{@1"0_1@2"1_1}}`);
    expect(parts.V).toBe("12");
  });

  it("canonicalizes objects inside arrays while preserving array order", () => {
    const token = encodeHbs(
      [
        { b: 2, a: 1 },
        { d: 4, c: 3 },
      ],
      HASH16_OPTIONS,
    );
    const parts = splitToken(token);
    const decoded = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(parts.K).toBe("a,b,c,d");
    expect(parts.T).toBe(`[{@0"0_1@1"1_1}{@2"2_1@3"3_1}]`);
    expect(parts.V).toBe("1234");
    expect(decoded.value).toEqual([
      { a: 1, b: 2 },
      { c: 3, d: 4 },
    ]);
  });

  it("reuses canonical key references across objects", () => {
    const token = encodeHbs([{ id: 1 }, { id: 2 }], HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.K).toBe("id");
    expect(parts.T).toBe(`[~1.2:@0"1:01]`);
    expect(parts.V).toBe("12");
  });

  it("uses table shape mode for homogeneous object arrays", () => {
    const value = [
      { a: 1, b: 2 },
      { a: 3, b: 4 },
      { a: 5, b: 6 },
    ];
    const token = encodeHbs(value, HASH16_OPTIONS);
    const parts = splitToken(token);
    const decoded = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(parts.K).toBe("a,b");
    expect(parts.T).toBe(`[~2.3:@0"1@1"1:012345]`);
    expect(parts.V).toBe("123456");
    expect(decoded.value).toEqual(value);
  });

  it("uses table column descriptors for fixed slots, variable slots, literals, and nested values", () => {
    const value = [
      {
        a: "x",
        arr: [1],
        f: false,
        m: 10,
        n: 1,
        o: { p: 2 },
        t: true,
        z: null,
      },
      {
        a: "yy",
        arr: [2],
        f: false,
        m: 20,
        n: 200,
        o: { p: 3 },
        t: true,
        z: null,
      },
    ];
    const token = encodeHbs(value, HASH16_OPTIONS);
    const parts = splitToken(token);
    const decoded = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(parts.K).toBe("a,arr,f,m,n,o,t,z,p");
    expect(parts.T).toContain(`[~8.2:@0'@1[@2f@3"2@4"@5{@6t@7z:`);
    expect(parts.T).toContain(`0_3;`);
    expect(parts.T).toContain(`0_1;`);
    expect(parts.T).toContain(`4_3;`);
    expect(decoded.value).toEqual(value);
  });

  it("uses table shape mode without a table-vs-normal cost estimate", () => {
    const token = encodeHbs([{ a: 1, b: 2 }], HASH16_OPTIONS);
    const heterogeneous = encodeHbs([{ a: 1 }, { a: 2, b: 3 }], HASH16_OPTIONS);
    const parts = splitToken(token);
    const heterogeneousParts = splitToken(heterogeneous);

    expect(parts.T).toBe(`[~2.1:@0"1@1"1:01]`);
    expect(heterogeneousParts.T).toBe(`[{@0"0_1}{@0"1_1@1"2_1}]`);
    expect(heterogeneousParts.T).not.toContain("~");
  });

  it("preserves array order instead of sorting array items", () => {
    const first = encodeHbs([2, 1], HASH16_OPTIONS);
    const second = encodeHbs([1, 2], HASH16_OPTIONS);

    expect(first).not.toBe(second);
    expect(decodeHbs(first, HASH16_OPTIONS).value).toEqual([2, 1]);
    expect(decodeHbs(second, HASH16_OPTIONS).value).toEqual([1, 2]);
  });
});

describe("HBS3 encoded value lengths and escaping", () => {
  it("stores string lengths as encoded JSON string literal lengths, including quotes and escapes", () => {
    const value = {
      line: "hello\nworld",
      quote: 'a"b',
      slash: "a\\b",
    };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.K).toBe("line,quote,slash");
    expect(parts.T).toBe(`{@0'0_14@1'1_6@2'2_6}`);
    expect(parts.V).toBe(`"hello\\nworld""a\\"b""a\\\\b"`);
  });

  it("allows reserved schema characters inside string values because V is sliced by schema-declared lengths", () => {
    const value = {
      weird: `@{}[]'"_:,\\\n`,
    };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const decoded = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;
    const parts = splitToken(token);
    const encodedLiteral = JSON.stringify(value.weird);

    expect(parts.T).toBe(`{@0'0_${utf8ByteLength(encodedLiteral)}}`);
    expect(parts.V).toBe(encodedLiteral);
    expect(decoded.value).toEqual(value);
    expect(decoded.checksum).toBe(true);
  });

  it("escapes lone surrogate code units in canonical string slots", () => {
    const value = { high: "\ud800", low: "\udc00", pair: "😀" };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const parts = splitToken(token);
    const decoded = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(parts.K).toBe("high,low,pair");
    expect(parts.T).toBe(`{@0'0_8@1'1_8@2'2_6}`);
    expect(parts.V).toBe(`"\\ud800""\\udc00""😀"`);
    expect(decoded.value).toEqual(value);
  });
});

describe("HBS3 full decoding", () => {
  it("decodes the exact nested fixture token with checksum true and no holes", () => {
    const token = makeToken({ T: FIXTURE_T, K: FIXTURE_K, V: FIXTURE_V });
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(result.truncated).toBe(false);
    expect(result.checksum).toBe(true);
    expect(result.holes).toEqual([]);
    expect(result.value).toEqual(FIXTURE);
  });

  it("preserves numeric JSON values as numbers and bigint-like source strings as strings", () => {
    const value = {
      bigint_like_string: "9305301016386906302397830",
      normal_number: 123,
    };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual(value);
    expect(typeof (result.value as any).bigint_like_string).toBe("string");
    expect(typeof (result.value as any).normal_number).toBe("number");
  });

  it("decodes __proto__ as an own JSON property", () => {
    const result = decodeHbs(
      makeToken({ T: '{@0"0_1}', K: "__proto__", V: "1" }),
      HASH16_OPTIONS,
    ) as DecodeResult;

    expect(
      Object.prototype.hasOwnProperty.call(result.value, "__proto__"),
    ).toBe(true);
    expect((result.value as Record<string, unknown>).__proto__).toBe(1);
  });

  it("throws when asked to encode a JavaScript BigInt because HBS3 preserves only JSON types", () => {
    expect(() => encodeHbs({ value: 1n } as any, HASH16_OPTIONS)).toThrow(
      /bigint|json|unsupported/i,
    );
  });

  it("encodes and decodes array roots while rejecting non-container roots", () => {
    const token = encodeHbs(["a", 1, { ok: true }], HASH16_OPTIONS);
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual(["a", 1, { ok: true }]);
    expect(result.holes).toEqual([]);
    expect(() => encodeHbs("x" as any, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
    expect(() => encodeHbs(1 as any, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
    expect(() => encodeHbs(true as any, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
    expect(() => encodeHbs(null as any, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
  });

  it("rejects sparse arrays at root and nested positions", () => {
    const sparseRoot: unknown[] = [undefined, undefined];
    const sparseNested: unknown[] = ["ok", undefined, "bad"];

    Reflect.deleteProperty(sparseRoot, "0");
    Reflect.deleteProperty(sparseNested, "1");

    expect(() => encodeHbs(sparseRoot, HASH16_OPTIONS)).toThrow(
      /sparse|array|json/i,
    );
    expect(() => encodeHbs({ items: sparseNested }, HASH16_OPTIONS)).toThrow(
      /sparse|array|json/i,
    );
  });

  it("still requires plain objects for object roots", () => {
    class ClassInstance {
      value = 1;
    }

    const nullPrototypeObject = Object.create(null) as Record<string, unknown>;
    nullPrototypeObject.value = 1;

    expect(() => encodeHbs(new Date() as any, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
    expect(() => encodeHbs(new ClassInstance() as any, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
    expect(() => encodeHbs(nullPrototypeObject, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
  });

  it("encodes finite JSON number edge cases and rejects non-finite numbers", () => {
    const value = {
      decimal: -12.5,
      negative_zero: -0,
      unsafe_integer: Number.MAX_SAFE_INTEGER + 1,
    };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const parts = splitToken(token);
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(parts.V).toBe("-12.509007199254740992");
    expect(result.value).toEqual({
      decimal: -12.5,
      negative_zero: 0,
      unsafe_integer: Number.MAX_SAFE_INTEGER + 1,
    });
    expect(() => encodeHbs({ n: Number.NaN }, HASH16_OPTIONS)).toThrow(
      /number|json|unsupported/i,
    );
    expect(() =>
      encodeHbs({ n: Number.POSITIVE_INFINITY }, HASH16_OPTIONS),
    ).toThrow(/number|json|unsupported/i);
  });

  it("throws when nested values are not JSON values", () => {
    expect(() => encodeHbs({ value: undefined }, HASH16_OPTIONS)).toThrow(
      /json|unsupported/i,
    );
    expect(() => encodeHbs({ value: () => 1 } as any, HASH16_OPTIONS)).toThrow(
      /json|unsupported/i,
    );
    expect(() =>
      encodeHbs({ value: Symbol("x") } as any, HASH16_OPTIONS),
    ).toThrow(/json|unsupported/i);
    class ClassInstance {
      value = 1;
    }

    expect(() =>
      encodeHbs({ value: new Date() } as any, HASH16_OPTIONS),
    ).toThrow(/json|unsupported/i);
    expect(() =>
      encodeHbs({ value: new ClassInstance() } as any, HASH16_OPTIONS),
    ).toThrow(/json|unsupported/i);
    expect(() =>
      encodeHbs({ items: ["ok", undefined] }, HASH16_OPTIONS),
    ).toThrow(/json|unsupported/i);
  });

  it("throws when host-only own properties would be dropped", () => {
    const symbolKeyed = { ok: true } as Record<PropertyKey, unknown>;
    symbolKeyed[Symbol("hidden")] = 1;

    const nonEnumerable = { ok: true };
    Object.defineProperty(nonEnumerable, "hidden", {
      value: 1,
      enumerable: false,
    });

    const expandoArray = ["ok"] as unknown[] & Record<string, unknown>;
    expandoArray.extra = 1;

    const nonEnumerableArray = [1];
    Object.defineProperty(nonEnumerableArray, "0", {
      value: 1,
      enumerable: false,
    });

    const inheritedArray = Array.from({ length: 1 }, () => "own");
    Reflect.deleteProperty(inheritedArray, "0");
    const inheritedArrayPrototype = Object.create(Array.prototype) as object;
    Object.defineProperty(inheritedArrayPrototype, "0", {
      value: "inherited",
      enumerable: true,
    });
    Object.setPrototypeOf(inheritedArray, inheritedArrayPrototype);

    const tableRowWithHiddenExtra = { a: 1 };
    Object.defineProperty(tableRowWithHiddenExtra, "hidden", {
      value: 2,
      enumerable: false,
    });

    const tableRowWithSymbolExtra = { a: 1 } as Record<PropertyKey, unknown>;
    tableRowWithSymbolExtra[Symbol("hidden")] = 2;

    const accessorObject = {};
    Object.defineProperty(accessorObject, "value", {
      get: () => 1,
      enumerable: true,
    });

    const accessorArray = [1];
    Object.defineProperty(accessorArray, "0", {
      get: () => 1,
      enumerable: true,
    });

    class ArraySubclass extends Array {}

    expect(() => encodeHbs(symbolKeyed, HASH16_OPTIONS)).toThrow(
      /symbol|json|unsupported/i,
    );
    expect(() => encodeHbs(nonEnumerable, HASH16_OPTIONS)).toThrow(
      /enumerable|json|unsupported/i,
    );
    expect(() => encodeHbs(expandoArray, HASH16_OPTIONS)).toThrow(
      /array|json|unsupported/i,
    );
    expect(() => encodeHbs(nonEnumerableArray, HASH16_OPTIONS)).toThrow(
      /enumerable|json|unsupported/i,
    );
    expect(() => encodeHbs(inheritedArray, HASH16_OPTIONS)).toThrow(
      /array|json|unsupported/i,
    );
    expect(() => encodeHbs([tableRowWithHiddenExtra], HASH16_OPTIONS)).toThrow(
      /enumerable|json|unsupported/i,
    );
    expect(() => encodeHbs([tableRowWithSymbolExtra], HASH16_OPTIONS)).toThrow(
      /symbol|json|unsupported/i,
    );
    expect(() => encodeHbs(accessorObject, HASH16_OPTIONS)).toThrow(
      /accessor|json|unsupported/i,
    );
    expect(() => encodeHbs(accessorArray, HASH16_OPTIONS)).toThrow(
      /accessor|json|unsupported/i,
    );
    expect(() =>
      encodeHbs(new ArraySubclass(1).fill("x"), HASH16_OPTIONS),
    ).toThrow(/array|json|unsupported/i);
  });

  it("throws when encoding circular JSON values", () => {
    const value: Record<string, unknown> = {};
    value.self = value;

    const array: unknown[] = [];
    array.push(array);

    expect(() => encodeHbs(value, HASH16_OPTIONS)).toThrow(/circular|json/i);
    expect(() => encodeHbs(array, HASH16_OPTIONS)).toThrow(/circular|json/i);
  });
});

describe("HBS3 factory", () => {
  it("creates an encoder and decoder with pre-bound options", () => {
    const hbs = createHbs(GUARDED_HASH16_OPTIONS);
    const token = hbs.encode({ name: "alice" });
    const result = hbs.decode(token) as DecodeResult;

    expect(result.value).toEqual({ name: "alice" });
    expect(result.checksum).toBe(true);
    expect(result.slotGuards?.[`'0`]).toBe(true);
  });
});

describe("HBS3 integrity", () => {
  it("uses default sha256 integrity options when none are provided", () => {
    const token = encodeHbs({ name: "alice" });
    const parts = splitToken(token);
    const result = decodeHbs(token) as DecodeResult;

    expect(parts.integrity).toBe(
      sha256Hex(integrityPayload(parts)).slice(0, 16),
    );
    expect(result.checksum).toBe(true);
    expect(result.value).toEqual({ name: "alice" });
  });

  it("returns checksum false, not truncated, when a full body is tampered without updating the leading hash", () => {
    const token = makeToken({ T: FIXTURE_T, K: FIXTURE_K, V: FIXTURE_V });
    const tampered = token.replace(`"mainnet"`, `"testnet"`);
    const result = decodeHbs(tampered, HASH16_OPTIONS) as DecodeResult;

    expect(result.truncated).toBe(false);
    expect(result.checksum).toBe(false);
    expect((result.value as any).meta.network).toBe("testnet");
  });

  it("throws when HMAC integrity is requested without a secret", () => {
    expect(() =>
      encodeHbs({ name: "alice" }, {
        integrity: { algorithm: "hmac-sha256" },
      } as any),
    ).toThrow(/hmac|secret/i);
  });

  it("validates options before traversing the input or storing them in an instance", () => {
    const invalidOptions = {
      integrity: { algorithm: "sha512", tagLength: 16 },
    } as any;

    expect(() =>
      encodeHbs("scalar root loses to options", invalidOptions),
    ).toThrow(/algorithm/i);
    expect(() => createHbs(invalidOptions)).toThrow(/algorithm/i);
  });

  it("rejects integrity fields that do not match the configured tag shape", () => {
    const token = makeToken({ T: "{}", K: "", V: "" });

    expect(() =>
      decodeHbs(tokenWithIntegrity(token, "f".repeat(15)), HASH16_OPTIONS),
    ).toThrow(/integrity.*length|tagLength/i);
    expect(() =>
      decodeHbs(tokenWithIntegrity(token, "g".repeat(16)), HASH16_OPTIONS),
    ).toThrow(/integrity.*hex/i);
  });

  it("rejects integrity tagLength values below two or outside integers", () => {
    const token = encodeHbs({ name: "alice" }, HASH16_OPTIONS);
    const tooShort = {
      integrity: { algorithm: "sha256", tagLength: 1 },
      guards: false,
    } as const;
    const fractional = {
      integrity: { algorithm: "sha256", tagLength: 2.5 },
      guards: false,
    } as const;

    expect(() => encodeHbs({ name: "alice" }, tooShort)).toThrow(
      /tagLength.*at least 2/i,
    );
    expect(() => decodeHbs(token, tooShort)).toThrow(/tagLength.*at least 2/i);
    expect(() => encodeHbs({ name: "alice" }, fractional)).toThrow(
      /tagLength.*integer/i,
    );
  });

  it("verifies HMAC integrity with the right secret and fails with the wrong secret", () => {
    const token = makeToken({
      T: FIXTURE_T,
      K: FIXTURE_K,
      V: FIXTURE_V,
      hmacSecret: "hbs3-test-secret",
    });
    const parts = splitToken(token);

    expect(parts.integrity).toBe(
      hmacSha256Hex(integrityPayload(parts), "hbs3-test-secret").slice(0, 16),
    );

    const rightSecret = decodeHbs(token, HMAC16_OPTIONS) as DecodeResult;
    const wrongSecret = decodeHbs(
      token,
      HMAC16_WRONG_SECRET_OPTIONS,
    ) as DecodeResult;

    expect(rightSecret.checksum).toBe(true);
    expect(wrongSecret.checksum).toBe(false);
  });

  it("returns checksum null when the body is truncated because full-body integrity cannot be verified", () => {
    const fullToken = makeToken({ T: FIXTURE_T, K: FIXTURE_K, V: FIXTURE_V });
    const availableBody = `${FIXTURE_T}${FIXTURE_K}${FIXTURE_V.slice(0, 20)}`;
    const truncatedToken = tokenWithTruncatedBody(fullToken, availableBody);
    const result = decodeHbs(truncatedToken, HASH16_OPTIONS) as DecodeResult;

    expect(result.truncated).toBe(true);
    expect(result.checksum).toBe(null);
  });
});

describe("HBS3 UTF-8 byte slicing", () => {
  it("rejects slices that split a multi-byte UTF-8 scalar instead of inserting U+FFFD", () => {
    expect(() => sliceUtf8("😀", 0, 1)).toThrow(/UTF-8 boundary/i);
  });
});

describe("HBS3 optional guards", () => {
  it("uses default guard width when guards are enabled without tagLength", () => {
    const options = {
      guards: { algorithm: "sha256" },
    } as const;
    const token = encodeHbs({ name: "alice" }, options);
    const parts = splitToken(token);
    const result = decodeHbs(token, options) as DecodeResult;

    expect(parts.G).toBe(
      sha256Hex(
        slotGuardPreimage(`'0`, utf8ByteLength(`"alice"`), `"alice"`),
      ).slice(0, 6),
    );
    expect(result.slotGuards?.[`'0`]).toBe(true);
  });

  it("supports enabled guards with an empty guard section", () => {
    const options = {
      guards: { algorithm: "sha256" },
    } as const;
    const token = encodeHbs({}, options);
    const parts = splitToken(token);
    const result = decodeHbs(token, options) as DecodeResult;

    expect(parts.G).toBe("");
    expect(result.value).toEqual({});
    expect(result.slotGuards).toEqual({});
    expect(result.guardIssues).toEqual([]);
  });

  it("rejects guard tagLength values below two or outside integers", () => {
    const validToken = encodeHbs(
      { name: "alice" },
      { guards: { algorithm: "sha256", tagLength: 2 } },
    );
    const tooShort = { guards: { algorithm: "sha256", tagLength: 1 } } as const;
    const fractional = {
      guards: { algorithm: "sha256", tagLength: 2.5 },
    } as const;

    expect(() => encodeHbs({}, tooShort)).toThrow(/tagLength.*at least 2/i);
    expect(() => decodeHbs(validToken, tooShort)).toThrow(
      /tagLength.*at least 2/i,
    );
    expect(() => encodeHbs({ name: "alice" }, fractional)).toThrow(
      /tagLength.*integer/i,
    );
  });

  it("omits the guard section when guards are disabled", () => {
    const token = encodeHbs(FIXTURE, HASH16_OPTIONS);
    const parts = splitToken(token);
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(parts.guardsLen).toBe(0);
    expect(parts.G).toBe("");
    expect(result.slotGuards ?? {}).toEqual({});
  });

  it("emits one guard per unique scalar slot when guards are enabled", () => {
    const token = encodeHbs(FIXTURE, GUARDED_HASH16_OPTIONS);
    const parts = splitToken(token);

    expect(parts.T).toBe(FIXTURE_T);
    expect(parts.K).toBe(FIXTURE_K);
    expect(parts.G).toBe(FIXTURE_G);
    expect(parts.V).toBe(FIXTURE_V);
    expect(parts.guardsLen).toBe(utf8ByteLength(FIXTURE_G));
    expect(parts.G.split(",")).toHaveLength(FIXTURE_SLOT_VALUES.length);
    expect(parts.integrity).toBe(
      sha256Hex(integrityPayload(parts)).slice(0, 16),
    );
  });

  it("verifies all recovered slots as true when guards and full body are valid", () => {
    const token = makeToken({
      T: FIXTURE_T,
      K: FIXTURE_K,
      G: FIXTURE_G,
      V: FIXTURE_V,
    });
    const result = decodeHbs(token, GUARDED_HASH16_OPTIONS) as DecodeResult;

    expect(result.checksum).toBe(true);
    expect(result.slotGuards).toBeDefined();

    for (const [slot] of FIXTURE_SLOT_VALUES) {
      expect(result.slotGuards?.[slot], `failed slot guard: ${slot}`).toBe(
        true,
      );
    }
  });

  it("marks only the tampered slot guard as false while leaving untampered slot guards true", () => {
    const token = makeToken({
      T: FIXTURE_T,
      K: FIXTURE_K,
      G: FIXTURE_G,
      V: FIXTURE_V,
    });
    const tampered = token.replace(`"mainnet"`, `"testnet"`);
    const result = decodeHbs(tampered, GUARDED_HASH16_OPTIONS) as DecodeResult;

    expect(result.checksum).toBe(false);
    expect(result.slotGuards?.[`'9`]).toBe(false);
    expect(result.slotGuards?.[`'0`]).toBe(true);
    expect(result.slotGuards?.[`'4`]).toBe(true);
  });

  it("keeps available slot guards useful when the value stream is truncated", () => {
    const fullToken = makeToken({
      T: FIXTURE_T,
      K: FIXTURE_K,
      G: FIXTURE_G,
      V: FIXTURE_V,
    });
    const prefixThroughOwnerSlot = FIXTURE_V.slice(
      0,
      26 + 68 + 8 + 68 + 15 + 44,
    );
    const availableBody = `${FIXTURE_T}${FIXTURE_K}${FIXTURE_G}${prefixThroughOwnerSlot}`;
    const truncatedToken = tokenWithTruncatedBody(fullToken, availableBody);
    const result = decodeHbs(
      truncatedToken,
      GUARDED_HASH16_OPTIONS,
    ) as DecodeResult;

    expect(result.truncated).toBe(true);
    expect(result.checksum).toBe(null);
    expect(result.slotGuards?.[`'0`]).toBe(true);
    expect(result.slotGuards?.[`'4`]).toBe(true);
    expect(result.slotGuards?.[`'5`]).toBe(null);
    expect(result.slotGuards?.[`"1`]).toBe(null);
  });

  it("supports HMAC slot guards", () => {
    const token = encodeHbs(
      { name: "alice", count: 3 },
      HMAC_GUARDED_HASH16_OPTIONS,
    );
    const parts = splitToken(token);
    const result = decodeHbs(
      token,
      HMAC_GUARDED_HASH16_OPTIONS,
    ) as DecodeResult;

    expect(parts.G).toBe(
      [
        hmacSha256Hex(
          slotGuardPreimage(`"0`, utf8ByteLength("3"), "3"),
          "hbs3-guard-secret",
        ).slice(0, 8),
        hmacSha256Hex(
          slotGuardPreimage(`'0`, utf8ByteLength(`"alice"`), `"alice"`),
          "hbs3-guard-secret",
        ).slice(0, 8),
      ].join(","),
    );
    expect(result.slotGuards).toEqual({ "'0": true, '"0': true });
  });

  it("reports missing guards separately while keeping slot guard status null", () => {
    const G = sha256Hex(
      slotGuardPreimage(`"0`, utf8ByteLength("3"), "3"),
    ).slice(0, 6);
    const token = makeToken({
      T: `{@0"0_1@1'0_7}`,
      K: "count,name",
      G,
      V: `3"alice"`,
    });
    const result = decodeHbs(token, GUARDED_HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual({ name: "alice", count: 3 });
    expect(result.slotGuards?.[`"0`]).toBe(true);
    expect(result.slotGuards?.[`'0`]).toBe(null);
    expect(result.guardIssues).toEqual([
      {
        index: 1,
        kind: "missing-guard",
        slot: `'0`,
        expectedLength: 6,
        availableLength: 0,
      },
    ]);
  });

  it("reports invalid guard entries separately while keeping slot guard status null", () => {
    const token = makeToken({ T: `{@0"0_1}`, K: "count", G: "zzzzzz", V: "1" });
    const result = decodeHbs(token, GUARDED_HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual({ count: 1 });
    expect(result.slotGuards?.[`"0`]).toBe(null);
    expect(result.guardIssues).toEqual([
      {
        index: 0,
        kind: "invalid-guard",
        slot: `"0`,
        expectedLength: 6,
        availableLength: 6,
      },
    ]);
  });

  it("reports truncated guard entries separately and recovers schema-only values when no value stream remains", () => {
    const fullToken = makeToken({
      T: `{@0t@1"0_1}`,
      K: "active,count",
      G: "6b86",
      V: "1",
    });
    const availableBody = `{@0t@1"0_1}active,count6b86`;
    const token = tokenWithTruncatedBody(fullToken, availableBody);
    const result = decodeHbs(token, GUARDED_HASH16_OPTIONS) as DecodeResult;

    expect(result.truncated).toBe(true);
    expect(result.value).toEqual({ active: true });
    expect(result.slotGuards?.[`"0`]).toBe(null);
    expect(result.guardIssues).toEqual([
      {
        index: 0,
        kind: "truncated-guard",
        slot: `"0`,
        expectedLength: 6,
        availableLength: 4,
      },
    ]);
    expectHole(result, {
      path: "/count",
      kind: "missing-slot",
      slot: `"0`,
      expectedType: "number",
      expectedLength: 1,
    });
  });

  it("reports extra guards separately instead of throwing", () => {
    const token = makeToken({
      T: `{@0"0_1}`,
      K: "count",
      G: `${sha256Hex(slotGuardPreimage(`"0`, 1, "1")).slice(0, 6)},abcdef`,
      V: "1",
    });
    const result = decodeHbs(token, GUARDED_HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual({ count: 1 });
    expect(result.slotGuards?.[`"0`]).toBe(true);
    expect(result.guardIssues).toEqual([
      {
        index: 1,
        kind: "extra-guard",
        expectedLength: 6,
        availableLength: 6,
      },
    ]);
  });

  it("reports a trailing comma in the guard section as an empty extra guard", () => {
    const guard = sha256Hex(slotGuardPreimage(`"0`, 1, "1")).slice(0, 6);
    const token = makeToken({
      T: `{@0"0_1}`,
      K: "count",
      G: `${guard},`,
      V: "1",
    });
    const result = decodeHbs(token, GUARDED_HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual({ count: 1 });
    expect(result.slotGuards?.[`"0`]).toBe(true);
    expect(result.guardIssues).toEqual([
      {
        index: 1,
        kind: "extra-guard",
        expectedLength: 6,
        availableLength: 0,
      },
    ]);
  });

  it("marks HMAC slot guards false when decoded with the wrong guard secret", () => {
    const token = encodeHbs({ name: "alice" }, HMAC_GUARDED_HASH16_OPTIONS);
    const result = decodeHbs(token, {
      ...HMAC_GUARDED_HASH16_OPTIONS,
      guards: {
        algorithm: "hmac-sha256",
        secret: "wrong-secret",
        tagLength: 8,
      },
    }) as DecodeResult;

    expect(result.slotGuards?.[`'0`]).toBe(false);
  });
});

describe("HBS3 partial decoding and structural recovery", () => {
  it("recovers schema-only values and reused slots when V is truncated after a shared slot", () => {
    const fullToken = makeToken({ T: FIXTURE_T, K: FIXTURE_K, V: FIXTURE_V });
    const prefixThroughOwnerSlot = FIXTURE_V.slice(
      0,
      26 + 68 + 8 + 68 + 15 + 44,
    );
    const availableBody = `${FIXTURE_T}${FIXTURE_K}${prefixThroughOwnerSlot}`;
    const truncatedToken = tokenWithTruncatedBody(fullToken, availableBody);
    const result = decodeHbs(truncatedToken, HASH16_OPTIONS) as DecodeResult;
    const value = result.value as any;

    expect(result.truncated).toBe(true);
    expect(result.checksum).toBe(null);

    expect(value.active).toBe(false);
    expect(value.attributes).toBe(null);
    expect(value.is_esip8).toBe(true);
    expect(value.meta.confirmed).toBe(true);

    expect(value.creator).toBe(OWNER);
    expect(value.current_owner).toBe(OWNER);
    expect(value.previous_owner).toBe(OWNER);
    expect(value.receiver).toBe(OWNER);

    expect(value.block_datetime).toBe(FIXTURE.block_datetime);
    expect(value.block_hash).toBe(FIXTURE.block_hash);
    expect(value.block_number).toBe(FIXTURE.block_number);
    expect(value.content_sha).toBe(FIXTURE.content_sha);
    expect(value.content_type).toBe(FIXTURE.content_type);

    expect(value).not.toHaveProperty("ethscription_number");
    expect(value).not.toHaveProperty("gas_price");
    expect(value.meta).not.toHaveProperty("chain");
    expect(value.meta.indexer).not.toHaveProperty("name");

    expectHole(result, {
      path: "/ethscription_number",
      kind: "missing-slot",
      slot: `'5`,
      expectedType: "string",
      expectedLength: 10,
    });
    expectHole(result, {
      path: "/gas_price",
      kind: "missing-slot",
      slot: `"1`,
      expectedType: "number",
      expectedLength: 9,
    });
    expectHole(result, {
      path: "/meta/chain",
      kind: "missing-slot",
      slot: `'6`,
      expectedType: "string",
      expectedLength: 10,
    });
    expectHole(result, {
      path: "/transaction_hash",
      kind: "missing-slot",
      slot: `'A`,
      expectedType: "string",
      expectedLength: 68,
    });
  });

  it("recovers booleans, nulls, object shape, and typed holes when the whole value stream is missing", () => {
    const fullToken = makeToken({ T: FIXTURE_T, K: FIXTURE_K, V: FIXTURE_V });
    const availableBody = `${FIXTURE_T}${FIXTURE_K}`;
    const truncatedToken = tokenWithTruncatedBody(fullToken, availableBody);
    const result = decodeHbs(truncatedToken, HASH16_OPTIONS) as DecodeResult;
    const value = result.value as any;

    expect(result.truncated).toBe(true);
    expect(result.checksum).toBe(null);

    expect(value.active).toBe(false);
    expect(value.attributes).toBe(null);
    expect(value.is_esip8).toBe(true);
    expect(value.meta.confirmed).toBe(true);
    expect(value.meta.indexer).toEqual({});

    expectHole(result, {
      path: "/block_datetime",
      kind: "missing-slot",
      slot: `'0`,
      expectedType: "string",
      expectedLength: 26,
    });
    expectHole(result, {
      path: "/block_number",
      kind: "missing-slot",
      slot: `"0`,
      expectedType: "number",
      expectedLength: 8,
    });
  });

  it("reports truncated-slot when a value slot is only partially available", () => {
    const fullToken = makeToken({ T: FIXTURE_T, K: FIXTURE_K, V: FIXTURE_V });
    const partialFirstSlot = FIXTURE_V.slice(0, 10);
    const availableBody = `${FIXTURE_T}${FIXTURE_K}${partialFirstSlot}`;
    const truncatedToken = tokenWithTruncatedBody(fullToken, availableBody);
    const result = decodeHbs(truncatedToken, HASH16_OPTIONS) as DecodeResult;

    expect(result.truncated).toBe(true);
    expectHole(result, {
      path: "/block_datetime",
      kind: "truncated-slot",
      slot: `'0`,
      expectedType: "string",
      expectedLength: 26,
      availableLength: 10,
    });
  });

  it("reports all paths affected by a missing shared slot", () => {
    const schema = `{@0'0_44@1'0_44@2'0_44}`;
    const keys = "creator,current_owner,receiver";
    const valueStream = `"${OWNER}"`;
    const fullToken = makeToken({ T: schema, K: keys, V: valueStream });
    const availableBody = `${schema}${keys}`;
    const truncatedToken = tokenWithTruncatedBody(fullToken, availableBody);
    const result = decodeHbs(truncatedToken, HASH16_OPTIONS) as DecodeResult;

    expect(valueStream).toEqual(`"${OWNER}"`);
    expectHole(result, { path: "/creator", kind: "missing-slot", slot: `'0` });
    expectHole(result, {
      path: "/current_owner",
      kind: "missing-slot",
      slot: `'0`,
    });
    expectHole(result, { path: "/receiver", kind: "missing-slot", slot: `'0` });
  });

  it("reports holes inside table shape rows with row and key paths", () => {
    const token = makeToken({
      T: `[~2.2:@0"1@1'3:0011]`,
      K: "n,name",
      V: `1"a"`,
    });
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual([{ name: "a", n: 1 }, {}]);
    expectHole(result, {
      path: "/1/name",
      kind: "missing-slot",
      slot: `'1`,
    });
    expectHole(result, {
      path: "/1/n",
      kind: "missing-slot",
      slot: `"1`,
    });
  });
});

describe("HBS3 large-object reference scaling", () => {
  it("uses extended key and slot refs when both refs are above the first 62 refs", () => {
    const value: Record<string, number> = {};

    for (let index = 0; index < 65; index += 1) {
      value[`k${String(index).padStart(2, "0")}`] = index;
    }

    const token = encodeHbs(value, HASH16_OPTIONS);
    const { T, K, V } = splitToken(token);

    expect(K.split(",")).toHaveLength(65);
    expect(T).toContain(`@z"z_2`);
    expect(T).toContain(`@{10}"{10}_2`);
    expect(T).toContain(`@{11}"{11}_2`);
    expect(T).toContain(`@{12}"{12}_2`);
    expect(V.endsWith("61626364")).toBe(true);
  });

  it("uses an extended key ref for nested objects whose key index is above the first 62 refs", () => {
    const value: Record<string, unknown> = {};

    for (let index = 0; index < 62; index += 1) {
      value[`k${String(index).padStart(2, "0")}`] = index;
    }
    value.k62 = { child: "value" };

    const token = encodeHbs(value, HASH16_OPTIONS);
    const { T, K, V } = splitToken(token);

    expect(K.split(",")).toHaveLength(64);
    expect(T).toContain(`@{10}{@{11}'0_7}`);
    expect(V.endsWith(`61"value"`)).toBe(true);
  });

  it("uses an extended key ref for arrays whose key index is above the first 62 refs", () => {
    const value: Record<string, unknown> = {};

    for (let index = 0; index < 62; index += 1) {
      value[`k${String(index).padStart(2, "0")}`] = index;
    }
    value.k62 = ["value"];

    const token = encodeHbs(value, HASH16_OPTIONS);
    const { T, K, V } = splitToken(token);

    expect(K.split(",")).toHaveLength(63);
    expect(T).toContain(`@{10}['0_7]`);
    expect(V.endsWith(`61"value"`)).toBe(true);
  });
});

describe("HBS3 malformed input handling", () => {
  it("throws for invalid version markers and malformed headers", () => {
    expect(() => decodeHbs("jts2.0.abc.0.0.0:", HASH16_OPTIONS)).toThrow(
      /hbs3|version|header/i,
    );
    expect(() => decodeHbs("hbs3.nope.abc.0.0.0:", HASH16_OPTIONS)).toThrow(
      /bodyLen|length|header|number/i,
    );
    expect(() => decodeHbs("hbs3.0.abc.0.0:", HASH16_OPTIONS)).toThrow(
      /header/i,
    );
  });

  it("throws for malformed key dictionaries", () => {
    const token = makeToken({ T: `{@0"0_1}`, K: "bad,key,", V: "1" });
    const duplicateKeyToken = makeToken({
      T: `{@0"0_1@1"1_1}`,
      K: "same,same",
      V: "12",
    });

    expect(() => decodeHbs(token, HASH16_OPTIONS)).toThrow(
      /key|dictionary|malformed/i,
    );
    expect(() => decodeHbs(duplicateKeyToken, HASH16_OPTIONS)).toThrow(
      /key|dictionary|duplicate|malformed/i,
    );
  });

  it("throws for complete non-canonical key dictionaries and key order", () => {
    const nonCanonicalKeyOrder = makeToken({ T: `{@1z@0z}`, K: "b,a", V: "" });
    const extraKey = makeToken({ T: `{}`, K: "unused", V: "" });
    const unsortedObjectEntries = makeToken({ T: `{@1z@0z}`, K: "a,b", V: "" });
    const unsortedTableColumns = makeToken({
      T: `[~2.1:@1z@0z:]`,
      K: "a,b",
      V: "",
    });

    expect(() => decodeHbs(nonCanonicalKeyOrder, HASH16_OPTIONS)).toThrow(
      /canonical|dictionary/i,
    );
    expect(() => decodeHbs(extraKey, HASH16_OPTIONS)).toThrow(
      /canonical|dictionary/i,
    );
    expect(() => decodeHbs(unsortedObjectEntries, HASH16_OPTIONS)).toThrow(
      /canonical|object|order/i,
    );
    expect(() => decodeHbs(unsortedTableColumns, HASH16_OPTIONS)).toThrow(
      /canonical|table|order/i,
    );
  });

  it("throws for slot lengths that cannot be parsed as non-negative decimal integers", () => {
    const nonNumericLength = makeToken({ T: `{@0'0_x}`, K: "name", V: `"x"` });
    const negativeLength = makeToken({ T: `{@0'0_-1}`, K: "name", V: `"x"` });
    const missingSeparator = makeToken({ T: `{@0'0}`, K: "name", V: `"x"` });

    expect(() => decodeHbs(nonNumericLength, HASH16_OPTIONS)).toThrow(
      /length|schema/i,
    );
    expect(() => decodeHbs(negativeLength, HASH16_OPTIONS)).toThrow(
      /length|schema/i,
    );
    expect(() => decodeHbs(missingSeparator, HASH16_OPTIONS)).toThrow(
      /separator|length|schema/i,
    );
  });

  it("throws when the available body is longer than the declared body length", () => {
    const token = makeToken({ T: `{@0"0_1}`, K: "n", V: "1" });

    expect(() => decodeHbs(`${token}extra`, HASH16_OPTIONS)).toThrow(
      /bodyLen|body length/i,
    );
  });

  it("throws when truncation cuts into schema or key sections", () => {
    const fullToken = makeToken({ T: `{@0'0_3}`, K: "name", V: `"x"` });

    expect(() =>
      decodeHbs(tokenWithTruncatedBody(fullToken, `{@`), HASH16_OPTIONS),
    ).toThrow(/schema/i);
    expect(() =>
      decodeHbs(tokenWithTruncatedBody(fullToken, `{@0'0_3na`), HASH16_OPTIONS),
    ).toThrow(/key|dictionary|malformed/i);
  });

  it("throws when the same slot ref is declared with conflicting lengths", () => {
    const token = makeToken({
      T: `{@0'0_3@1'0_4}`,
      K: "first,second",
      V: `"x"`,
    });

    expect(() => decodeHbs(token, HASH16_OPTIONS)).toThrow(
      /slot|conflict|length/i,
    );
  });

  it("accepts repeated slot refs with the same declared length", () => {
    const token = makeToken({
      T: `{@0'0_3@1'0_3}`,
      K: "first,second",
      V: `"x"`,
    });
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual({ first: "x", second: "x" });
    expect(result.holes).toEqual([]);
  });

  it("throws for malformed schema containers and references", () => {
    const unclosedObject = makeToken({ T: `{@0"0_1`, K: "n", V: "1" });
    const unclosedArray = makeToken({ T: `{@0["0_1}`, K: "items", V: "1" });
    const unclosedArrayRoot = makeToken({ T: `["0_1`, K: "", V: "1" });
    const trailingJunk = makeToken({ T: `{@0"0_1}x`, K: "n", V: "1" });
    const malformedExtendedRef = makeToken({ T: `{@{1}"0_1}`, K: "n", V: "1" });
    const unclosedExtendedRef = makeToken({ T: `'{10_1`, K: "", V: "1" });
    const malformedTableRowSeparator = makeToken({
      T: `[~1:1@0"0_1]`,
      K: "n",
      V: "1",
    });
    const malformedTableHeader = makeToken({
      T: `[~1.1@0"1:0]`,
      K: "n",
      V: "1",
    });
    const malformedTableKeyRef = makeToken({
      T: `[~1.1:0"1:0]`,
      K: "n",
      V: "1",
    });
    const missingTableBodySeparator = makeToken({
      T: `[~1.1:@0"10]`,
      K: "n",
      V: "1",
    });
    const malformedTableColumnMarker = makeToken({
      T: `[~1.1:@0?:]`,
      K: "n",
      V: "1",
    });
    const missingTableLengthSeparator = makeToken({
      T: `[~1.1:@0":0;]`,
      K: "n",
      V: "1",
    });
    const missingTableLengthTerminator = makeToken({
      T: `[~1.1:@0":0_1]`,
      K: "n",
      V: "1",
    });
    const unclosedTable = makeToken({ T: `[~1.1:@0"1:0}`, K: "n", V: "1" });
    const missingKeyRef = makeToken({ T: `{@}`, K: "n", V: "" });

    expect(() => decodeHbs(unclosedObject, HASH16_OPTIONS)).toThrow(/schema/i);
    expect(() => decodeHbs(unclosedArray, HASH16_OPTIONS)).toThrow(/schema/i);
    expect(() => decodeHbs(unclosedArrayRoot, HASH16_OPTIONS)).toThrow(
      /schema/i,
    );
    expect(() => decodeHbs(trailingJunk, HASH16_OPTIONS)).toThrow(/schema/i);
    expect(() => decodeHbs(malformedExtendedRef, HASH16_OPTIONS)).toThrow(
      /ref|schema/i,
    );
    expect(() => decodeHbs(unclosedExtendedRef, HASH16_OPTIONS)).toThrow(
      /ref|schema/i,
    );
    expect(() => decodeHbs(malformedTableRowSeparator, HASH16_OPTIONS)).toThrow(
      /table|schema/i,
    );
    expect(() => decodeHbs(malformedTableHeader, HASH16_OPTIONS)).toThrow(
      /table|schema/i,
    );
    expect(() => decodeHbs(malformedTableKeyRef, HASH16_OPTIONS)).toThrow(
      /table|schema/i,
    );
    expect(() => decodeHbs(missingTableBodySeparator, HASH16_OPTIONS)).toThrow(
      /table|schema/i,
    );
    expect(() => decodeHbs(malformedTableColumnMarker, HASH16_OPTIONS)).toThrow(
      /table|schema/i,
    );
    expect(() =>
      decodeHbs(missingTableLengthSeparator, HASH16_OPTIONS),
    ).toThrow(/table|schema/i);
    expect(() =>
      decodeHbs(missingTableLengthTerminator, HASH16_OPTIONS),
    ).toThrow(/table|schema/i);
    expect(() => decodeHbs(unclosedTable, HASH16_OPTIONS)).toThrow(
      /table|schema/i,
    );
    expect(() => decodeHbs(missingKeyRef, HASH16_OPTIONS)).toThrow(
      /ref|schema/i,
    );
  });

  it("reports missing-key when a schema key ref points past the dictionary", () => {
    const token = makeToken({ T: `{@1"0_1}`, K: "only", V: "1" });
    const tableToken = makeToken({ T: `[~1.1:@1"1:0]`, K: "only", V: "1" });
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;
    const tableResult = decodeHbs(tableToken, HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual({});
    expectHole(result, { path: "", kind: "missing-key" });
    expect(tableResult.value).toEqual([{}]);
    expectHole(tableResult, { path: "/0", kind: "missing-key" });
  });

  it("decodes array root schemas and rejects scalar root schemas", () => {
    const arrayRoot = makeToken({ T: `["0_1]`, K: "", V: "1" });
    const scalarRoot = makeToken({ T: `"0_1`, K: "", V: "1" });
    const result = decodeHbs(arrayRoot, HASH16_OPTIONS) as DecodeResult;

    expect(result.value).toEqual([1]);
    expect(() => decodeHbs(scalarRoot, HASH16_OPTIONS)).toThrow(
      /object|array|root/i,
    );
  });

  it("reports invalid-slot holes for full-length slot values that are not valid JSON literals of the expected type", () => {
    const token = makeToken({ T: `{@0"0_2@1'0_3}`, K: "n,name", V: `0xabc` });
    const wrongTypeToken = makeToken({
      T: `{@0"0_3@1'0_1}`,
      K: "n,name",
      V: `"x"1`,
    });
    const result = decodeHbs(token, HASH16_OPTIONS) as DecodeResult;
    const wrongTypeResult = decodeHbs(
      wrongTypeToken,
      HASH16_OPTIONS,
    ) as DecodeResult;

    expect(result.value).toEqual({});
    expectHole(result, {
      path: "/name",
      kind: "invalid-slot",
      slot: `'0`,
      expectedType: "string",
      expectedLength: 3,
    });
    expectHole(result, {
      path: "/n",
      kind: "invalid-slot",
      slot: `"0`,
      expectedType: "number",
      expectedLength: 2,
    });
    expect(wrongTypeResult.value).toEqual({});
    expectHole(wrongTypeResult, {
      path: "/name",
      kind: "invalid-slot",
      slot: `'0`,
      expectedType: "string",
      expectedLength: 1,
    });
    expectHole(wrongTypeResult, {
      path: "/n",
      kind: "invalid-slot",
      slot: `"0`,
      expectedType: "number",
      expectedLength: 3,
    });
  });

  it("decodes canonical JSON number literals and rejects malformed or non-canonical number literals", () => {
    const validToken = makeToken({
      T: `{@0"0_3}`,
      K: "decimal",
      V: `0.5`,
    });
    const invalidToken = makeToken({
      T: `{@0"0_2@1"1_3@2"2_2@3"3_2@4"4_2@5"5_2@6"6_4@7"7_2}`,
      K: "dot,exp,exp_missing,leading,neg_zero,plus,tiny,trailing",
      V: `.11e31e01-0+11e-31.`,
    });
    const validResult = decodeHbs(validToken, HASH16_OPTIONS) as DecodeResult;
    const invalidResult = decodeHbs(
      invalidToken,
      HASH16_OPTIONS,
    ) as DecodeResult;

    expect(validResult.value).toEqual({
      decimal: 0.5,
    });
    expectHole(invalidResult, {
      path: "/exp",
      kind: "invalid-slot",
      slot: `"1`,
    });
    expectHole(invalidResult, {
      path: "/neg_zero",
      kind: "invalid-slot",
      slot: `"4`,
    });
    expectHole(invalidResult, {
      path: "/tiny",
      kind: "invalid-slot",
      slot: `"6`,
    });
    expectHole(invalidResult, {
      path: "/leading",
      kind: "invalid-slot",
      slot: `"3`,
    });
    expectHole(invalidResult, {
      path: "/plus",
      kind: "invalid-slot",
      slot: `"5`,
    });
    expectHole(invalidResult, {
      path: "/dot",
      kind: "invalid-slot",
      slot: `"0`,
    });
    expectHole(invalidResult, {
      path: "/trailing",
      kind: "invalid-slot",
      slot: `"7`,
    });
    expectHole(invalidResult, {
      path: "/exp_missing",
      kind: "invalid-slot",
      slot: `"2`,
    });
  });

  it("reports nested array element holes with JSON-pointer paths during partial decoding", () => {
    const fullToken = makeToken({
      T: `{@0['0_3'1_3]}`,
      K: "items",
      V: `"a""b"`,
    });
    const truncated = tokenWithTruncatedBody(
      fullToken,
      `{@0['0_3'1_3]}items"a"`,
    );
    const result = decodeHbs(truncated, HASH16_OPTIONS) as DecodeResult;

    expect((result.value as any).items[0]).toBe("a");
    expect((result.value as any).items).toEqual(["a", null]);
    expectHole(result, {
      path: "/items/1",
      kind: "missing-slot",
      slot: `'1`,
      expectedType: "string",
      expectedLength: 3,
    });
  });

  it("reports deep nested holes inside arrays with JSON-pointer paths", () => {
    const fullToken = makeToken({
      T: `{@0[{@1'0_7@2'1_7}]}`,
      K: "items,label,name",
      V: `"admin""alice"`,
    });
    const truncated = tokenWithTruncatedBody(
      fullToken,
      `{@0[{@1'0_7@2'1_7}]}items,label,name"admin"`,
    );
    const result = decodeHbs(truncated, HASH16_OPTIONS) as DecodeResult;

    expect((result.value as any).items[0].label).toBe("admin");
    expectHole(result, {
      path: "/items/0/name",
      kind: "missing-slot",
      slot: `'1`,
      expectedType: "string",
      expectedLength: 7,
    });
  });

  it("recovers complete keys when K is truncated exactly after a comma", () => {
    const fullToken = makeToken({ T: `{@0t@1f}`, K: "a,b", V: "" });
    const truncated = tokenWithTruncatedBody(fullToken, `{@0t@1f}a,`);
    const result = decodeHbs(truncated, HASH16_OPTIONS) as DecodeResult;

    expect(result.truncated).toBe(true);
    expect(result.value).toEqual({ a: true });
    expectHole(result, {
      path: "",
      kind: "missing-key",
    });
  });

  it("rejects nesting deeper than the implementation limit before the stack is the limit", () => {
    let deepInput: unknown = "leaf";

    for (let index = 0; index < 257; index += 1) {
      deepInput = [deepInput];
    }

    const deepSchema = `${"[".repeat(258)}z${"]".repeat(258)}`;
    const token = makeToken({ T: deepSchema, K: "", V: "" });

    expect(() => encodeHbs(deepInput, HASH16_OPTIONS)).toThrow(/nesting/i);
    expect(() => decodeHbs(token, HASH16_OPTIONS)).toThrow(/nesting/i);
  });

  it("rejects pathological decimal lengths before converting them to offsets", () => {
    const longDigits = "9".repeat(17);
    const validTag = "0".repeat(16);

    expect(() =>
      decodeHbs(`hbs3.${validTag}.${longDigits}.0.0.0:`, HASH16_OPTIONS),
    ).toThrow(/safe integer/i);
    expect(() =>
      decodeHbs(
        makeToken({ T: `{@0"0_${longDigits}}`, K: "n", V: "" }),
        HASH16_OPTIONS,
      ),
    ).toThrow(/safe integer/i);
  });

  it("rejects malformed table rows without throwing a host TypeError", () => {
    const token = makeToken({
      T: `[~1.2:@0':0_3;]`,
      K: "a",
      V: `"x"`,
    });

    expect(() => decodeHbs(token, HASH16_OPTIONS)).toThrow(/ref|cell|schema/i);
  });
});
