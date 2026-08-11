import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import {
  canonicalizeNumber,
  canonicalizeString,
  sortObjectKeys,
} from "./canonical.ts";

export {
  canonicalizeNumber,
  canonicalizeString,
  sortObjectKeys,
} from "./canonical.ts";

const REF_ALPHABET =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const STRICT_KEY_RE = /^[A-Za-z0-9_$][A-Za-z0-9_$@.-]*(?: [A-Za-z0-9_$@.-]+)*$/;
const CANONICAL_UINT_RE = /^(?:0|[1-9]\d*)$/;
const HEX_TAG_RE = /^[0-9a-f]+$/;
const MAX_DECIMAL_DIGITS = 16;
const MAX_REF_DIGITS = 9;
const MAX_NESTING_DEPTH = 256;
const hasOwn = (value: object, key: PropertyKey): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export type IntegrityOptions =
  | { algorithm: "sha256"; tagLength?: number }
  | { algorithm: "hmac-sha256"; secret: string; tagLength?: number };

export type GuardOptions =
  | false
  | {
      algorithm: "sha256" | "hmac-sha256";
      secret?: string;
      tagLength?: number;
    };

export type HbsOptions = {
  integrity?: IntegrityOptions;
  guards?: GuardOptions;
};

export type Hole = {
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

type SlotType = "string" | "number";
export type SlotRef = `'${string}` | `"${string}`;

type Node =
  | { kind: "object"; entries: Array<{ keyRef: string; value: Node }> }
  | { kind: "array"; items: Node[] }
  | { kind: "table"; columns: TableColumn[]; rows: Node[][] }
  | { kind: "literal"; value: boolean | null }
  | { kind: "slot"; slot: SlotRef; slotType: SlotType; length: number };

type TableColumn =
  | { kind: "fixed-slot"; keyRef: string; slotType: SlotType; length: number }
  | { kind: "variable-slot"; keyRef: string; slotType: SlotType }
  | { kind: "literal"; keyRef: string; value: boolean | null }
  | { kind: "node"; keyRef: string; marker: "{" | "[" | "*" };

type SlotInfo = {
  slot: SlotRef;
  type: SlotType;
  length: number;
  encoded?: string;
  value?: string | number;
  kind?: Hole["kind"];
  availableLength?: number;
};

type EncodeState = {
  keyIndex: Map<string, number>;
  keys: string[];
  stringIndex: Map<string, { index: number; length: number }>;
  numberIndex: Map<string, { index: number; length: number }>;
  slotOrder: Array<{ slot: SlotRef; encoded: string; length: number }>;
};

export type GuardIssue = {
  index: number;
  kind: "missing-guard" | "truncated-guard" | "invalid-guard" | "extra-guard";
  slot?: string;
  expectedLength?: number;
  availableLength?: number;
};

export type DecodeResult = {
  value: unknown;
  truncated: boolean;
  checksum: boolean | null;
  holes: Hole[];
  slotGuards: Record<string, true | false | null>;
  guardIssues: GuardIssue[];
};

export function isValidHbsKey(key: string): boolean {
  return STRICT_KEY_RE.test(key);
}

export function encodeRef(index: number): string {
  if (typeof index !== "number" || Number.isNaN(index)) {
    throw new Error("ref index must be a number");
  }
  if (!Number.isInteger(index)) {
    throw new Error("ref index must be an integer");
  }
  if (index < 0) {
    throw new Error("ref index cannot be negative");
  }
  if (!Number.isSafeInteger(index)) {
    throw new Error("ref index exceeds safe integer range");
  }
  if (index < REF_ALPHABET.length) {
    return REF_ALPHABET[index]!;
  }

  let value = index;
  let out = "";

  while (value > 0) {
    out = REF_ALPHABET[value % REF_ALPHABET.length]! + out;
    value = Math.floor(value / REF_ALPHABET.length);
  }

  if (out.length > MAX_REF_DIGITS) {
    throw new Error("ref index exceeds safe integer range");
  }

  return `{${out}}`;
}

export function decodeRef(ref: string): number {
  if (ref.length === 1) {
    const index = REF_ALPHABET.indexOf(ref);

    if (index === -1) {
      throw new Error("malformed ref");
    }

    return index;
  }

  const match = /^\{([0-9A-Za-z]+)\}$/.exec(ref);

  if (!match) {
    throw new Error("malformed ref");
  }

  const digits = match[1]!;

  if (digits.length < 2) {
    throw new Error("malformed extended ref");
  }
  if (digits.startsWith("0")) {
    throw new Error("malformed extended ref");
  }
  if (digits.length > MAX_REF_DIGITS) {
    throw new Error("ref index exceeds safe integer range");
  }

  let value = 0;

  for (const digit of digits) {
    const n = REF_ALPHABET.indexOf(digit);

    /* v8 ignore if -- @preserve extended ref regex only permits alphabet digits */
    if (n === -1) {
      throw new Error("malformed ref");
    }

    value = value * REF_ALPHABET.length + n;
    if (!Number.isSafeInteger(value)) {
      throw new Error("ref index exceeds safe integer range");
    }
  }

  if (value < REF_ALPHABET.length) {
    throw new Error("malformed extended ref");
  }

  return value;
}

export function createHbs(options: HbsOptions = {}): {
  encode(value: unknown): string;
  decode(token: string): ReturnType<typeof decodeHbs>;
} {
  validateHbsOptions(options);

  return {
    encode(value: unknown): string {
      return encodeHbs(value, options);
    },
    decode(token: string): ReturnType<typeof decodeHbs> {
      return decodeHbs(token, options);
    },
  };
}

export function encodeHbs(value: unknown, options: HbsOptions = {}): string {
  const validatedOptions = validateHbsOptions(options);

  if (!isSupportedRoot(value)) {
    throw new Error("HBS3 root must be a plain object or array");
  }

  let state: EncodeState = {
    keyIndex: new Map(),
    keys: [],
    stringIndex: new Map(),
    numberIndex: new Map(),
    slotOrder: [],
  };

  const keyRef = (key: string): string => {
    if (!isValidHbsKey(key)) {
      throw new Error(`invalid strict key: ${key}`);
    }

    let index = state.keyIndex.get(key);

    if (index === undefined) {
      index = state.keys.length;
      state.keyIndex.set(key, index);
      state.keys.push(key);
    }

    return encodeRef(index);
  };

  const scalarInfo = (
    input: string | number,
  ): { ref: string; slotType: SlotType; length: number } => {
    if (typeof input === "string") {
      const encoded = canonicalizeString(input);
      let cached = state.stringIndex.get(encoded);

      if (cached === undefined) {
        const index = state.stringIndex.size;
        const length = utf8ByteLength(encoded);

        cached = { index, length };
        state.stringIndex.set(encoded, cached);
        state.slotOrder.push({
          slot: `'${encodeRef(index)}` as SlotRef,
          encoded,
          length,
        });
      }

      return {
        ref: encodeRef(cached.index),
        slotType: "string",
        length: cached.length,
      };
    }

    const encoded = canonicalizeNumber(input);
    let cached = state.numberIndex.get(encoded);

    if (cached === undefined) {
      const index = state.numberIndex.size;
      const length = utf8ByteLength(encoded);

      cached = { index, length };
      state.numberIndex.set(encoded, cached);
      state.slotOrder.push({
        slot: `"${encodeRef(index)}` as SlotRef,
        encoded,
        length,
      });
    }

    return {
      ref: encodeRef(cached.index),
      slotType: "number",
      length: cached.length,
    };
  };

  const scalarToken = (input: string | number): string => {
    const info = scalarInfo(input);
    const sigil = info.slotType === "string" ? "'" : '"';

    return `${sigil}${info.ref}_${info.length}`;
  };

  const sameKeys = (left: string[], right: string[]): boolean => {
    if (left.length !== right.length) {
      return false;
    }

    return left.every((key, index) => key === right[index]);
  };

  const homogeneousObjectKeys = (input: unknown[]): string[] | null => {
    if (input.length === 0) {
      return null;
    }

    if (!input.every((item) => isPlainObject(item))) {
      return null;
    }

    for (const item of input) {
      rejectHostObjectProperties(item as Record<string, unknown>);
    }

    const keys = sortObjectKeys(input[0] as Record<string, unknown>);

    for (const item of input) {
      if (!sameKeys(keys, sortObjectKeys(item as Record<string, unknown>))) {
        return null;
      }
    }

    return keys;
  };

  const tableColumn = (
    keyRef: string,
    values: unknown[],
    depth: number,
  ): { column: TableColumn; encodeCell(value: unknown): string } => {
    if (values.every((value) => typeof value === "string")) {
      const lengths = new Set(
        values.map((value) =>
          utf8ByteLength(canonicalizeString(value as string)),
        ),
      );
      const length = lengths.size === 1 ? [...lengths][0]! : undefined;

      return {
        column:
          length === undefined
            ? { kind: "variable-slot", keyRef, slotType: "string" }
            : { kind: "fixed-slot", keyRef, slotType: "string", length },
        encodeCell(value: unknown): string {
          const info = scalarInfo(value as string);

          return length === undefined
            ? `${info.ref}_${info.length};`
            : info.ref;
        },
      };
    }

    if (values.every((value) => typeof value === "number")) {
      const lengths = new Set(
        values.map((value) =>
          utf8ByteLength(canonicalizeNumber(value as number)),
        ),
      );
      const length = lengths.size === 1 ? [...lengths][0]! : undefined;

      return {
        column:
          length === undefined
            ? { kind: "variable-slot", keyRef, slotType: "number" }
            : { kind: "fixed-slot", keyRef, slotType: "number", length },
        encodeCell(value: unknown): string {
          const info = scalarInfo(value as number);

          return length === undefined
            ? `${info.ref}_${info.length};`
            : info.ref;
        },
      };
    }

    if (values.every((value) => value === true)) {
      return {
        column: { kind: "literal", keyRef, value: true },
        encodeCell: () => "",
      };
    }

    if (values.every((value) => value === false)) {
      return {
        column: { kind: "literal", keyRef, value: false },
        encodeCell: () => "",
      };
    }

    if (values.every((value) => value === null)) {
      return {
        column: { kind: "literal", keyRef, value: null },
        encodeCell: () => "",
      };
    }

    const marker = values.every((value) => isPlainObject(value))
      ? "{"
      : values.every((value) => Array.isArray(value))
        ? "["
        : "*";

    return {
      column: { kind: "node", keyRef, marker },
      encodeCell(value: unknown): string {
        return encodeNode(value, depth + 2);
      },
    };
  };

  const encodeTable = (
    input: unknown[],
    shapeKeys: string[],
    depth: number,
  ): string => {
    const columns = shapeKeys.map((key) =>
      tableColumn(
        keyRef(key),
        input.map((item) => (item as Record<string, unknown>)[key]),
        depth,
      ),
    );
    const header = columns
      .map(({ column }) => {
        if (column.kind === "fixed-slot") {
          const sigil = column.slotType === "string" ? "'" : '"';

          return `@${column.keyRef}${sigil}${column.length}`;
        }

        if (column.kind === "variable-slot") {
          const sigil = column.slotType === "string" ? "'" : '"';

          return `@${column.keyRef}${sigil}`;
        }

        if (column.kind === "literal") {
          return `@${column.keyRef}${column.value === null ? "z" : column.value ? "t" : "f"}`;
        }

        return `@${column.keyRef}${column.marker}`;
      })
      .join("");
    const rows = input
      .map((item) =>
        columns
          .map((column, index) =>
            column.encodeCell(
              (item as Record<string, unknown>)[shapeKeys[index]!],
            ),
          )
          .join(""),
      )
      .join("");

    return `[~${columns.length}.${input.length}:${header}:${rows}]`;
  };

  const ancestors = new Set<object>();

  const encodeNode = (input: unknown, depth = 0): string => {
    assertNestingDepth(depth, "HBS3");

    if (typeof input === "bigint") {
      throw new Error("BigInt is not a supported JSON type");
    }
    if (input === null) {
      return "z";
    }
    if (input === true) {
      return "t";
    }
    if (input === false) {
      return "f";
    }
    if (typeof input === "string" || typeof input === "number") {
      return scalarToken(input);
    }
    if (Array.isArray(input)) {
      if (ancestors.has(input)) {
        throw new Error("circular JSON value");
      }

      rejectHostArrayProperties(input);
      ancestors.add(input);

      try {
        for (let index = 0; index < input.length; index += 1) {
          if (!hasOwn(input, index)) {
            throw new Error("sparse arrays are unsupported JSON values");
          }
        }

        const shapeKeys = homogeneousObjectKeys(input);

        if (shapeKeys !== null) {
          return encodeTable(input, shapeKeys, depth);
        }

        const parts = input.map((item) => encodeNode(item, depth + 1));

        return `[${parts.join("")}]`;
      } finally {
        ancestors.delete(input);
      }
    }

    if (isPlainObject(input)) {
      if (ancestors.has(input)) {
        throw new Error("circular JSON value");
      }

      rejectHostObjectProperties(input);
      ancestors.add(input);

      try {
        const entries = sortObjectKeys(input).map(
          (key) => [key, input[key]] as const,
        );
        const refs = entries.map(([key]) => keyRef(key));

        return `{${entries
          .map(
            ([, child], index) =>
              `@${refs[index]}${encodeNode(child, depth + 1)}`,
          )
          .join("")}}`;
      } finally {
        ancestors.delete(input);
      }
    }

    throw new Error("unsupported JSON value");
  };

  const T = encodeNode(value);
  const K = state.keys.join(",");
  const guards = validatedOptions.guards;
  const guardTagLength = validatedOptions.guardTagLength;
  const G = guards
    ? state.slotOrder
        .map(({ slot, encoded, length }) =>
          digest(slotGuardPreimage(slot, length, encoded), guards).slice(
            0,
            guardTagLength,
          ),
        )
        .join(",")
    : "";

  const V = state.slotOrder.map(({ encoded }) => encoded).join("");
  const body = `${T}${K}${G}${V}`;
  const payload = `${utf8ByteLength(body)}.${utf8ByteLength(T)}.${utf8ByteLength(K)}.${utf8ByteLength(G)}:${body}`;
  const integrityTagLength = validatedOptions.integrityTagLength;
  const tag = digest(payload, options.integrity).slice(0, integrityTagLength);

  return `hbs3.${tag}.${payload}`;
}

export function decodeHbs(
  token: string,
  options: HbsOptions = {},
): DecodeResult {
  const validatedOptions = validateHbsOptions(options);
  const match = /^hbs3\.([^.]+)\.(\d+)\.(\d+)\.(\d+)\.(\d+):(.*)$/s.exec(token);

  if (!match) {
    throw new Error("malformed hbs3 header");
  }

  const [
    ,
    integrity,
    bodyLenRaw,
    schemaLenRaw,
    keysLenRaw,
    guardsLenRaw,
    body,
  ] = match as RegExpExecArray &
    [string, string, string, string, string, string, string];

  const bodyLen = parseCanonicalLength(bodyLenRaw, "bodyLen");
  const schemaLen = parseCanonicalLength(schemaLenRaw, "schemaLen");
  const keysLen = parseCanonicalLength(keysLenRaw, "keysLen");
  const guardsLen = parseCanonicalLength(guardsLenRaw, "guardsLen");

  if (schemaLen + keysLen + guardsLen > bodyLen) {
    throw new Error("header segment lengths exceed bodyLen");
  }

  /* v8 ignore next -- @preserve header regex always captures body */
  const availableBody = body ?? "";
  const availableBodyLength = utf8ByteLength(availableBody);

  if (availableBodyLength > bodyLen) {
    throw new Error("body length exceeds declared bodyLen header");
  }

  const truncated = availableBodyLength < bodyLen;
  const integrityTagLength = validatedOptions.integrityTagLength;
  validateHexTag("integrity", integrity, integrityTagLength);
  const checksum = truncated
    ? null
    : constantTimeTagEqual(
        digest(
          `${bodyLen}.${schemaLen}.${keysLen}.${guardsLen}:${availableBody}`,
          options.integrity,
        ).slice(0, integrityTagLength),
        integrity,
      );

  if (availableBodyLength < schemaLen) {
    throw new Error("schema tape is truncated");
  }

  const T = sliceUtf8(availableBody, 0, schemaLen);
  const K = sliceUtf8(availableBody, schemaLen, schemaLen + keysLen);
  const G = sliceUtf8(
    availableBody,
    schemaLen + keysLen,
    schemaLen + keysLen + guardsLen,
  );
  const V =
    availableBodyLength < schemaLen + keysLen + guardsLen
      ? ""
      : sliceUtf8(availableBody, schemaLen + keysLen + guardsLen);
  const keysComplete = availableBodyLength >= schemaLen + keysLen;
  const keys = parseKeys(K, keysComplete);
  const parsed = parseSchema(T);

  if (
    parsed.root.kind !== "object" &&
    parsed.root.kind !== "array" &&
    parsed.root.kind !== "table"
  ) {
    throw new Error("HBS3 root schema must be a plain object or array");
  }

  if (keysComplete) {
    validateCanonicalSchema(parsed.root, keys);
  }

  const slots = decodeSlots(parsed.slotOrder, V);
  const holes: Hole[] = [];
  const value = buildValue(parsed.root, keys, slots, "", holes);
  const guardResult = verifyGuards(
    parsed.slotOrder,
    slots,
    G,
    validatedOptions.guards,
  );

  return {
    value,
    truncated,
    checksum,
    holes,
    slotGuards: guardResult.slotGuards,
    guardIssues: guardResult.guardIssues,
  };
}

function digest(
  input: string,
  options?: IntegrityOptions | Exclude<GuardOptions, false>,
): string {
  const algorithm = validateDigestOptions(options);

  if (algorithm === "hmac-sha256") {
    const secret = (options as { secret: string }).secret;

    return createHmac("sha256", secret).update(input, "utf8").digest("hex");
  }

  return createHash("sha256").update(input, "utf8").digest("hex");
}

function tagLength(
  options: { tagLength?: number } | undefined,
  defaultLength: number,
): number {
  const length = options?.tagLength ?? defaultLength;

  if (!Number.isInteger(length)) {
    throw new Error("tagLength must be an integer");
  }

  if (length < 2) {
    throw new Error("tagLength must be at least 2");
  }

  if (length > 64) {
    throw new Error("tagLength must be at most 64");
  }

  return length;
}

function validateHbsOptions(options: HbsOptions): {
  integrityTagLength: number;
  guards?: Exclude<GuardOptions, false>;
  guardTagLength: number;
} {
  validateDigestOptions(options.integrity);

  const integrityTagLength = tagLength(options.integrity, 16);
  const guards =
    options.guards === false || options.guards === undefined
      ? undefined
      : options.guards;
  const guardTagLength = guards ? tagLength(guards, 6) : 0;

  if (guards) {
    validateDigestOptions(guards);
  }

  return {
    integrityTagLength,
    guardTagLength,
    ...(guards ? { guards } : {}),
  };
}

function validateHexTag(
  label: string,
  value: string,
  expectedLength: number,
): void {
  if (value.length !== expectedLength) {
    throw new Error(`${label} tag length does not match tagLength`);
  }

  if (!HEX_TAG_RE.test(value)) {
    throw new Error(`${label} tag must be lowercase hexadecimal`);
  }
}

function constantTimeTagEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(textEncoder.encode(left), textEncoder.encode(right));
}

function validateDigestOptions(
  options?: IntegrityOptions | Exclude<GuardOptions, false>,
): "sha256" | "hmac-sha256" {
  const algorithm = options?.algorithm ?? "sha256";

  if (algorithm !== "sha256" && algorithm !== "hmac-sha256") {
    throw new Error("unsupported algorithm");
  }

  if (algorithm === "hmac-sha256") {
    const secret = (options as { secret?: string } | undefined)?.secret;

    if (!secret) {
      throw new Error("hmac-sha256 requires a secret");
    }
  }

  return algorithm;
}

export function utf8ByteLength(input: string): number {
  return textEncoder.encode(input).length;
}

export function sliceUtf8(input: string, start: number, end?: number): string {
  return decodeUtf8Bytes(textEncoder.encode(input), start, end);
}

function decodeUtf8Bytes(
  input: Uint8Array,
  start: number,
  end?: number,
): string {
  try {
    return textDecoder.decode(input.subarray(start, end));
  } catch {
    throw new Error("invalid UTF-8 boundary");
  }
}

function parseCanonicalLength(raw: string, label: string): number {
  return parseCanonicalUint(raw, `${label} header length`);
}

function parseCanonicalUint(raw: string, label: string): number {
  if (!CANONICAL_UINT_RE.test(raw)) {
    throw new Error(`non-canonical ${label}`);
  }

  if (raw.length > MAX_DECIMAL_DIGITS) {
    throw new Error(`${label} exceeds safe integer range`);
  }

  const value = Number(raw);

  if (!Number.isSafeInteger(value)) {
    throw new Error(`${label} exceeds safe integer range`);
  }

  return value;
}

function assertNestingDepth(depth: number, label: string): void {
  if (depth > MAX_NESTING_DEPTH) {
    throw new Error(`${label} nesting depth exceeds limit`);
  }
}

export function slotGuardPreimage(
  slot: SlotRef,
  encodedLength: number,
  slotValue: string,
): string {
  return `hbs3-slot:${slot}:${encodedLength}:${slotValue}`;
}

function isSupportedRoot(
  value: unknown,
): value is Record<string, unknown> | unknown[] {
  return Array.isArray(value) || isPlainObject(value);
}

function rejectHostArrayProperties(value: unknown[]): void {
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw new Error("array prototypes are unsupported JSON values");
  }

  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "symbol") {
      throw new Error("symbol keys are unsupported JSON values");
    }
    if (key === "length") {
      continue;
    }
    if (!CANONICAL_UINT_RE.test(key) || Number(key) >= value.length) {
      throw new Error("array expando properties are unsupported JSON values");
    }

    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    /* v8 ignore next -- @preserve Reflect.ownKeys guarantees a descriptor */
    if (descriptor === undefined) {
      throw new Error("array properties are unsupported JSON values");
    }
    if (!descriptor.enumerable) {
      throw new Error("non-enumerable properties are unsupported JSON values");
    }
    if (!("value" in descriptor)) {
      throw new Error("accessor properties are unsupported JSON values");
    }
  }
}

function rejectHostObjectProperties(value: Record<string, unknown>): void {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "symbol") {
      throw new Error("symbol keys are unsupported JSON values");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    /* v8 ignore next -- @preserve Reflect.ownKeys guarantees a descriptor */
    if (descriptor === undefined) {
      throw new Error("object properties are unsupported JSON values");
    }
    if (!descriptor.enumerable) {
      throw new Error("non-enumerable properties are unsupported JSON values");
    }
    if (!("value" in descriptor)) {
      throw new Error("accessor properties are unsupported JSON values");
    }
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);

  return prototype === Object.prototype;
}

function parseKeys(raw: string, complete: boolean): string[] {
  if (raw === "") {
    return [];
  }

  const parts = raw.split(",");
  const keys = complete
    ? parts
    : raw.endsWith(",")
      ? parts.slice(0, -1)
      : parts.slice(0, -1);

  if (keys.some((key) => !isValidHbsKey(key))) {
    throw new Error("malformed key dictionary");
  }

  if (new Set(keys).size !== keys.length) {
    throw new Error("duplicate key in malformed key dictionary");
  }

  return keys;
}

function validateCanonicalSchema(root: Node, keys: string[]): void {
  const encounteredKeys: string[] = [];
  const seenKeys = new Set<string>();
  let hasMissingKeyRef = false;

  const resolveKey = (keyRef: string): string | undefined => {
    const key = keys[decodeRef(keyRef)];

    if (key === undefined) {
      hasMissingKeyRef = true;
    }

    return key;
  };

  const encounterKey = (keyRef: string): string | undefined => {
    const key = resolveKey(keyRef);

    if (key !== undefined && !seenKeys.has(key)) {
      seenKeys.add(key);
      encounteredKeys.push(key);
    }

    return key;
  };

  const assertSorted = (
    resolvedKeys: Array<string | undefined>,
    label: string,
  ): void => {
    if (resolvedKeys.some((key) => key === undefined)) {
      return;
    }

    const actual = resolvedKeys as string[];
    const sorted = [...actual].sort();

    for (let index = 0; index < actual.length; index += 1) {
      if (actual[index] !== sorted[index]) {
        throw new Error(`non-canonical ${label} order`);
      }
    }
  };

  const visit = (node: Node): void => {
    if (node.kind === "literal" || node.kind === "slot") {
      return;
    }

    if (node.kind === "array") {
      for (const item of node.items) {
        visit(item);
      }
      return;
    }

    if (node.kind === "table") {
      const columnKeys = node.columns.map((column) =>
        resolveKey(column.keyRef),
      );

      assertSorted(columnKeys, "table column");

      for (const row of node.rows) {
        const rowKeys = node.columns.map((column) =>
          encounterKey(column.keyRef),
        );
        let cellIndex = 0;

        for (let index = 0; index < node.columns.length; index += 1) {
          const column = node.columns[index]!;

          if (column.kind === "literal") {
            continue;
          }

          const cell = row[cellIndex];

          cellIndex += 1;

          if (rowKeys[index] !== undefined && cell !== undefined) {
            visit(cell);
          }
        }
      }
      return;
    }

    const entryKeys = node.entries.map((entry) => encounterKey(entry.keyRef));

    assertSorted(entryKeys, "object entry");

    for (let index = 0; index < node.entries.length; index += 1) {
      if (entryKeys[index] !== undefined) {
        visit(node.entries[index]!.value);
      }
    }
  };

  visit(root);

  if (hasMissingKeyRef) {
    return;
  }

  if (encounteredKeys.length !== keys.length) {
    throw new Error("non-canonical key dictionary");
  }

  for (let index = 0; index < keys.length; index += 1) {
    if (encounteredKeys[index] !== keys[index]) {
      throw new Error("non-canonical key dictionary");
    }
  }
}

function parseSchema(schema: string): { root: Node; slotOrder: SlotInfo[] } {
  const slotMap = new Map<SlotRef, SlotInfo>();
  const slotOrder: SlotInfo[] = [];
  let pos = 0;

  const readRef = (): string => {
    if (schema[pos] === "{") {
      const end = schema.indexOf("}", pos + 1);

      if (end === -1) {
        throw new Error("schema malformed ref");
      }

      const ref = schema.slice(pos, end + 1);
      decodeRef(ref);
      pos = end + 1;

      return ref;
    }

    const ref = schema[pos++];

    if (ref === undefined) {
      throw new Error("schema missing ref");
    }

    decodeRef(ref);

    return ref;
  };

  const readDecimal = (label: string): number => {
    const start = pos;

    while (/\d/.test(schema[pos] ?? "")) {
      pos += 1;
    }

    if (pos === start) {
      throw new Error(`schema ${label} malformed`);
    }

    const raw = schema.slice(start, pos);

    return parseCanonicalUint(raw, `schema ${label}`);
  };

  const registerSlot = (
    sigil: "'" | '"',
    ref: string,
    length: number,
  ): Node => {
    const slot = `${sigil}${ref}` as SlotRef;
    const slotType = sigil === "'" ? "string" : "number";
    const existing = slotMap.get(slot);

    if (existing) {
      if (existing.type !== slotType || existing.length !== length) {
        throw new Error("schema slot reference has conflicting type or length");
      }
    } else {
      const info = { slot, type: slotType, length } satisfies SlotInfo;

      slotMap.set(slot, info);
      slotOrder.push(info);
    }

    return { kind: "slot", slot, slotType, length };
  };

  const readSlot = (sigil: "'" | '"'): Node => {
    pos += 1;
    const ref = readRef();

    if (schema[pos] !== "_") {
      throw new Error("schema slot length separator missing");
    }

    pos += 1;
    const length = readDecimal("slot length");

    return registerSlot(sigil, ref, length);
  };

  const readTableColumn = (): TableColumn => {
    if (schema[pos] !== "@") {
      throw new Error("schema table expected key ref");
    }

    pos += 1;
    const keyRef = readRef();
    const marker = schema[pos++];

    if (marker === "'" || marker === '"') {
      const slotType = marker === "'" ? "string" : "number";
      const start = pos;

      while (/\d/.test(schema[pos] ?? "")) {
        pos += 1;
      }

      if (pos === start) {
        return { kind: "variable-slot", keyRef, slotType };
      }
      const rawLength = schema.slice(start, pos);

      const length = parseCanonicalUint(
        rawLength,
        "schema table column length",
      );

      return {
        kind: "fixed-slot",
        keyRef,
        slotType,
        length,
      };
    }

    if (marker === "t" || marker === "f" || marker === "z") {
      return {
        kind: "literal",
        keyRef,
        value: marker === "z" ? null : marker === "t",
      };
    }

    if (marker === "{" || marker === "[" || marker === "*") {
      return { kind: "node", keyRef, marker };
    }

    throw new Error("schema table column marker malformed");
  };

  const readTableCell = (column: TableColumn, depth: number): Node | null => {
    if (column.kind === "literal") {
      return null;
    }

    if (column.kind === "fixed-slot") {
      const sigil = column.slotType === "string" ? "'" : '"';
      const ref = readRef();

      return registerSlot(sigil, ref, column.length);
    }

    if (column.kind === "variable-slot") {
      const sigil = column.slotType === "string" ? "'" : '"';
      const ref = readRef();

      if (schema[pos] !== "_") {
        throw new Error("schema table slot length separator missing");
      }

      pos += 1;
      const length = readDecimal("table slot length");

      if (schema[pos] !== ";") {
        throw new Error("schema table slot length terminator missing");
      }

      pos += 1;

      return registerSlot(sigil, ref, length);
    }

    const cell = readNode(depth);

    if (column.marker === "{" && cell.kind !== "object") {
      throw new Error("schema table object column cell must be object");
    }
    if (
      column.marker === "[" &&
      cell.kind !== "array" &&
      cell.kind !== "table"
    ) {
      throw new Error("schema table array column cell must be array");
    }

    return cell;
  };

  const readTable = (depth: number): Node => {
    pos += 1;
    const keyCount = readDecimal("table key count");

    if (schema[pos] !== ".") {
      throw new Error("schema table row separator missing");
    }

    pos += 1;
    const rowCount = readDecimal("table row count");

    if (schema[pos] !== ":") {
      throw new Error("schema table header separator missing");
    }

    pos += 1;
    const columns: TableColumn[] = [];
    const keyRefs = new Set<string>();

    for (let index = 0; index < keyCount; index += 1) {
      const column = readTableColumn();

      if (keyRefs.has(column.keyRef)) {
        throw new Error("schema table has duplicate column key ref");
      }

      keyRefs.add(column.keyRef);
      columns.push(column);
    }

    if (schema[pos] !== ":") {
      throw new Error("schema table body separator missing");
    }

    pos += 1;
    const rows: Node[][] = [];

    for (let rowIndex = 0; rowIndex < rowCount; rowIndex += 1) {
      const row: Node[] = [];

      for (const column of columns) {
        const cell = readTableCell(column, depth + 1);

        if (cell !== null) {
          row.push(cell);
        }
      }

      rows.push(row);
    }

    return { kind: "table", columns, rows };
  };

  const readNode = (depth = 0): Node => {
    assertNestingDepth(depth, "schema");

    const token = schema[pos];

    if (token === "{") {
      pos += 1;
      const entries: Array<{ keyRef: string; value: Node }> = [];
      const keyRefs = new Set<string>();

      while (schema[pos] !== "}") {
        if (pos >= schema.length) {
          throw new Error("schema object not closed");
        }

        if (schema[pos] !== "@") {
          throw new Error("schema expected key ref");
        }

        pos += 1;

        const keyRef = readRef();

        if (keyRefs.has(keyRef)) {
          throw new Error("schema object has duplicate key ref");
        }

        keyRefs.add(keyRef);
        entries.push({ keyRef, value: readNode(depth + 1) });
      }

      pos += 1;

      return { kind: "object", entries };
    }
    if (token === "[") {
      pos += 1;

      if (schema[pos] === "~") {
        const table = readTable(depth + 1);

        if (schema[pos] !== "]") {
          throw new Error("schema table not closed");
        }

        pos += 1;

        return table;
      }

      const items: Node[] = [];

      while (schema[pos] !== "]") {
        if (pos >= schema.length) {
          throw new Error("schema array not closed");
        }

        items.push(readNode(depth + 1));
      }

      pos += 1;

      return { kind: "array", items };
    }
    if (token === "t") {
      pos += 1;
      return { kind: "literal", value: true };
    }
    if (token === "f") {
      pos += 1;
      return { kind: "literal", value: false };
    }
    if (token === "z") {
      pos += 1;
      return { kind: "literal", value: null };
    }
    if (token === "'") {
      return readSlot("'");
    }

    if (token === '"') {
      return readSlot('"');
    }

    throw new Error("schema token malformed");
  };

  const root = readNode();

  if (pos !== schema.length) {
    throw new Error("schema has trailing data");
  }

  return { root, slotOrder };
}

function decodeSlots(slotOrder: SlotInfo[], V: string): Map<SlotRef, SlotInfo> {
  const slots = new Map<SlotRef, SlotInfo>();
  let offset = 0;
  const valueBytes = textEncoder.encode(V);
  const availableBytes = valueBytes.length;

  for (const slot of slotOrder) {
    const availableLength = Math.max(
      0,
      Math.min(slot.length, availableBytes - offset),
    );
    const info: SlotInfo = { ...slot };

    if (availableLength === slot.length) {
      const encoded = decodeUtf8Bytes(valueBytes, offset, offset + slot.length);
      info.encoded = encoded;

      try {
        const decoded = JSON.parse(encoded) as unknown;

        if (
          slot.type === "string" &&
          typeof decoded === "string" &&
          canonicalizeString(decoded) === encoded
        ) {
          info.value = decoded;
        } else if (
          slot.type === "number" &&
          typeof decoded === "number" &&
          Number.isFinite(decoded) &&
          canonicalizeNumber(decoded) === encoded
        ) {
          info.value = decoded;
        } else {
          info.kind = "invalid-slot";
        }
      } catch {
        info.kind = "invalid-slot";
      }
    } else if (availableLength > 0) {
      info.kind = "truncated-slot";
      info.availableLength = availableLength;
    } else {
      info.kind = "missing-slot";
    }
    slots.set(slot.slot, info);
    offset += slot.length;
  }

  if (availableBytes > offset) {
    throw new Error("value stream has trailing data");
  }

  return slots;
}

function buildValue(
  node: Node,
  keys: string[],
  slots: Map<SlotRef, SlotInfo>,
  path: string,
  holes: Hole[],
  depth = 0,
): unknown {
  assertNestingDepth(depth, "decoded value");

  if (node.kind === "literal") {
    return node.value;
  }

  if (node.kind === "slot") {
    const info = slots.get(node.slot);

    if (info?.kind !== undefined || info?.value === undefined) {
      /* v8 ignore next -- @preserve parsed slots always have slot info */
      const kind = info?.kind ?? "missing-slot";

      holes.push({
        path,
        kind,
        slot: node.slot,
        expectedType: node.slotType,
        expectedLength: node.length,
        ...(info?.availableLength !== undefined
          ? { availableLength: info.availableLength }
          : {}),
      });

      return undefined;
    }

    return info.value;
  }
  if (node.kind === "array") {
    return node.items.map((item, index) => {
      const child = buildValue(
        item,
        keys,
        slots,
        `${path}/${index}`,
        holes,
        depth + 1,
      );

      return child === undefined ? null : child;
    });
  }

  if (node.kind === "table") {
    return node.rows.map((row, rowIndex) => {
      const out: Record<string, unknown> = {};
      let cellIndex = 0;

      for (const column of node.columns) {
        const key = keys[decodeRef(column.keyRef)];

        if (key === undefined) {
          holes.push({ path: `${path}/${rowIndex}`, kind: "missing-key" });

          if (column.kind !== "literal") {
            cellIndex += 1;
          }

          continue;
        }

        if (column.kind === "literal") {
          assignJsonProperty(out, key, column.value);
          continue;
        }

        const cell = row[cellIndex];

        cellIndex += 1;

        if (cell === undefined) {
          throw new Error("schema table row cell missing");
        }

        const child = buildValue(
          cell,
          keys,
          slots,
          `${path}/${rowIndex}/${key}`,
          holes,
          depth + 1,
        );

        if (child !== undefined) {
          assignJsonProperty(out, key, child);
        }
      }

      return out;
    });
  }

  const out: Record<string, unknown> = {};

  for (const entry of node.entries) {
    const key = keys[decodeRef(entry.keyRef)];

    if (key === undefined) {
      holes.push({ path, kind: "missing-key" });
      continue;
    }

    const child = buildValue(
      entry.value,
      keys,
      slots,
      `${path}/${key}`,
      holes,
      depth + 1,
    );

    if (child !== undefined) {
      assignJsonProperty(out, key, child);
    }
  }

  return out;
}

function assignJsonProperty(
  target: Record<string, unknown>,
  key: string,
  value: unknown,
): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function verifyGuards(
  slotOrder: SlotInfo[],
  slots: Map<SlotRef, SlotInfo>,
  G: string,
  options?: Exclude<GuardOptions, false>,
): {
  slotGuards: Record<string, true | false | null>;
  guardIssues: GuardIssue[];
} {
  if (!options) {
    return { slotGuards: {}, guardIssues: [] };
  }
  validateDigestOptions(options);

  const guards = G === "" ? [] : G.split(",");
  const guardWidth = tagLength(options, 6);
  const slotGuards: Record<string, true | false | null> = {};
  const guardIssues: GuardIssue[] = [];

  for (let index = 0; index < slotOrder.length; index += 1) {
    const slot = slotOrder[index]!;
    const info = slots.get(slot.slot);
    const guard = guards[index];

    if (guard === undefined || guard === "") {
      slotGuards[slot.slot] = null;
      guardIssues.push({
        index,
        kind: "missing-guard",
        slot: slot.slot,
        expectedLength: guardWidth,
        availableLength: 0,
      });
      continue;
    }
    if (guard.length < guardWidth) {
      slotGuards[slot.slot] = null;
      guardIssues.push({
        index,
        kind: "truncated-guard",
        slot: slot.slot,
        expectedLength: guardWidth,
        availableLength: guard.length,
      });
      continue;
    }
    if (guard.length > guardWidth || !HEX_TAG_RE.test(guard)) {
      slotGuards[slot.slot] = null;
      guardIssues.push({
        index,
        kind: "invalid-guard",
        slot: slot.slot,
        expectedLength: guardWidth,
        availableLength: guard.length,
      });
      continue;
    }
    if (info?.encoded === undefined || info.kind !== undefined) {
      slotGuards[slot.slot] = null;
    } else {
      slotGuards[slot.slot] = constantTimeTagEqual(
        digest(
          slotGuardPreimage(slot.slot, slot.length, info.encoded),
          options,
        ).slice(0, guardWidth),
        guard,
      );
    }
  }

  for (let index = slotOrder.length; index < guards.length; index += 1) {
    const guard = guards[index]!;
    guardIssues.push({
      index,
      kind: "extra-guard",
      expectedLength: guardWidth,
      availableLength: guard.length,
    });
  }

  return { slotGuards, guardIssues };
}
