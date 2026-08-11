import {
  alphabetFingerprint,
  directTokens,
  isTokenLiteral,
  simpleTokenSuffixes,
  tokenBanks,
  tokenByteLength,
  tokenCapacity,
  tokenFor,
  tokenIndex,
  tokenPrefix,
} from "./alphabet.ts";

const FORMAT = "dia1";
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const MAX_EXPANDED_BYTES = 128 * 1024 * 1024;
const MAX_ENTRY_BYTES = 4096;
const MAX_DEPTH = 128;
const MAX_DECODE_NODES = 1_000_000;
const MAX_SPLICE_BYTES = 512;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const numberPattern = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

export type DialectOptions = {
  words?: readonly string[];
  minWordBytes?: number;
  minWordOccurrences?: number;
  maxWords?: number;
  maxValues?: number;
  maxShapes?: number;
};

type JsonScalar = null | boolean | number | string;
type JsonObject = { [key: string]: JsonValue };
type JsonValue = JsonScalar | JsonValue[] | JsonObject;

type ResolvedOptions = {
  words: string[];
  minWordBytes: number;
  minWordOccurrences: number;
  maxWords: number;
  maxValues: number;
  maxShapes: number;
};

type Candidate = {
  count: number;
  score: number;
  value: string;
};

type ExactCandidate = Candidate & {
  json: string;
};

type LocalRelation =
  | { kind: "dynamic" }
  | { kind: "copy"; source: number }
  | { kind: "concat"; prefix: string; source: number; suffix: string };

type ShapeField = LocalRelation | { json: string; kind: "constant" };

type ShapeGroup = {
  count: number;
  fields: LocalRelation[];
  keys: string[];
  records: JsonObject[];
  signature: string;
};

type Shape = {
  fields: ShapeField[];
  keys: string[];
  score: number;
  signature: string;
};

type Stats = {
  exact: Map<string, { count: number; json: string }>;
  keys: Map<string, number>;
  shapeGroups: Map<string, ShapeGroup>;
  strings: string[];
};

type TrieNode = {
  index?: number;
  next: Map<string, TrieNode>;
};

type Dialect = {
  exactIndex: Map<string, number>;
  exactValues: string[];
  keyIndex: Map<string, number>;
  keys: string[];
  shapeIndex: Map<string, number>;
  shapes: Shape[];
  wordIndex: Map<string, number>;
  words: string[];
  wordTrie: TrieNode;
};

type Usage = {
  exact: number[];
  shapes: number[];
  words: number[];
};

type Encoded = {
  exactUses: number[];
  shapeUses: number[];
  wire: string;
  wordUses: number[];
};

type Splice = {
  dropLeft: number;
  dropRight: number;
  prefix: string;
  sourceDistance: number;
  suffix: string;
};

type DecodedShape = {
  fields: ShapeField[];
  keys: string[];
};

type DecodeTables = {
  exactValues: string[];
  keys: string[];
  shapes: DecodedShape[];
  words: string[];
};

type DecodeBudget = {
  bytesRemaining: number;
  nodesRemaining: number;
};

type Header = {
  exactCount: number;
  expandedBytes: number;
  keyCount: number;
  payload: string;
  shapeCount: number;
  wordCount: number;
};

export function encodeDialect(
  value: unknown,
  options: DialectOptions = {},
): string {
  const resolved = resolveOptions(options);
  const json = serializeJson(value);
  const normalized = JSON.parse(json) as JsonValue;
  const stats = collectStats(normalized);

  let dialect = buildDialect(stats, resolved);
  let encoded = encodeDocument(normalized, dialect);

  for (let pass = 0; pass < 3; pass += 1) {
    const pruned = pruneDialect(dialect, encoded.usage);
    if (sameDialectSize(dialect, pruned)) {
      break;
    }

    dialect = pruned;
    encoded = encodeDocument(normalized, dialect);
  }

  const tables = serializeTables(dialect);
  const header = [
    FORMAT,
    utf8Length(json),
    dialect.keys.length,
    dialect.words.length,
    dialect.exactValues.length,
    dialect.shapes.length,
    alphabetFingerprint,
  ].join(".");

  return header + ":" + tables + encoded.body;
}

export function decodeDialect(encoded: string): unknown {
  const header = parseHeader(encoded);
  if (header.expandedBytes > MAX_EXPANDED_BYTES) {
    throw new Error("dialect expanded payload exceeds the decoder limit");
  }

  const reader = new ByteReader(textEncoder.encode(header.payload));
  const keys = readStringTable(reader, header.keyCount, "key");
  const words = readStringTable(reader, header.wordCount, "word");
  const exactValues = readExactTable(reader, header.exactCount);
  const shapes = readShapeTable(reader, header.shapeCount, keys);
  const tables = { exactValues, keys, shapes, words };
  const budget: DecodeBudget = {
    bytesRemaining: header.expandedBytes,
    nodesRemaining: Math.min(header.expandedBytes, MAX_DECODE_NODES),
  };

  const value = decodeValue(reader, tables, budget, undefined, 0);
  if (!reader.done()) {
    throw new Error("dialect body contains trailing bytes");
  }

  if (budget.bytesRemaining !== 0) {
    throw new Error("dialect expanded byte budget was not fully consumed");
  }

  const json = JSON.stringify(value);
  if (utf8Length(json) !== header.expandedBytes) {
    throw new Error("dialect expanded byte length does not match the header");
  }

  return value;
}

function resolveOptions(options: DialectOptions): ResolvedOptions {
  const minWordBytes = options.minWordBytes ?? 4;
  const minWordOccurrences = options.minWordOccurrences ?? 3;
  const maxWords = options.maxWords ?? tokenCapacity;
  const maxValues = options.maxValues ?? 768;
  const maxShapes = options.maxShapes ?? 256;

  assertIntegerRange(minWordBytes, "minWordBytes", 4, 1024);
  assertIntegerRange(minWordOccurrences, "minWordOccurrences", 2, 1_000_000);
  assertIntegerRange(maxWords, "maxWords", 0, tokenCapacity);
  assertIntegerRange(maxValues, "maxValues", 0, tokenCapacity);
  assertIntegerRange(maxShapes, "maxShapes", 0, tokenCapacity);

  const words = uniqueStrings(options.words ?? [], "words");

  return {
    words,
    minWordBytes,
    minWordOccurrences,
    maxWords,
    maxValues,
    maxShapes,
  };
}

function serializeJson(value: unknown): string {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new Error("dialect input must be JSON serializable");
  }
  if (utf8Length(json) > MAX_EXPANDED_BYTES) {
    throw new Error("dialect input exceeds the encoder limit");
  }

  return json;
}

function collectStats(root: JsonValue): Stats {
  const stats: Stats = {
    exact: new Map(),
    keys: new Map(),
    shapeGroups: new Map(),
    strings: [],
  };

  visitValue(root, true, stats, 0);

  return stats;
}

function visitValue(
  value: JsonValue,
  root: boolean,
  stats: Stats,
  depth: number,
): void {
  if (depth > MAX_DEPTH) {
    throw new Error("dialect input exceeds the nesting limit");
  }

  if (!root) {
    const json = JSON.stringify(value);
    const existing = stats.exact.get(json);
    if (existing) {
      existing.count += 1;
    } else if (utf8Length(json) <= MAX_ENTRY_BYTES) {
      stats.exact.set(json, { count: 1, json });
    }
  }

  if (typeof value === "string") {
    stats.strings.push(value);

    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      visitValue(item, false, stats, depth + 1);
    }

    return;
  }

  const keys = Object.keys(value);
  const fields = inferLocalRelations(value, keys);
  const signature = shapeSignature(keys, fields);
  const group = stats.shapeGroups.get(signature);

  if (group) {
    group.count += 1;
    group.records.push(value);
  } else {
    stats.shapeGroups.set(signature, {
      count: 1,
      fields,
      keys,
      records: [value],
      signature,
    });
  }

  for (const key of keys) {
    stats.keys.set(key, (stats.keys.get(key) ?? 0) + 1);
    visitValue(value[key]!, false, stats, depth + 1);
  }
}

function inferLocalRelations(
  record: JsonObject,
  keys: string[],
): LocalRelation[] {
  return keys.map((key, index) => {
    const target = record[key]!;

    for (let source = index - 1; source >= 0; source -= 1) {
      const candidate = record[keys[source]!]!;
      if (
        isJsonScalar(target) &&
        isJsonScalar(candidate) &&
        target === candidate
      ) {
        return { kind: "copy", source };
      }
    }

    if (typeof target !== "string") {
      return { kind: "dynamic" };
    }

    let best:
      | { kind: "concat"; prefix: string; source: number; suffix: string }
      | undefined;

    for (let source = 0; source < index; source += 1) {
      const candidate = record[keys[source]!]!;
      if (
        typeof candidate !== "string" ||
        utf8Length(candidate) < 8 ||
        !target.includes(candidate)
      ) {
        continue;
      }

      const position = target.indexOf(candidate);
      const relation = {
        kind: "concat" as const,
        prefix: target.slice(0, position),
        source,
        suffix: target.slice(position + candidate.length),
      };
      if (
        !best ||
        utf8Length(candidate) > utf8Length(record[keys[best.source]!] as string)
      ) {
        best = relation;
      }
    }

    return best ?? { kind: "dynamic" };
  });
}

function shapeSignature(keys: string[], fields: LocalRelation[]): string {
  const relations = fields.map((field) => {
    if (field.kind === "dynamic") {
      return ["d"];
    }
    if (field.kind === "copy") {
      return ["r", field.source];
    }

    return ["p", field.source, field.prefix, field.suffix];
  });

  return JSON.stringify([keys, relations]);
}

function buildDialect(stats: Stats, options: ResolvedOptions): Dialect {
  const keys = [...stats.keys]
    .sort(
      ([leftKey, leftCount], [rightKey, rightCount]) =>
        rightCount - leftCount ||
        utf8Length(rightKey) - utf8Length(leftKey) ||
        leftKey.localeCompare(rightKey),
    )
    .map(([key]) => key);
  if (keys.length > tokenCapacity) {
    throw new Error("dialect key table exceeds the token capacity");
  }

  const keyIndex = indexStrings(keys);
  const words = selectWords(stats.strings, options);
  const exactValues = selectExactValues(stats.exact, options.maxValues);
  const shapes = selectShapes(stats.shapeGroups, keyIndex, options.maxShapes);

  return createDialect(keys, words, exactValues, shapes);
}

function selectWords(strings: string[], options: ResolvedOptions): string[] {
  const counts = new Map<string, number>();

  for (const value of strings) {
    const candidates = lexicalCandidates(value);
    for (const candidate of candidates) {
      if (candidate === value) {
        continue;
      }

      const occurrences = countOccurrences(value, candidate);
      counts.set(candidate, (counts.get(candidate) ?? 0) + occurrences);
    }
  }

  for (const word of options.words) {
    let occurrences = 0;
    for (const value of strings) {
      occurrences += countOccurrences(value, word);
    }

    counts.set(word, Math.max(counts.get(word) ?? 0, occurrences));
  }

  const candidates = [...counts]
    .map(([value, count]) => {
      const bytes = utf8Length(value);
      const score = count * (bytes - 3) - stringFrameBytes(value);

      return { count, score, value };
    })
    .filter(
      (candidate) =>
        candidate.count >= options.minWordOccurrences &&
        utf8Length(candidate.value) >= options.minWordBytes &&
        utf8Length(candidate.value) <= MAX_ENTRY_BYTES &&
        candidate.score > 0,
    )
    .sort(compareCandidates);

  const words: string[] = [];
  for (const candidate of candidates) {
    if (words.length >= options.maxWords) {
      break;
    }

    const referenceBytes = tokenByteLength(words.length);
    const score =
      candidate.count * (utf8Length(candidate.value) - referenceBytes) -
      stringFrameBytes(candidate.value);
    if (score > 0) {
      words.push(candidate.value);
    }
  }

  return words;
}

function lexicalCandidates(value: string): Set<string> {
  const candidates = new Set<string>();

  const timestamp = /^(\d{4}-\d{2}-\d{2})T/.exec(value);
  if (timestamp) {
    candidates.add(timestamp[1]!);
  }

  const url =
    /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$/.exec(
      value,
    );
  if (url) {
    const origin = url[1]! + url[2]!;
    candidates.add(origin);
    candidates.add(url[2]!);

    const segments = url[3]!.split("/").filter(Boolean);
    let prefix = origin;
    for (const segment of segments.slice(0, 3)) {
      prefix += "/" + segment;
      candidates.add(prefix);
      candidates.add(segment);
    }

    for (const suffix of ["/issues", "#readme", ".git"]) {
      if (value.endsWith(suffix)) {
        candidates.add(suffix);
      }
    }
  }

  const at = value.lastIndexOf("@");
  if (at > 0 && at < value.length - 1) {
    candidates.add(value.slice(at));
    candidates.add(value.slice(at + 1));
  }

  const atoms =
    value.match(/[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+|[^A-Za-z0-9]+/g) ?? [];
  for (let start = 0; start < atoms.length; start += 1) {
    let phrase = "";

    for (let offset = 0; offset < 6; offset += 1) {
      const atom = atoms[start + offset];
      if (atom === undefined) {
        break;
      }

      phrase += atom;
      if (utf8Length(phrase) > 128) {
        break;
      }
      if (/[\p{L}\p{N}]/u.test(phrase)) {
        candidates.add(phrase);
      }
    }
  }

  return candidates;
}

function selectExactValues(
  counts: Map<string, { count: number; json: string }>,
  maximum: number,
): string[] {
  const candidates: ExactCandidate[] = [];

  for (const entry of counts.values()) {
    if (entry.count < 2) {
      continue;
    }

    const inlineBytes = estimateInlineBytes(entry.json);
    const score = entry.count * (inlineBytes - 3) - rawFrameBytes(entry.json);
    if (score > 0) {
      candidates.push({
        count: entry.count,
        json: entry.json,
        score,
        value: entry.json,
      });
    }
  }

  candidates.sort(compareCandidates);

  const values: string[] = [];
  for (const candidate of candidates) {
    if (values.length >= maximum) {
      break;
    }

    const score =
      candidate.count *
        (estimateInlineBytes(candidate.json) - tokenByteLength(values.length)) -
      rawFrameBytes(candidate.json);
    if (score > 0) {
      values.push(candidate.json);
    }
  }

  return values;
}

function estimateInlineBytes(json: string): number {
  const first = json[0];
  if (first === '"') {
    const value = JSON.parse(json) as string;

    return utf8Length(quoteRawString(value));
  }
  if (
    first === "{" ||
    first === "[" ||
    first === "-" ||
    (first !== undefined && first >= "0" && first <= "9")
  ) {
    return utf8Length(json) + (first === "{" || first === "[" ? 0 : 1);
  }

  return 1;
}

function selectShapes(
  groups: Map<string, ShapeGroup>,
  keyIndex: Map<string, number>,
  maximum: number,
): Shape[] {
  const candidates: Shape[] = [];

  for (const group of groups.values()) {
    if (group.count < 2 || group.keys.length === 0) {
      continue;
    }

    const fields = inferShapeConstants(group);
    const definitionBytes = estimateShapeDefinition(
      fields,
      group.keys,
      keyIndex,
    );
    const irregularStructure =
      2 +
      group.keys.reduce(
        (total, key) => total + tokenByteLength(keyIndex.get(key)!),
        0,
      );
    const omittedValueBytes = fields.reduce((total, field, index) => {
      if (field.kind === "dynamic") {
        return total;
      }

      return (
        total +
        group.records.reduce(
          (sum, record) =>
            sum +
            estimateInlineBytes(JSON.stringify(record[group.keys[index]!]!)),
          0,
        )
      );
    }, 0);
    const score =
      group.count * irregularStructure +
      omittedValueBytes -
      definitionBytes -
      group.count * 4;

    if (score > 0) {
      candidates.push({
        fields,
        keys: group.keys,
        score,
        signature: group.signature,
      });
    }
  }

  candidates.sort(
    (left, right) =>
      right.score - left.score ||
      right.keys.length - left.keys.length ||
      left.signature.localeCompare(right.signature),
  );

  const shapes: Shape[] = [];
  for (const candidate of candidates) {
    if (shapes.length >= maximum) {
      break;
    }

    shapes.push(candidate);
  }

  return shapes;
}

function inferShapeConstants(group: ShapeGroup): ShapeField[] {
  return group.fields.map((field, index) => {
    if (field.kind !== "dynamic") {
      return field;
    }

    const key = group.keys[index]!;
    const first = JSON.stringify(group.records[0]![key]!);
    if (
      group.records.every((record) => JSON.stringify(record[key]!) === first)
    ) {
      const definitionBytes = 1 + rawFrameBytes(first);
      const repeatedBytes = group.records.reduce(
        (total, record) =>
          total + estimateInlineBytes(JSON.stringify(record[key]!)),
        0,
      );
      if (repeatedBytes > definitionBytes) {
        return { json: first, kind: "constant" };
      }
    }

    return field;
  });
}

function estimateShapeDefinition(
  fields: ShapeField[],
  keys: string[],
  keyIndex: Map<string, number>,
): number {
  let bytes = String(fields.length).length + 1;

  fields.forEach((field, index) => {
    bytes += tokenByteLength(keyIndex.get(keys[index]!)!) + 1;
    if (field.kind === "constant") {
      bytes += rawFrameBytes(field.json);
    } else if (field.kind === "copy") {
      bytes += String(field.source).length + 1;
    } else if (field.kind === "concat") {
      bytes +=
        String(field.source).length +
        1 +
        stringFrameBytes(field.prefix) +
        stringFrameBytes(field.suffix);
    }
  });

  return bytes;
}

function createDialect(
  keys: string[],
  words: string[],
  exactValues: string[],
  shapes: Shape[],
): Dialect {
  return {
    exactIndex: indexStrings(exactValues),
    exactValues,
    keyIndex: indexStrings(keys),
    keys,
    shapeIndex: new Map(shapes.map((shape, index) => [shape.signature, index])),
    shapes,
    wordIndex: indexStrings(words),
    words,
    wordTrie: buildTrie(words),
  };
}

function encodeDocument(
  value: JsonValue,
  dialect: Dialect,
): { body: string; usage: Usage } {
  const encoded = encodeValue(value, dialect, undefined, false, 0);
  const usage: Usage = {
    exact: Array.from({ length: dialect.exactValues.length }, () => 0),
    shapes: Array.from({ length: dialect.shapes.length }, () => 0),
    words: Array.from({ length: dialect.words.length }, () => 0),
  };

  for (const index of encoded.exactUses) {
    usage.exact[index]! += 1;
  }
  for (const index of encoded.shapeUses) {
    usage.shapes[index]! += 1;
  }
  for (const index of encoded.wordUses) {
    usage.words[index]! += 1;
  }

  return { body: encoded.wire, usage };
}

function encodeValue(
  value: JsonValue,
  dialect: Dialect,
  scope: JsonScalar[] | undefined,
  allowExact: boolean,
  depth: number,
): Encoded {
  if (depth > MAX_DEPTH) {
    throw new Error("dialect value exceeds the nesting limit");
  }

  if (isJsonScalar(value)) {
    return encodeScalar(value, dialect, scope);
  }

  const json = JSON.stringify(value);
  const exactIndex = allowExact ? dialect.exactIndex.get(json) : undefined;
  if (exactIndex !== undefined) {
    return encodedToken(exactIndex);
  }

  if (Array.isArray(value)) {
    return encodeArray(value, dialect, scope, depth + 1);
  }

  return encodeObject(value, dialect, scope, depth + 1);
}

function encodeScalar(
  value: JsonScalar,
  dialect: Dialect,
  scope: JsonScalar[] | undefined,
): Encoded {
  const normal = encodeScalarNormally(value, dialect);
  let best = normal;

  if (scope && scope.length > 0) {
    const copy = encodeScalarCopy(value, scope);
    if (copy && utf8Length(copy.wire) < utf8Length(best.wire)) {
      best = copy;
    }

    if (typeof value === "string") {
      const splice = encodeScalarSplice(value, scope, dialect);
      if (splice && utf8Length(splice.wire) < utf8Length(best.wire)) {
        best = splice;
      }
    }
  }

  if (scope) {
    scope.push(value);
  }

  return best;
}

function encodeScalarNormally(value: JsonScalar, dialect: Dialect): Encoded {
  const json = JSON.stringify(value);
  const exactIndex = dialect.exactIndex.get(json);
  if (exactIndex !== undefined) {
    return encodedToken(exactIndex);
  }

  if (typeof value === "string") {
    return encodeString(value, dialect);
  }
  if (typeof value === "number") {
    return emptyEncoded(json + ";");
  }
  if (value === true) {
    return emptyEncoded("t");
  }
  if (value === false) {
    return emptyEncoded("f");
  }

  return emptyEncoded("z");
}

function encodeScalarCopy(
  value: JsonScalar,
  scope: JsonScalar[],
): Encoded | undefined {
  const start = Math.max(0, scope.length - BASE62.length);

  for (let index = scope.length - 1; index >= start; index -= 1) {
    if (scope[index] === value) {
      const distance = scope.length - 1 - index;

      return emptyEncoded("=" + BASE62[distance]!);
    }
  }

  return undefined;
}

function encodeScalarSplice(
  target: string,
  scope: JsonScalar[],
  dialect: Dialect,
): Encoded | undefined {
  const targetBytes = utf8Length(target);
  if (targetBytes > MAX_SPLICE_BYTES) {
    return undefined;
  }

  let best: Encoded | undefined;
  const start = Math.max(0, scope.length - BASE62.length);
  const targetCharacters = Array.from(target);
  const targetIsAscii = targetBytes === target.length;

  for (let index = scope.length - 1; index >= start; index -= 1) {
    const source = scope[index];
    if (typeof source !== "string") {
      continue;
    }

    const sourceBytes = utf8Length(source);
    if (sourceBytes < 8 || sourceBytes > MAX_SPLICE_BYTES) {
      continue;
    }

    const candidate = findSplice(
      source,
      target,
      targetCharacters,
      targetIsAscii && sourceBytes === source.length,
      scope.length - 1 - index,
    );
    if (!candidate) {
      continue;
    }

    const prefix = encodeString(candidate.prefix, dialect);
    const suffix = encodeString(candidate.suffix, dialect);
    const prefixWire =
      "p" +
      BASE62[candidate.sourceDistance]! +
      candidate.dropLeft +
      ":" +
      candidate.dropRight +
      ":";
    const encoded = combineEncoded(prefixWire, "", [prefix, suffix]);

    if (!best || utf8Length(encoded.wire) < utf8Length(best.wire)) {
      best = encoded;
    }
  }

  return best;
}

function findSplice(
  source: string,
  target: string,
  targetCharacters: string[],
  ascii: boolean,
  sourceDistance: number,
): Splice | undefined {
  const containedAt = target.indexOf(source);
  if (containedAt >= 0) {
    return {
      dropLeft: 0,
      dropRight: 0,
      prefix: target.slice(0, containedAt),
      sourceDistance,
      suffix: target.slice(containedAt + source.length),
    };
  }

  if (ascii) {
    return findAsciiSplice(source, target, sourceDistance);
  }

  const sourceCharacters = Array.from(source);
  const sourceLength = sourceCharacters.length;
  const targetLength = targetCharacters.length;

  let prefixLength = 0;
  while (
    prefixLength < sourceLength &&
    prefixLength < targetLength &&
    sourceCharacters[prefixLength] === targetCharacters[prefixLength]
  ) {
    prefixLength += 1;
  }

  let suffixLength = 0;
  while (
    suffixLength < sourceLength &&
    suffixLength < targetLength &&
    sourceCharacters[sourceLength - 1 - suffixLength] ===
      targetCharacters[targetLength - 1 - suffixLength]
  ) {
    suffixLength += 1;
  }

  const prefixBytes = utf8Length(
    sourceCharacters.slice(0, prefixLength).join(""),
  );
  const suffixBytes = utf8Length(
    sourceCharacters.slice(sourceLength - suffixLength).join(""),
  );

  if (prefixBytes >= suffixBytes && prefixBytes >= 8) {
    return {
      dropLeft: 0,
      dropRight: sourceLength - prefixLength,
      prefix: "",
      sourceDistance,
      suffix: targetCharacters.slice(prefixLength, targetLength).join(""),
    };
  }
  if (suffixBytes >= 8) {
    return {
      dropLeft: sourceLength - suffixLength,
      dropRight: 0,
      prefix: targetCharacters.slice(0, targetLength - suffixLength).join(""),
      sourceDistance,
      suffix: "",
    };
  }

  return undefined;
}

function findAsciiSplice(
  source: string,
  target: string,
  sourceDistance: number,
): Splice | undefined {
  let prefixLength = 0;
  while (
    prefixLength < source.length &&
    prefixLength < target.length &&
    source[prefixLength] === target[prefixLength]
  ) {
    prefixLength += 1;
  }

  let suffixLength = 0;
  while (
    suffixLength < source.length &&
    suffixLength < target.length &&
    source[source.length - 1 - suffixLength] ===
      target[target.length - 1 - suffixLength]
  ) {
    suffixLength += 1;
  }

  if (prefixLength >= 8 && prefixLength >= suffixLength) {
    return {
      dropLeft: 0,
      dropRight: source.length - prefixLength,
      prefix: "",
      sourceDistance,
      suffix: target.slice(prefixLength),
    };
  }
  if (suffixLength >= 8) {
    return {
      dropLeft: source.length - suffixLength,
      dropRight: 0,
      prefix: target.slice(0, target.length - suffixLength),
      sourceDistance,
      suffix: "",
    };
  }

  return undefined;
}

function encodeString(value: string, dialect: Dialect): Encoded {
  const raw = emptyEncoded(quoteRawString(value));
  if (dialect.words.length === 0 || value.length === 0) {
    return raw;
  }

  const characters = Array.from(value);
  const costs = Array.from(
    { length: characters.length + 1 },
    () => Number.POSITIVE_INFINITY,
  );
  const choices: Array<
    { kind: "raw" } | { end: number; index: number; kind: "word" } | undefined
  > = Array.from({ length: characters.length });
  costs[characters.length] = 0;

  for (let start = characters.length - 1; start >= 0; start -= 1) {
    costs[start] = utf8Length(characters[start]!) + costs[start + 1]!;
    choices[start] = { kind: "raw" };

    let node: TrieNode | undefined = dialect.wordTrie;
    for (let end = start; end < characters.length; end += 1) {
      node = node.next.get(characters[end]!);
      if (!node) {
        break;
      }
      if (node.index === undefined) {
        continue;
      }

      const cost = tokenByteLength(node.index) + costs[end + 1]!;
      if (cost < costs[start]!) {
        costs[start] = cost;
        choices[start] = { end: end + 1, index: node.index, kind: "word" };
      }
    }
  }

  const pieces: Array<
    { kind: "raw"; value: string } | { index: number; kind: "word" }
  > = [];
  let rawBuffer = "";
  let cursor = 0;

  while (cursor < characters.length) {
    const choice = choices[cursor]!;
    if (choice.kind === "raw") {
      rawBuffer += characters[cursor]!;
      cursor += 1;
      continue;
    }

    if (rawBuffer) {
      pieces.push({ kind: "raw", value: rawBuffer });
      rawBuffer = "";
    }
    pieces.push({ index: choice.index, kind: "word" });
    cursor = choice.end;
  }
  if (rawBuffer) {
    pieces.push({ kind: "raw", value: rawBuffer });
  }

  const wordUses: number[] = [];
  let wire = '"';
  for (const piece of pieces) {
    if (piece.kind === "word") {
      wire += tokenFor(piece.index);
      wordUses.push(piece.index);
    } else {
      wire += escapeRawStringContent(piece.value);
    }
  }
  wire += '"';

  const encoded: Encoded = {
    exactUses: [],
    shapeUses: [],
    wire,
    wordUses,
  };

  return utf8Length(encoded.wire) < utf8Length(raw.wire) ? encoded : raw;
}

function encodeArray(
  value: JsonValue[],
  dialect: Dialect,
  scope: JsonScalar[] | undefined,
  depth: number,
): Encoded {
  const normalParts = value.map((item) =>
    encodeValue(item, dialect, scope, true, depth),
  );
  let best = combineEncoded("[", "]", normalParts);

  if (
    scope === undefined &&
    value.length > 1 &&
    value.every(
      (item) =>
        !Array.isArray(item) && item !== null && typeof item === "object",
    )
  ) {
    const records = value as JsonObject[];
    const signatures = records.map((record) =>
      shapeSignature(
        Object.keys(record),
        inferLocalRelations(record, Object.keys(record)),
      ),
    );
    const shapeIndex = dialect.shapeIndex.get(signatures[0]!);
    if (
      shapeIndex !== undefined &&
      signatures.every((signature) => signature === signatures[0]) &&
      records.every(
        (record) =>
          dialect.exactIndex.get(JSON.stringify(record)) === undefined,
      )
    ) {
      const shape = dialect.shapes[shapeIndex]!;
      const parts: Encoded[] = [];
      for (const record of records) {
        parts.push(encodeShapeFields(record, shape, dialect, [], depth));
      }

      const run = combineEncoded(
        "[r" + tokenFor(shapeIndex) + records.length + ":",
        "]",
        parts,
      );
      run.shapeUses.push(shapeIndex);
      if (utf8Length(run.wire) < utf8Length(best.wire)) {
        best = run;
      }
    }
  }

  return best;
}

function encodeObject(
  value: JsonObject,
  dialect: Dialect,
  scope: JsonScalar[] | undefined,
  depth: number,
): Encoded {
  const keys = Object.keys(value);
  const signature = shapeSignature(keys, inferLocalRelations(value, keys));
  const shapeIndex = dialect.shapeIndex.get(signature);
  const localScope = scope ?? [];

  if (shapeIndex !== undefined) {
    const shape = dialect.shapes[shapeIndex]!;
    const fields = encodeShapeFields(value, shape, dialect, localScope, depth);
    fields.wire = "s" + tokenFor(shapeIndex) + fields.wire;
    fields.shapeUses.push(shapeIndex);

    return fields;
  }

  const parts: Encoded[] = [];
  for (const key of keys) {
    const keyIndex = dialect.keyIndex.get(key);
    if (keyIndex === undefined) {
      throw new Error("dialect object key is missing from the key table");
    }

    const encoded = encodeValue(value[key]!, dialect, localScope, true, depth);
    encoded.wire = tokenFor(keyIndex) + encoded.wire;
    parts.push(encoded);
  }

  return combineEncoded("{", "}", parts);
}

function encodeShapeFields(
  record: JsonObject,
  shape: Shape,
  dialect: Dialect,
  scope: JsonScalar[],
  depth: number,
): Encoded {
  const parts: Encoded[] = [];
  const values: JsonValue[] = [];

  shape.fields.forEach((field, index) => {
    const actual = record[shape.keys[index]!]!;

    if (field.kind === "dynamic") {
      parts.push(encodeValue(actual, dialect, scope, true, depth));
      values.push(actual);

      return;
    }
    if (field.kind === "constant") {
      appendScalars(actual, scope);
      values.push(actual);

      return;
    }
    if (field.kind === "copy") {
      appendScalars(actual, scope);
      values.push(values[field.source]!);

      return;
    }

    appendScalars(actual, scope);
    values.push(
      field.prefix + requireString(values[field.source]) + field.suffix,
    );
  });

  return combineEncoded("", "", parts);
}

function emptyEncoded(wire: string): Encoded {
  return { exactUses: [], shapeUses: [], wire, wordUses: [] };
}

function encodedToken(index: number): Encoded {
  return {
    exactUses: [index],
    shapeUses: [],
    wire: tokenFor(index),
    wordUses: [],
  };
}

function combineEncoded(
  prefix: string,
  suffix: string,
  parts: Encoded[],
): Encoded {
  const result = emptyEncoded(prefix);

  for (const part of parts) {
    result.wire += part.wire;
    appendNumbers(result.exactUses, part.exactUses);
    appendNumbers(result.shapeUses, part.shapeUses);
    appendNumbers(result.wordUses, part.wordUses);
  }

  result.wire += suffix;

  return result;
}

function pruneDialect(dialect: Dialect, usage: Usage): Dialect {
  const words = dialect.words.filter((word, index) => {
    const uses = usage.words[index]!;
    const maximumSavings =
      uses *
      Math.max(
        0,
        utf8Length(escapeRawStringContent(word)) - tokenByteLength(index),
      );

    return uses > 0 && maximumSavings > stringFrameBytes(word);
  });
  const exactValues = dialect.exactValues.filter((value, index) => {
    const uses = usage.exact[index]!;
    const maximumSavings =
      uses * Math.max(0, estimateInlineBytes(value) - tokenByteLength(index));

    return uses > 0 && maximumSavings > rawFrameBytes(value);
  });
  const shapes = dialect.shapes.filter((_, index) => usage.shapes[index]! > 0);

  return createDialect(dialect.keys, words, exactValues, shapes);
}

function sameDialectSize(left: Dialect, right: Dialect): boolean {
  return (
    left.words.length === right.words.length &&
    left.exactValues.length === right.exactValues.length &&
    left.shapes.length === right.shapes.length
  );
}

function serializeTables(dialect: Dialect): string {
  let output = "";

  for (const key of dialect.keys) {
    output += stringFrame(key);
  }
  for (const word of dialect.words) {
    output += stringFrame(word);
  }
  for (const value of dialect.exactValues) {
    output += rawFrame(value);
  }
  for (const shape of dialect.shapes) {
    output += String(shape.fields.length) + ":";

    shape.fields.forEach((field, index) => {
      const keyIndex = dialect.keyIndex.get(shape.keys[index]!);
      if (keyIndex === undefined) {
        throw new Error("dialect shape key is missing from the key table");
      }

      const marker =
        field.kind === "dynamic"
          ? "d"
          : field.kind === "constant"
            ? "c"
            : field.kind === "copy"
              ? "r"
              : "p";
      output += tokenFor(keyIndex) + marker;
      if (field.kind === "constant") {
        output += rawFrame(field.json);
      } else if (field.kind === "copy") {
        output += String(field.source) + ":";
      } else if (field.kind === "concat") {
        output +=
          String(field.source) +
          ":" +
          stringFrame(field.prefix) +
          stringFrame(field.suffix);
      }
    });
  }

  return output;
}

function parseHeader(encoded: string): Header {
  const match =
    /^dia1\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.([0-9a-f]{16}):/.exec(encoded);
  if (!match) {
    throw new Error("malformed dialect header");
  }
  if (match[6] !== alphabetFingerprint) {
    throw new Error("dialect alphabet does not match this runtime");
  }

  const expandedBytes = parseUnsigned(match[1]!, "expandedBytes");
  const keyCount = parseUnsigned(match[2]!, "keyCount");
  const wordCount = parseUnsigned(match[3]!, "wordCount");
  const exactCount = parseUnsigned(match[4]!, "exactCount");
  const shapeCount = parseUnsigned(match[5]!, "shapeCount");

  assertIntegerRange(keyCount, "keyCount", 0, tokenCapacity);
  assertIntegerRange(wordCount, "wordCount", 0, tokenCapacity);
  assertIntegerRange(exactCount, "exactCount", 0, tokenCapacity);
  assertIntegerRange(shapeCount, "shapeCount", 0, tokenCapacity);

  return {
    exactCount,
    expandedBytes,
    keyCount,
    payload: encoded.slice(match[0].length),
    shapeCount,
    wordCount,
  };
}

function readStringTable(
  reader: ByteReader,
  count: number,
  name: string,
): string[] {
  const entries: string[] = [];

  for (let index = 0; index < count; index += 1) {
    const value = reader.readFramedString();
    if (utf8Length(value) > MAX_ENTRY_BYTES && name !== "key") {
      throw new Error("dialect " + name + " entry exceeds the decoder limit");
    }

    entries.push(value);
  }

  return entries;
}

function readRawTable(
  reader: ByteReader,
  count: number,
  name: string,
): string[] {
  const entries: string[] = [];

  for (let index = 0; index < count; index += 1) {
    const value = reader.readRawString();
    if (utf8Length(value) > MAX_ENTRY_BYTES && name !== "key") {
      throw new Error("dialect " + name + " entry exceeds the decoder limit");
    }

    entries.push(value);
  }

  return entries;
}

function readExactTable(reader: ByteReader, count: number): string[] {
  const entries = readRawTable(reader, count, "exact value");

  for (const entry of entries) {
    parseJsonValue(entry);
  }

  return entries;
}

function readShapeTable(
  reader: ByteReader,
  count: number,
  keys: string[],
): DecodedShape[] {
  const shapes: DecodedShape[] = [];

  for (let shapeIndex = 0; shapeIndex < count; shapeIndex += 1) {
    const fieldCount = reader.readUnsigned();
    if (fieldCount > 4096) {
      throw new Error("dialect shape exceeds the field limit");
    }

    const shapeKeys: string[] = [];
    const fields: ShapeField[] = [];

    for (let fieldIndex = 0; fieldIndex < fieldCount; fieldIndex += 1) {
      const keyIndex = reader.readToken(keys.length);
      shapeKeys.push(keys[keyIndex]!);

      const mode = reader.readAscii();
      if (mode === "d") {
        fields.push({ kind: "dynamic" });
      } else if (mode === "c") {
        const json = reader.readRawString();
        parseJsonValue(json);
        fields.push({ json, kind: "constant" });
      } else if (mode === "r") {
        const source = reader.readUnsigned();
        if (source >= fieldIndex) {
          throw new Error("dialect shape copy points forward");
        }

        fields.push({ kind: "copy", source });
      } else if (mode === "p") {
        const source = reader.readUnsigned();
        if (source >= fieldIndex) {
          throw new Error("dialect shape concat points forward");
        }

        fields.push({
          kind: "concat",
          prefix: reader.readFramedString(),
          source,
          suffix: reader.readFramedString(),
        });
      } else {
        throw new Error("dialect shape contains an unknown field mode");
      }
    }

    shapes.push({ fields, keys: shapeKeys });
  }

  return shapes;
}

function decodeValue(
  reader: ByteReader,
  tables: DecodeTables,
  budget: DecodeBudget,
  scope: JsonScalar[] | undefined,
  depth: number,
): JsonValue {
  if (depth > MAX_DEPTH) {
    throw new Error("dialect body exceeds the nesting limit");
  }

  if (reader.startsToken()) {
    const index = reader.readToken(tables.exactValues.length);
    const value = parseJsonValue(tables.exactValues[index]!);
    chargeTree(budget, value);
    if (isJsonScalar(value) && scope) {
      scope.push(value);
    }

    return value;
  }

  const marker = reader.peekAscii();
  if (marker === '"') {
    const value = reader.readQuotedString(tables.words, budget.bytesRemaining);
    chargeScalar(budget, value);
    if (scope) {
      scope.push(value);
    }

    return value;
  }
  if (marker === "-" || (marker >= "0" && marker <= "9")) {
    const source = reader.readUntil(59);
    if (!numberPattern.test(source)) {
      throw new Error("dialect body contains a malformed number");
    }

    const value = Number(source);
    if (!Number.isFinite(value)) {
      throw new Error("dialect body contains a non-finite number");
    }
    chargeScalar(budget, value);
    if (scope) {
      scope.push(value);
    }

    return value;
  }

  reader.readAscii();

  if (marker === "t") {
    chargeScalar(budget, true);
    scope?.push(true);

    return true;
  }
  if (marker === "f") {
    chargeScalar(budget, false);
    scope?.push(false);

    return false;
  }
  if (marker === "z") {
    chargeScalar(budget, null);
    scope?.push(null);

    return null;
  }
  if (marker === "[") {
    return decodeArray(reader, tables, budget, scope, depth + 1);
  }
  if (marker === "{") {
    return decodeObject(reader, tables, budget, scope, depth + 1);
  }
  if (marker === "s") {
    const shapeIndex = reader.readToken(tables.shapes.length);

    return decodeShape(
      reader,
      tables,
      budget,
      shapeIndex,
      scope ?? [],
      depth + 1,
    );
  }
  if (marker === "=") {
    const value = readScopeScalar(reader, scope);
    chargeScalar(budget, value);
    scope!.push(value);

    return value;
  }
  if (marker === "p") {
    const source = readScopeScalar(reader, scope);
    if (typeof source !== "string") {
      throw new Error("dialect splice source is not a string");
    }

    const dropLeft = reader.readUnsigned();
    const dropRight = reader.readUnsigned();
    const prefix = reader.readQuotedString(tables.words, budget.bytesRemaining);
    const suffix = reader.readQuotedString(tables.words, budget.bytesRemaining);
    const characters = Array.from(source);
    if (dropLeft + dropRight > characters.length) {
      throw new Error("dialect splice exceeds its source");
    }

    const value =
      prefix +
      characters.slice(dropLeft, characters.length - dropRight).join("") +
      suffix;
    chargeScalar(budget, value);
    scope!.push(value);

    return value;
  }

  throw new Error("dialect body contains an unknown value marker");
}

function decodeArray(
  reader: ByteReader,
  tables: DecodeTables,
  budget: DecodeBudget,
  scope: JsonScalar[] | undefined,
  depth: number,
): JsonValue[] {
  const values: JsonValue[] = [];
  chargeContainer(budget);

  if (reader.peekAscii() === "r") {
    reader.readAscii();
    const shapeIndex = reader.readToken(tables.shapes.length);
    const count = reader.readUnsigned();
    if (count > budget.nodesRemaining || count > MAX_DECODE_NODES) {
      throw new Error("dialect shaped run exceeds the decode budget");
    }

    for (let index = 0; index < count; index += 1) {
      if (index > 0) {
        chargeBytes(budget, 1);
      }
      values.push(
        decodeShape(reader, tables, budget, shapeIndex, scope ?? [], depth + 1),
      );
    }

    reader.expectAscii("]");

    return values;
  }

  while (reader.peekAscii() !== "]") {
    if (values.length > 0) {
      chargeBytes(budget, 1);
    }
    values.push(decodeValue(reader, tables, budget, scope, depth + 1));
  }
  reader.readAscii();

  return values;
}

function decodeObject(
  reader: ByteReader,
  tables: DecodeTables,
  budget: DecodeBudget,
  scope: JsonScalar[] | undefined,
  depth: number,
): JsonObject {
  const value: JsonObject = {};
  const localScope = scope ?? [];
  chargeContainer(budget);

  while (reader.peekAscii() !== "}") {
    const keyIndex = reader.readToken(tables.keys.length);
    const key = tables.keys[keyIndex]!;
    chargeMember(budget, key, Object.keys(value).length);
    const child = decodeValue(reader, tables, budget, localScope, depth + 1);
    defineJsonProperty(value, key, child);
  }
  reader.readAscii();

  return value;
}

function decodeShape(
  reader: ByteReader,
  tables: DecodeTables,
  budget: DecodeBudget,
  shapeIndex: number,
  scope: JsonScalar[],
  depth: number,
): JsonObject {
  const shape = tables.shapes[shapeIndex]!;
  const value: JsonObject = {};
  const fields: JsonValue[] = [];
  chargeContainer(budget);

  shape.fields.forEach((field, index) => {
    chargeMember(budget, shape.keys[index]!, index);
    let child: JsonValue;

    if (field.kind === "dynamic") {
      child = decodeValue(reader, tables, budget, scope, depth + 1);
    } else if (field.kind === "constant") {
      child = parseJsonValue(field.json);
      chargeTree(budget, child);
      appendScalars(child, scope);
    } else if (field.kind === "copy") {
      const source = fields[field.source]!;
      chargeTree(budget, source);
      child = cloneJsonValue(source);
      appendScalars(child, scope);
    } else {
      child = field.prefix + requireString(fields[field.source]) + field.suffix;
      chargeScalar(budget, child);
      appendScalars(child, scope);
    }

    fields.push(child);
    defineJsonProperty(value, shape.keys[index]!, child);
  });

  return value;
}

function readScopeScalar(
  reader: ByteReader,
  scope: JsonScalar[] | undefined,
): JsonScalar {
  if (!scope) {
    throw new Error("dialect reference appears outside a scalar scope");
  }

  const distanceCode = reader.readAscii();
  const distance = BASE62.indexOf(distanceCode);
  if (distance < 0 || distance >= scope.length) {
    throw new Error("dialect scalar reference is out of range");
  }

  return scope[scope.length - 1 - distance]!;
}

function quoteRawString(value: string): string {
  return '"' + escapeRawStringContent(value) + '"';
}

function escapeRawStringContent(value: string): string {
  const escaped = JSON.stringify(value).slice(1, -1);
  let output = "";

  for (const character of escaped) {
    output += isTokenLiteral(character) ? "\\" + character : character;
  }

  return output;
}

function stringFrame(value: string): string {
  return rawFrame(JSON.stringify(value));
}

function stringFrameBytes(value: string): number {
  return rawFrameBytes(JSON.stringify(value));
}

function rawFrame(value: string): string {
  return String(utf8Length(value)) + ":" + value;
}

function rawFrameBytes(value: string): number {
  return String(utf8Length(value)).length + 1 + utf8Length(value);
}

function buildTrie(words: string[]): TrieNode {
  const root: TrieNode = { next: new Map() };

  words.forEach((word, index) => {
    let node = root;

    for (const character of word) {
      let child = node.next.get(character);
      if (!child) {
        child = { next: new Map() };
        node.next.set(character, child);
      }

      node = child;
    }

    node.index = index;
  });

  return root;
}

function indexStrings(values: string[]): Map<string, number> {
  return new Map(values.map((value, index) => [value, index]));
}

function compareCandidates(left: Candidate, right: Candidate): number {
  return (
    right.score - left.score ||
    utf8Length(right.value) - utf8Length(left.value) ||
    left.value.localeCompare(right.value)
  );
}

function countOccurrences(value: string, candidate: string): number {
  let count = 0;
  let cursor = 0;

  while (cursor <= value.length - candidate.length) {
    const index = value.indexOf(candidate, cursor);
    if (index < 0) {
      break;
    }

    count += 1;
    cursor = index + candidate.length;
  }

  return count;
}

function appendScalars(value: JsonValue, scope: JsonScalar[]): void {
  if (isJsonScalar(value)) {
    scope.push(value);

    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) {
      appendScalars(child, scope);
    }

    return;
  }

  for (const key of Object.keys(value)) {
    appendScalars(value[key]!, scope);
  }
}

function isJsonScalar(value: JsonValue): value is JsonScalar {
  return value === null || typeof value !== "object";
}

function parseJsonValue(source: string): JsonValue {
  const value = JSON.parse(source) as unknown;
  validateJsonValue(value, 0, { nodes: 0 });

  return value as JsonValue;
}

function validateJsonValue(
  value: unknown,
  depth: number,
  state: { nodes: number },
): void {
  if (depth > MAX_DEPTH) {
    throw new Error("dialect table value exceeds the nesting limit");
  }

  state.nodes += 1;
  if (state.nodes > MAX_DECODE_NODES) {
    throw new Error("dialect table value exceeds the node limit");
  }

  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) {
      validateJsonValue(child, depth + 1, state);
    }

    return;
  }
  if (typeof value === "object") {
    for (const child of Object.values(value)) {
      validateJsonValue(child, depth + 1, state);
    }

    return;
  }

  throw new Error("dialect table contains a non-JSON value");
}

function chargeBytes(budget: DecodeBudget, bytes: number): void {
  if (bytes > budget.bytesRemaining) {
    throw new Error("dialect value exceeds the declared expanded byte budget");
  }

  budget.bytesRemaining -= bytes;
}

function chargeNode(budget: DecodeBudget): void {
  if (budget.nodesRemaining <= 0) {
    throw new Error("dialect value exceeds the decode node budget");
  }

  budget.nodesRemaining -= 1;
}

function chargeScalar(budget: DecodeBudget, value: JsonScalar): void {
  chargeNode(budget);
  chargeBytes(budget, utf8Length(JSON.stringify(value)));
}

function chargeContainer(budget: DecodeBudget): void {
  chargeNode(budget);
  chargeBytes(budget, 2);
}

function chargeMember(budget: DecodeBudget, key: string, index: number): void {
  chargeBytes(
    budget,
    utf8Length(JSON.stringify(key)) + 1 + (index > 0 ? 1 : 0),
  );
}

function chargeTree(budget: DecodeBudget, value: JsonValue): void {
  if (isJsonScalar(value)) {
    chargeScalar(budget, value);

    return;
  }

  chargeContainer(budget);
  if (Array.isArray(value)) {
    value.forEach((child, index) => {
      if (index > 0) {
        chargeBytes(budget, 1);
      }
      chargeTree(budget, child);
    });

    return;
  }

  Object.keys(value).forEach((key, index) => {
    chargeMember(budget, key, index);
    chargeTree(budget, value[key]!);
  });
}

function requireString(value: JsonValue | undefined): string {
  if (typeof value !== "string") {
    throw new Error("dialect concat source is not a string");
  }

  return value;
}

function cloneJsonValue(value: JsonValue): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function defineJsonProperty(
  target: JsonObject,
  key: string,
  value: JsonValue,
): void {
  Object.defineProperty(target, key, {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

function appendNumbers(target: number[], values: number[]): void {
  for (const value of values) {
    target.push(value);
  }
}

function uniqueStrings(values: readonly string[], name: string): string[] {
  if (
    values.some(
      (value) =>
        typeof value !== "string" ||
        value.length === 0 ||
        utf8Length(value) > MAX_ENTRY_BYTES,
    )
  ) {
    throw new Error(name + " must contain non-empty bounded strings");
  }

  return [...new Set(values)];
}

function utf8Length(value: string): number {
  return Buffer.byteLength(value);
}

function parseUnsigned(value: string, name: string): number {
  if (!/^(?:0|[1-9]\d*)$/.test(value)) {
    throw new Error("dialect " + name + " is not a canonical unsigned integer");
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("dialect " + name + " exceeds the safe integer range");
  }

  return parsed;
}

function assertIntegerRange(
  value: number,
  name: string,
  minimum: number,
  maximum: number,
): void {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(
      name + " must be an integer from " + minimum + " to " + maximum,
    );
  }
}

class ByteReader {
  readonly bytes: Uint8Array;
  cursor = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  done(): boolean {
    return this.cursor === this.bytes.length;
  }

  expectAscii(expected: string): void {
    const actual = this.readAscii();
    if (actual !== expected) {
      throw new Error(
        "dialect expected " +
          JSON.stringify(expected) +
          " but found " +
          JSON.stringify(actual),
      );
    }
  }

  peekAscii(offset = 0): string {
    const byte = this.bytes[this.cursor + offset];
    if (byte === undefined) {
      throw new Error("dialect payload ended unexpectedly");
    }
    if (byte > 0x7f) {
      return "";
    }

    return String.fromCharCode(byte);
  }

  readAscii(): string {
    const byte = this.bytes[this.cursor];
    if (byte === undefined || byte > 0x7f) {
      throw new Error("dialect payload contains an invalid ASCII marker");
    }

    this.cursor += 1;

    return String.fromCharCode(byte);
  }

  readCodePoint(): string {
    const first = this.bytes[this.cursor];
    if (first === undefined) {
      throw new Error("dialect payload ended inside a character");
    }

    const length = first < 0x80 ? 1 : first < 0xe0 ? 2 : first < 0xf0 ? 3 : 4;
    const end = this.cursor + length;
    if (end > this.bytes.length) {
      throw new Error("dialect payload ends inside a UTF-8 character");
    }

    const value = textDecoder.decode(this.bytes.subarray(this.cursor, end));
    this.cursor = end;

    return value;
  }

  readFramedString(): string {
    const value = JSON.parse(this.readRawString()) as unknown;
    if (typeof value !== "string") {
      throw new Error("dialect string frame does not contain a string");
    }

    return value;
  }

  readRawString(): string {
    const length = this.readUnsigned();
    if (
      length > MAX_EXPANDED_BYTES ||
      this.cursor + length > this.bytes.length
    ) {
      throw new Error("dialect raw value exceeds the available payload");
    }

    const value = textDecoder.decode(
      this.bytes.subarray(this.cursor, this.cursor + length),
    );
    this.cursor += length;

    return value;
  }

  readQuotedString(words: string[], maxDecodedBytes: number): string {
    this.expectAscii('"');

    let decodedBytes = 0;
    let escaped = "";
    let value = "";

    const append = (piece: string): void => {
      decodedBytes += utf8Length(piece);
      if (decodedBytes + 2 > maxDecodedBytes) {
        throw new Error("dialect string exceeds the decode byte budget");
      }

      value += piece;
    };
    const flush = (): void => {
      if (!escaped) {
        return;
      }

      append(JSON.parse('"' + escaped + '"') as string);
      escaped = "";
    };

    while (true) {
      const marker = this.peekAscii();
      if (marker === '"') {
        this.readAscii();
        flush();

        return value;
      }
      if (this.startsToken()) {
        flush();
        const index = this.readToken(words.length);
        append(words[index]!);
        continue;
      }
      if (marker === "\\") {
        this.readAscii();
        const escape = this.readAscii();
        if (isTokenLiteral(escape)) {
          flush();
          append(escape);
          continue;
        }

        escaped += "\\" + escape;

        if (escape === "u") {
          for (let index = 0; index < 4; index += 1) {
            const digit = this.readAscii();
            if (!/[0-9A-Fa-f]/.test(digit)) {
              throw new Error("dialect string contains a malformed escape");
            }

            escaped += digit;
          }
        }

        continue;
      }

      escaped += this.readCodePoint();
    }
  }

  readToken(limit: number): number {
    const first = this.readAscii();
    let token = first;

    if (first === tokenPrefix) {
      const suffix = this.readAscii();
      token += suffix;
      if (tokenBanks.includes(suffix)) {
        token += this.readAscii();
      } else if (!simpleTokenSuffixes.includes(suffix)) {
        throw new Error("dialect payload contains an unknown token suffix");
      }
    } else if (!directTokens.includes(first)) {
      throw new Error("dialect payload contains an unknown token root");
    }

    const index = tokenIndex.get(token);
    if (index === undefined) {
      throw new Error("dialect payload contains an unknown token");
    }
    if (index >= limit) {
      throw new Error("dialect token reference is out of range");
    }

    return index;
  }

  readUnsigned(): number {
    const start = this.cursor;

    while (true) {
      const byte = this.bytes[this.cursor];
      if (byte === 58) {
        break;
      }
      if (byte === undefined || byte < 48 || byte > 57) {
        throw new Error("dialect payload contains a malformed length");
      }

      this.cursor += 1;
    }

    if (this.cursor === start) {
      throw new Error("dialect payload contains an empty length");
    }

    const value = Number(
      textDecoder.decode(this.bytes.subarray(start, this.cursor)),
    );
    this.cursor += 1;

    if (!Number.isSafeInteger(value)) {
      throw new Error("dialect payload length exceeds the safe integer range");
    }

    return value;
  }

  readUntil(delimiter: number): string {
    const start = this.cursor;

    while (this.bytes[this.cursor] !== delimiter) {
      if (this.bytes[this.cursor] === undefined) {
        throw new Error("dialect payload is missing a terminator");
      }

      this.cursor += 1;
    }

    const value = textDecoder.decode(this.bytes.subarray(start, this.cursor));
    this.cursor += 1;

    return value;
  }

  startsToken(): boolean {
    const byte = this.bytes[this.cursor];
    if (byte === undefined || byte > 0x7f) {
      return false;
    }

    const character = String.fromCharCode(byte);

    return character === tokenPrefix || directTokens.includes(character);
  }
}
