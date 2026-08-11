import { createHash } from "node:crypto";

const FORMAT = "tgj1";
const ESCAPE = "~";
const SHARED_MARKER = "#";
const DIRECT_TOKEN_LIMIT = 40;
const MAX_EXPANDED_BYTES = 128 * 1024 * 1024;
const MAX_DICTIONARY_ENTRY_BYTES = 2048;
const MAX_DICTIONARY_BYTES = 92 * (MAX_DICTIONARY_ENTRY_BYTES + 8);
const MIN_SHARED_HASH_LENGTH = 5;
const MAX_SHARED_HASH_LENGTH = 16;
const SHARED_FINGERPRINT_LENGTH = 16;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const printableCodes = Array.from({ length: 94 }, (_, index) =>
  String.fromCharCode(index + 33),
).filter((char) => char !== ESCAPE && char !== SHARED_MARKER);

export type TgjOptions = {
  maxTokens?: number;
  minOccurrences?: number;
  minTokenBytes?: number;
  customTokens?: readonly string[];
  sharedTokens?: readonly string[];
  sharedHashLength?: number;
};

type ResolvedOptions = {
  maxTokens: number;
  minOccurrences: number;
  minTokenBytes: number;
  customTokens: string[];
  sharedTokens: string[];
  sharedHashLength: number;
};

type Segment =
  | { kind: "literal"; value: string }
  | { kind: "local"; index: number }
  | { kind: "shared"; alias: string };

type SharedVocabulary = {
  byAlias: Map<string, string>;
  entries: Array<{ alias: string; value: string }>;
  fingerprint: string;
  hashLength: number;
};

type Header = {
  expandedBytes: number;
  directCount: number;
  tokenCount: number;
  dictionaryBytes: number;
  sharedHashLength: number;
  sharedFingerprint: string;
  payload: string;
};

export function encodeTgj(value: unknown, options: TgjOptions = {}): string {
  const resolved = resolveOptions(options);
  const json = serializeJson(value);
  const normalized = JSON.parse(json) as unknown;
  const hints = collectCandidateHints(normalized, resolved);

  const sharedVocabulary = createSharedVocabulary(
    resolved.sharedTokens,
    resolved.sharedHashLength,
  );
  const withShared = selectSharedTokens(
    [{ kind: "literal", value: json }],
    sharedVocabulary,
    resolved.sharedHashLength,
  );
  const selected = selectLocalTokens(withShared, hints, resolved);
  const sharedFingerprint = selected.segments.some(
    (segment) => segment.kind === "shared",
  )
    ? sharedVocabulary.fingerprint
    : "-";

  const directAlphabet = chooseDirectAlphabet(
    selected.segments,
    Math.min(DIRECT_TOKEN_LIMIT, selected.tokens.length),
  );
  const dictionary = serializeDictionary(selected.tokens);
  const body = encodeSegments(
    selected.segments,
    directAlphabet,
    selected.tokens.length,
  );
  const header = [
    FORMAT,
    utf8Length(json),
    directAlphabet.length,
    selected.tokens.length,
    utf8Length(dictionary),
    resolved.sharedHashLength,
    sharedFingerprint,
  ].join(".");

  return `${header}:${directAlphabet.join("")}${dictionary}${body}`;
}

export function decodeTgj(encoded: string, options: TgjOptions = {}): unknown {
  const header = parseHeader(encoded);
  if (header.expandedBytes > MAX_EXPANDED_BYTES) {
    throw new Error("TGJ expanded payload exceeds the decoder limit");
  }
  if (
    options.sharedHashLength !== undefined &&
    options.sharedHashLength !== header.sharedHashLength
  ) {
    throw new Error("TGJ shared hash length does not match decoder options");
  }

  const payloadBytes = textEncoder.encode(header.payload);
  const metadataBytes = header.directCount + header.dictionaryBytes;
  if (metadataBytes > payloadBytes.length) {
    throw new Error("TGJ metadata exceeds the available payload");
  }

  const directAlphabet = textDecoder.decode(
    payloadBytes.subarray(0, header.directCount),
  );
  validateDirectAlphabet(directAlphabet, header.directCount);

  const dictionaryStart = header.directCount;
  const dictionaryEnd = dictionaryStart + header.dictionaryBytes;
  const dictionary = parseDictionary(
    payloadBytes.subarray(dictionaryStart, dictionaryEnd),
    header.tokenCount,
  );
  const body = textDecoder.decode(payloadBytes.subarray(dictionaryEnd));
  const sharedVocabulary = createSharedVocabulary(
    uniqueStrings(options.sharedTokens ?? [], "sharedTokens"),
    header.sharedHashLength,
  );
  if (
    header.sharedFingerprint !== "-" &&
    sharedVocabulary.fingerprint !== header.sharedFingerprint
  ) {
    throw new Error("TGJ shared token registry does not match the header");
  }
  const activeSharedVocabulary =
    header.sharedFingerprint === "-"
      ? createSharedVocabulary([], header.sharedHashLength)
      : sharedVocabulary;
  const json = decodeBody(
    body,
    dictionary,
    directAlphabet,
    activeSharedVocabulary,
    header.expandedBytes,
  );

  return JSON.parse(json) as unknown;
}

function resolveOptions(options: TgjOptions): ResolvedOptions {
  const maxTokens = options.maxTokens ?? printableCodes.length;
  const minOccurrences = options.minOccurrences ?? 2;
  const minTokenBytes = options.minTokenBytes ?? 4;
  const sharedHashLength = options.sharedHashLength ?? 6;

  assertIntegerRange(maxTokens, "maxTokens", 0, printableCodes.length);
  assertIntegerRange(minOccurrences, "minOccurrences", 2, 1_000_000);
  assertIntegerRange(minTokenBytes, "minTokenBytes", 2, 1024);
  assertIntegerRange(
    sharedHashLength,
    "sharedHashLength",
    MIN_SHARED_HASH_LENGTH,
    MAX_SHARED_HASH_LENGTH,
  );

  return {
    maxTokens,
    minOccurrences,
    minTokenBytes,
    customTokens: uniqueStrings(options.customTokens ?? [], "customTokens"),
    sharedTokens: uniqueStrings(options.sharedTokens ?? [], "sharedTokens"),
    sharedHashLength,
  };
}

function serializeJson(value: unknown): string {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new Error("TGJ input must be JSON serializable");
  }

  return json;
}

function collectCandidateHints(
  value: unknown,
  options: ResolvedOptions,
): Map<string, number> {
  const hints = new Map<string, number>();
  const add = (candidate: string, count = 1): void => {
    if (!isWellFormedUnicode(candidate)) {
      return;
    }

    const bytes = utf8Length(candidate);
    if (bytes < options.minTokenBytes || bytes > MAX_DICTIONARY_ENTRY_BYTES) {
      return;
    }

    hints.set(candidate, (hints.get(candidate) ?? 0) + count);
  };

  for (const token of options.customTokens) {
    add(token, options.minOccurrences);
  }

  visitJsonValue(value, 0, add);

  return hints;
}

function visitJsonValue(
  value: unknown,
  depth: number,
  add: (candidate: string, count?: number) => void,
): void {
  if (typeof value === "string") {
    for (const candidate of stringCandidates(value)) {
      add(candidate);
    }

    return;
  }

  if (value === null || typeof value !== "object") {
    return;
  }

  if (depth > 0) {
    const subtree = JSON.stringify(value);
    if (utf8Length(subtree) <= MAX_DICTIONARY_ENTRY_BYTES) {
      add(subtree);
    }
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      visitJsonValue(item, depth + 1, add);
    }

    return;
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);

  keys.forEach((key, index) => {
    const child = record[key];
    const encodedKey = JSON.stringify(key);
    const prefix = index === 0 ? "{" : ",";

    add(`${encodedKey}:`);
    add(`${prefix}${encodedKey}:`);

    if (isJsonScalar(child)) {
      const encodedValue = JSON.stringify(child);
      add(`${encodedKey}:${encodedValue}`);
      add(`${prefix}${encodedKey}:${encodedValue}`);
    }

    visitJsonValue(child, depth + 1, add);
  });
}

function stringCandidates(value: string): Set<string> {
  const candidates = new Set<string>();
  const encoded = JSON.stringify(value);
  const content = encoded.slice(1, -1);

  candidates.add(encoded);
  candidates.add(content);

  const timestamp = /^(\d{4}-\d{2}-\d{2})T/.exec(value);
  if (timestamp) {
    candidates.add(timestamp[1]!);

    return candidates;
  }

  addUrlCandidates(value, candidates);
  addEmailCandidates(value, candidates);
  addLexicalCandidates(content, candidates);

  const codePoints = Array.from(content);
  for (const width of [4, 6, 8, 12, 16, 24]) {
    if (codePoints.length >= width * 2) {
      candidates.add(codePoints.slice(0, width).join(""));
      candidates.add(codePoints.slice(-width).join(""));
    }
  }

  return candidates;
}

function addUrlCandidates(value: string, candidates: Set<string>): void {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/?#]+)([^?#]*)/.exec(value);
  if (!match) {
    return;
  }

  const origin = `${match[1]!}${match[2]!}`;
  candidates.add(origin);
  candidates.add(match[2]!);

  const segments = match[3]!.split("/").filter(Boolean);
  let prefix = origin;

  for (const segment of segments.slice(0, 3)) {
    prefix += `/${segment}`;
    candidates.add(prefix);
    candidates.add(segment);
  }

  const suffix = /(?:\/issues|#readme|\.git|\/tree\/[^/?#]+)$/.exec(value);
  if (suffix) {
    candidates.add(suffix[0]);
  }
}

function addEmailCandidates(value: string, candidates: Set<string>): void {
  const at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) {
    return;
  }

  candidates.add(value.slice(at));
  candidates.add(value.slice(at + 1));
}

function addLexicalCandidates(content: string, candidates: Set<string>): void {
  const parts = content.match(/[A-Za-z0-9]+|[^A-Za-z0-9]+/g) ?? [];

  for (let start = 0; start < parts.length; start += 1) {
    let candidate = "";

    for (let offset = 0; offset < 6; offset += 1) {
      const part = parts[start + offset];
      if (part === undefined) {
        break;
      }

      candidate += part;
      if (utf8Length(candidate) > 128) {
        break;
      }

      candidates.add(candidate);
    }
  }
}

function selectLocalTokens(
  initialSegments: Segment[],
  hints: Map<string, number>,
  options: ResolvedOptions,
): { tokens: string[]; segments: Segment[] } {
  const candidates = [...hints]
    .map(([value, hintedOccurrences]) => {
      const bytes = utf8Length(value);
      const entryBytes = dictionaryEntryBytes(value);
      const score = hintedOccurrences * (bytes - 2) - entryBytes;

      return { value, hintedOccurrences, score };
    })
    .filter(
      (candidate) =>
        candidate.hintedOccurrences >= options.minOccurrences &&
        candidate.score > 0,
    )
    .sort(
      (left, right) =>
        right.score - left.score ||
        utf8Length(right.value) - utf8Length(left.value) ||
        left.value.localeCompare(right.value),
    );
  const maxChecks = Math.min(
    candidates.length,
    Math.max(512, options.maxTokens * 12),
  );
  const tokens: string[] = [];
  let segments = initialSegments;

  for (const candidate of candidates.slice(0, maxChecks)) {
    if (tokens.length >= options.maxTokens) {
      break;
    }

    const occurrences = countInLiteralSegments(segments, candidate.value);
    if (occurrences < options.minOccurrences) {
      continue;
    }

    const referenceBytes = tokens.length < DIRECT_TOKEN_LIMIT ? 1 : 2;
    const gain =
      occurrences * (utf8Length(candidate.value) - referenceBytes) -
      dictionaryEntryBytes(candidate.value);
    if (gain <= 0) {
      continue;
    }

    const index = tokens.length;
    tokens.push(candidate.value);
    segments = replaceInLiteralSegments(segments, candidate.value, {
      kind: "local",
      index,
    });
  }

  return { tokens, segments };
}

function selectSharedTokens(
  segments: Segment[],
  vocabulary: SharedVocabulary,
  hashLength: number,
): Segment[] {
  const referenceBytes = hashLength + 2;
  const candidates = vocabulary.entries
    .map((entry) => {
      const occurrences = countInLiteralSegments(segments, entry.value);
      const literalBytes = occurrences * utf8Length(entry.value);
      const sharedBytes = occurrences * referenceBytes;
      const localBytes = dictionaryEntryBytes(entry.value) + occurrences * 1;
      const gain = literalBytes - sharedBytes;

      return { ...entry, occurrences, gain, localBytes, sharedBytes };
    })
    .filter(
      (entry) =>
        entry.occurrences > 0 &&
        entry.gain > 0 &&
        entry.sharedBytes < entry.localBytes,
    )
    .sort(
      (left, right) =>
        right.gain - left.gain ||
        utf8Length(right.value) - utf8Length(left.value) ||
        left.value.localeCompare(right.value),
    );
  let nextSegments = segments;

  for (const candidate of candidates) {
    const occurrences = countInLiteralSegments(nextSegments, candidate.value);
    const sharedBytes = occurrences * referenceBytes;
    const localBytes = dictionaryEntryBytes(candidate.value) + occurrences * 1;
    if (
      occurrences * utf8Length(candidate.value) <= sharedBytes ||
      sharedBytes >= localBytes
    ) {
      continue;
    }

    nextSegments = replaceInLiteralSegments(nextSegments, candidate.value, {
      kind: "shared",
      alias: candidate.alias,
    });
  }

  return nextSegments;
}

function countInLiteralSegments(
  segments: Segment[],
  candidate: string,
): number {
  let count = 0;

  for (const segment of segments) {
    if (segment.kind !== "literal") {
      continue;
    }

    let cursor = 0;
    while (cursor <= segment.value.length - candidate.length) {
      const index = segment.value.indexOf(candidate, cursor);
      if (index === -1) {
        break;
      }

      count += 1;
      cursor = index + candidate.length;
    }
  }

  return count;
}

function replaceInLiteralSegments(
  segments: Segment[],
  candidate: string,
  replacement: Exclude<Segment, { kind: "literal" }>,
): Segment[] {
  const result: Segment[] = [];

  for (const segment of segments) {
    if (segment.kind !== "literal") {
      result.push(segment);
      continue;
    }

    let cursor = 0;
    while (cursor <= segment.value.length - candidate.length) {
      const index = segment.value.indexOf(candidate, cursor);
      if (index === -1) {
        break;
      }

      if (index > cursor) {
        result.push({
          kind: "literal",
          value: segment.value.slice(cursor, index),
        });
      }

      result.push(replacement);
      cursor = index + candidate.length;
    }

    if (cursor < segment.value.length) {
      result.push({ kind: "literal", value: segment.value.slice(cursor) });
    }
  }

  return result;
}

function chooseDirectAlphabet(segments: Segment[], count: number): string[] {
  const frequency = new Map(printableCodes.map((char) => [char, 0]));

  for (const segment of segments) {
    if (segment.kind !== "literal") {
      continue;
    }

    for (const char of segment.value) {
      if (frequency.has(char)) {
        frequency.set(char, frequency.get(char)! + 1);
      }
    }
  }

  return [...frequency]
    .sort(
      ([leftChar, leftCount], [rightChar, rightCount]) =>
        leftCount - rightCount || leftChar.localeCompare(rightChar),
    )
    .slice(0, count)
    .map(([char]) => char);
}

function encodeSegments(
  segments: Segment[],
  directAlphabet: string[],
  tokenCount: number,
): string {
  const direct = new Set(directAlphabet);
  const extended = printableCodes.filter((char) => !direct.has(char));
  const output: string[] = [];

  for (const segment of segments) {
    if (segment.kind === "local") {
      if (segment.index >= tokenCount) {
        throw new Error("TGJ local token index exceeds the dictionary");
      }

      if (segment.index < directAlphabet.length) {
        output.push(directAlphabet[segment.index]!);
      } else {
        const code = extended[segment.index - directAlphabet.length];
        if (code === undefined) {
          throw new Error("TGJ local token index exceeds the code alphabet");
        }

        output.push(`${ESCAPE}${code}`);
      }

      continue;
    }

    if (segment.kind === "shared") {
      output.push(`${ESCAPE}${SHARED_MARKER}${segment.alias}`);
      continue;
    }

    for (const char of segment.value) {
      if (char === ESCAPE) {
        output.push(`${ESCAPE}${ESCAPE}`);
      } else if (direct.has(char)) {
        output.push(`${ESCAPE}${char}`);
      } else {
        output.push(char);
      }
    }
  }

  return output.join("");
}

function decodeBody(
  body: string,
  dictionary: string[],
  directAlphabet: string,
  sharedVocabulary: SharedVocabulary,
  expectedExpandedBytes: number,
): string {
  const direct = new Map(
    directAlphabet.split("").map((char, index) => [char, index]),
  );
  const extended = printableCodes.filter((char) => !direct.has(char));
  const extendedIndex = new Map(extended.map((char, index) => [char, index]));
  const output: string[] = [];
  let outputBytes = 0;
  const append = (value: string): void => {
    outputBytes += utf8Length(value);
    if (outputBytes > expectedExpandedBytes) {
      throw new Error("TGJ expanded payload exceeds its declared byte length");
    }

    output.push(value);
  };

  for (let index = 0; index < body.length; index += 1) {
    const char = body[index]!;
    const directIndex = direct.get(char);

    if (directIndex !== undefined) {
      append(dictionary[directIndex]!);
      continue;
    }
    if (char !== ESCAPE) {
      const codePoint = body.codePointAt(index)!;
      const literal = String.fromCodePoint(codePoint);
      append(literal);
      index += literal.length - 1;
      continue;
    }

    const marker = body[index + 1];
    if (marker === undefined) {
      throw new Error("TGJ body ends with an incomplete escape");
    }

    index += 1;

    if (marker === ESCAPE) {
      append(ESCAPE);
      continue;
    }
    if (marker === SHARED_MARKER) {
      if (sharedVocabulary.entries.length === 0) {
        throw new Error("TGJ body requires a shared token vocabulary");
      }

      const hashLength = sharedVocabulary.hashLength;
      const alias = body.slice(index + 1, index + 1 + hashLength);
      if (alias.length !== hashLength || !/^[0-9a-f]+$/.test(alias)) {
        throw new Error("TGJ body contains a malformed shared token alias");
      }

      const shared = sharedVocabulary.byAlias.get(alias);
      if (shared === undefined) {
        throw new Error(`missing TGJ shared token alias: ${alias}`);
      }

      append(shared);
      index += hashLength;
      continue;
    }

    const escapedDirect = direct.get(marker);
    if (escapedDirect !== undefined) {
      append(marker);
      continue;
    }

    const offset = extendedIndex.get(marker);
    if (offset === undefined) {
      throw new Error("TGJ body contains an unknown token code");
    }

    const tokenIndex = directAlphabet.length + offset;
    const token = dictionary[tokenIndex];
    if (token === undefined) {
      throw new Error("TGJ body references a missing local token");
    }

    append(token);
  }

  if (outputBytes !== expectedExpandedBytes) {
    throw new Error("TGJ expanded byte length does not match the header");
  }

  return output.join("");
}

function serializeDictionary(tokens: string[]): string {
  return tokens.map((token) => `${utf8Length(token)}:${token}`).join("");
}

function parseDictionary(bytes: Uint8Array, tokenCount: number): string[] {
  const tokens: string[] = [];
  let cursor = 0;

  while (tokens.length < tokenCount) {
    const lengthStart = cursor;
    while (cursor < bytes.length && bytes[cursor] !== 58) {
      const byte = bytes[cursor]!;
      if (byte < 48 || byte > 57) {
        throw new Error("TGJ dictionary contains a malformed length");
      }

      cursor += 1;
    }

    if (cursor === lengthStart || cursor >= bytes.length) {
      throw new Error("TGJ dictionary contains an incomplete length");
    }

    const length = Number.parseInt(
      textDecoder.decode(bytes.subarray(lengthStart, cursor)),
      10,
    );
    cursor += 1;

    const end = cursor + length;
    if (
      !Number.isSafeInteger(length) ||
      length > MAX_DICTIONARY_ENTRY_BYTES ||
      end > bytes.length
    ) {
      throw new Error("TGJ dictionary entry exceeds the available bytes");
    }

    tokens.push(textDecoder.decode(bytes.subarray(cursor, end)));
    cursor = end;
  }

  if (cursor !== bytes.length) {
    throw new Error("TGJ dictionary contains trailing bytes");
  }

  return tokens;
}

function parseHeader(encoded: string): Header {
  const match =
    /^tgj1\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(-|[0-9a-f]{16}):(.*)$/s.exec(
      encoded,
    );
  if (!match) {
    throw new Error("malformed TGJ header");
  }

  const expandedBytes = parseHeaderInteger(match[1]!, "expandedBytes");
  const directCount = parseHeaderInteger(match[2]!, "directCount");
  const tokenCount = parseHeaderInteger(match[3]!, "tokenCount");
  const dictionaryBytes = parseHeaderInteger(match[4]!, "dictionaryBytes");
  const sharedHashLength = parseHeaderInteger(match[5]!, "sharedHashLength");
  const sharedFingerprint = match[6]!;

  assertIntegerRange(directCount, "directCount", 0, DIRECT_TOKEN_LIMIT);
  assertIntegerRange(tokenCount, "tokenCount", 0, printableCodes.length);
  assertIntegerRange(
    dictionaryBytes,
    "dictionaryBytes",
    0,
    MAX_DICTIONARY_BYTES,
  );
  assertIntegerRange(
    sharedHashLength,
    "sharedHashLength",
    MIN_SHARED_HASH_LENGTH,
    MAX_SHARED_HASH_LENGTH,
  );
  if (directCount > tokenCount) {
    throw new Error("TGJ direct token count exceeds its dictionary");
  }

  return {
    expandedBytes,
    directCount,
    tokenCount,
    dictionaryBytes,
    sharedHashLength,
    sharedFingerprint,
    payload: match[7]!,
  };
}

function validateDirectAlphabet(alphabet: string, count: number): void {
  const chars = alphabet.split("");
  if (chars.length !== count || new Set(chars).size !== count) {
    throw new Error("TGJ direct token alphabet is malformed");
  }
  if (chars.some((char) => !printableCodes.includes(char))) {
    throw new Error("TGJ direct token alphabet contains a reserved character");
  }
}

function createSharedVocabulary(
  tokens: string[],
  hashLength: number,
): SharedVocabulary {
  const byAlias = new Map<string, string>();
  const entries: Array<{ alias: string; value: string }> = [];

  for (const value of tokens) {
    const alias = createHash("sha256")
      .update(value, "utf8")
      .digest("hex")
      .slice(0, hashLength);
    const existing = byAlias.get(alias);

    if (existing !== undefined && existing !== value) {
      throw new Error(`TGJ shared token hash collision: ${alias}`);
    }
    if (existing !== undefined) {
      continue;
    }

    byAlias.set(alias, value);
    entries.push({ alias, value });
  }

  const fingerprint = createHash("sha256")
    .update(`${hashLength}:`)
    .update(JSON.stringify([...tokens].sort()))
    .digest("hex")
    .slice(0, SHARED_FINGERPRINT_LENGTH);

  return { byAlias, entries, fingerprint, hashLength };
}

function isJsonScalar(value: unknown): boolean {
  return value === null || typeof value !== "object";
}

function dictionaryEntryBytes(value: string): number {
  const bytes = utf8Length(value);

  return String(bytes).length + 1 + bytes;
}

function utf8Length(value: string): number {
  return textEncoder.encode(value).length;
}

function uniqueStrings(values: readonly string[], name: string): string[] {
  if (
    values.some(
      (value) =>
        typeof value !== "string" ||
        value.length === 0 ||
        !isWellFormedUnicode(value),
    )
  ) {
    throw new Error(`${name} must contain non-empty, well-formed strings`);
  }

  return [...new Set(values)];
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        return false;
      }

      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }

  return true;
}

function assertIntegerRange(
  value: number,
  name: string,
  minimum: number,
  maximum: number,
): void {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
}

function parseHeaderInteger(value: string, name: string): number {
  if (!/^(?:0|[1-9]\d*)$/.test(value)) {
    throw new Error(`TGJ ${name} is not a canonical unsigned integer`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`TGJ ${name} exceeds the safe integer range`);
  }

  return parsed;
}
