import { constants as zlibConstants, gzipSync } from "node:zlib";

import { writeBenchmarkResults } from "./benchmark-output.ts";
import { decodeDialect, encodeDialect } from "./packages/dia1/src/index.ts";

const gzipLevel = zlibConstants.Z_BEST_COMPRESSION;
const targetSizes = [50_000, 100_000, 250_000, 500_000] as const;
const corpora = [
  {
    corpus: "generated prose",
    path: "./fixtures/prose/generated-prose-master.txt",
  },
  {
    corpus: "real prose",
    path: "./fixtures/prose/real-prose-master.txt",
  },
] as const;

const textEncoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", {
  fatal: true,
  ignoreBOM: true,
});

const byteLength = (value: string): number => Buffer.byteLength(value);
const gzipByteLength = (value: string): number =>
  gzipSync(Buffer.from(value), { level: gzipLevel }).byteLength;
const rounded = (value: number): number => Number(value.toFixed(2));

const normalizeProse = (source: string): string =>
  source
    .replace(/\r\n?/g, "\n")
    .trim()
    .split(/\n[\t ]*\n+/)
    .map((paragraph) =>
      paragraph
        .replace(/[\t ]*\n[\t ]*/g, " ")
        .replace(/[\t ]+/g, " ")
        .trim(),
    )
    .filter(Boolean)
    .join("\n\n");

const exactUtf8Prefix = (
  source: string,
  targetBytes: number,
): { paddingBytes: number; sample: string } => {
  const sourceBytes = textEncoder.encode(source);
  if (sourceBytes.byteLength < targetBytes) {
    throw new Error(
      `source has ${sourceBytes.byteLength} UTF-8 bytes, fewer than target ${targetBytes}`,
    );
  }

  for (let paddingBytes = 0; paddingBytes <= 3; paddingBytes += 1) {
    try {
      const prefixBytes = sourceBytes.subarray(0, targetBytes - paddingBytes);
      const sample = utf8Decoder.decode(prefixBytes) + " ".repeat(paddingBytes);
      if (byteLength(sample) !== targetBytes) {
        throw new Error(`failed to construct a ${targetBytes}-byte sample`);
      }

      return { paddingBytes, sample };
    } catch (error) {
      if (!(error instanceof TypeError)) {
        throw error;
      }
    }
  }

  throw new Error(`could not find a UTF-8 boundary for target ${targetBytes}`);
};

console.log(`Bun: ${Bun.version}`);
console.log(`gzip level: ${gzipLevel}`);
console.log("prose normalization: LF, one line per paragraph");

const rows = [];
for (const { corpus, path } of corpora) {
  const source = normalizeProse(
    await Bun.file(new URL(path, import.meta.url)).text(),
  );

  for (const target of targetSizes) {
    const { paddingBytes, sample } = exactUtf8Prefix(source, target);
    console.log(`encoding ${corpus} at ${target} bytes...`);

    const encodeStartedAt = performance.now();
    const dia1 = encodeDialect(sample, { deduplicate: true });
    const encodeMs = performance.now() - encodeStartedAt;
    const dia1Wrapped = JSON.stringify(dia1);
    const dia1Unwrapped = JSON.parse(dia1Wrapped);

    const decodeStartedAt = performance.now();
    const decoded = decodeDialect(dia1Unwrapped);
    const decodeMs = performance.now() - decodeStartedAt;
    if (decoded !== sample) {
      throw new Error(
        `${corpus} at ${target} bytes failed the DIA1 round trip`,
      );
    }

    const gzipBytes = gzipByteLength(sample);
    const gzipDia1Bytes = gzipByteLength(dia1Wrapped);
    const gzipDia1Delta = gzipDia1Bytes - gzipBytes;

    rows.push({
      corpus,
      target,
      sourceBytes: byteLength(sample),
      utf8PaddingBytes: paddingBytes,
      gzipBytes,
      dia1WrappedBytes: byteLength(dia1Wrapped),
      gzipDia1Bytes,
      gzipDia1Delta,
      gzipDia1DeltaPercent: rounded((gzipDia1Delta / gzipBytes) * 100),
      encodeMs: rounded(encodeMs),
      decodeMs: rounded(decodeMs),
    });
  }
}

await writeBenchmarkResults("prose-compression.json", {
  benchmark: "prose compression",
  runtime: `Bun ${Bun.version}`,
  gzipLevel,
  normalization: "LF, one line per paragraph",
  dia1: { deduplicate: true, jsonWrapped: true },
  rows,
});
console.table(rows);
