import {
  brotliCompressSync,
  constants as zlibConstants,
  gzipSync,
} from "node:zlib";

import { writeBenchmarkResults } from "./benchmark-output.ts";
import fixture from "./fixture.json" with { type: "json" };
import { decodeDialect, encodeDialect } from "./packages/dia1/src/index.ts";

const gzipLevel = 9;
const brotliQuality = 11;
const brotliMode = zlibConstants.BROTLI_MODE_TEXT;

const byteLength = (value: string): number => Buffer.byteLength(value);
const gzipByteLength = (value: string): number =>
  gzipSync(Buffer.from(value), { level: gzipLevel }).byteLength;
const brotliByteLength = (value: string): number =>
  brotliCompressSync(Buffer.from(value), {
    params: {
      [zlibConstants.BROTLI_PARAM_MODE]: brotliMode,
      [zlibConstants.BROTLI_PARAM_QUALITY]: brotliQuality,
    },
  }).byteLength;
const rounded = (value: number): number => Number(value.toFixed(2));

const fixtures = [
  {
    fixture: "first 40 objects",
    value: { ...fixture, objects: fixture.objects.slice(0, 40) },
  },
  { fixture: "full fixture", value: fixture },
] as const;

const rows = [];
for (const sample of fixtures) {
  const sourceJson = JSON.stringify(sample.value);
  const parsedValue: unknown = JSON.parse(sourceJson);

  const encodeStartedAt = performance.now();
  const dia1 = encodeDialect(parsedValue, { deduplicate: true });
  const encodeMs = performance.now() - encodeStartedAt;
  const dia1Wrapped = JSON.stringify(dia1);
  const dia1Unwrapped = JSON.parse(dia1Wrapped);

  const decodeStartedAt = performance.now();
  const decoded = decodeDialect(dia1Unwrapped);
  const decodeMs = performance.now() - decodeStartedAt;
  if (JSON.stringify(decoded) !== sourceJson) {
    throw new Error(`${sample.fixture} failed the DIA1 round trip`);
  }

  const gzipSourceBytes = gzipByteLength(sourceJson);
  const gzipDia1Bytes = gzipByteLength(dia1Wrapped);
  const gzipDia1Delta = gzipDia1Bytes - gzipSourceBytes;
  const brotliSourceBytes = brotliByteLength(sourceJson);
  const brotliDia1Bytes = brotliByteLength(dia1Wrapped);
  const brotliDia1Delta = brotliDia1Bytes - brotliSourceBytes;

  rows.push({
    fixture: sample.fixture,
    objects: sample.value.objects.length,
    sourceJsonBytes: byteLength(sourceJson),
    dia1WrappedBytes: byteLength(dia1Wrapped),
    gzipSourceBytes,
    gzipDia1Bytes,
    gzipDia1Delta,
    gzipDia1DeltaPercent: rounded((gzipDia1Delta / gzipSourceBytes) * 100),
    brotliSourceBytes,
    brotliDia1Bytes,
    brotliDia1Delta,
    brotliDia1DeltaPercent: rounded(
      (brotliDia1Delta / brotliSourceBytes) * 100,
    ),
    encodeMs: rounded(encodeMs),
    decodeMs: rounded(decodeMs),
  });
}

await writeBenchmarkResults("npm-json-compression.json", {
  benchmark: "NPM JSON compression",
  runtime: `Bun ${Bun.version}`,
  gzipLevel,
  brotliQuality,
  brotliMode: "text",
  dia1: { deduplicate: true, jsonWrapped: true },
  rows,
});

console.table(rows);
