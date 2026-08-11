import {
  brotliCompressSync,
  constants as zlibConstants,
  gzipSync,
} from "node:zlib";

import { decodeDialect, encodeDialect } from "../../packages/dia1/src/index.ts";

const gzipLevel = 9;
const brotliQuality = 11;
const resultDirectory = new URL("./", import.meta.url);

type Fixture = {
  objects: unknown[];
  [key: string]: unknown;
};

const fixture = (await Bun.file(
  new URL("../../fixture.json", import.meta.url),
).json()) as Fixture;
const samples = [
  {
    case: "43kb",
    objects: 40,
    value: { ...fixture, objects: fixture.objects.slice(0, 40) },
  },
  {
    case: "271kb",
    objects: fixture.objects.length,
    value: fixture,
  },
];

const rows = [];

for (const sample of samples) {
  const original = JSON.stringify(sample.value);
  const dia1 = encodeDialect(sample.value);
  const dia2 = encodeDialect(sample.value, { dia2: true });

  assertRoundTrip(original, dia1, "DIA1");
  assertRoundTrip(original, dia2, "DIA2");

  const originalGzip = compressGzip(original);
  const originalBrotli = compressBrotli(original);
  const dia1Gzip = compressGzip(dia1);
  const dia2Gzip = compressGzip(dia2);
  const dia1Brotli = compressBrotli(dia1);
  const dia2Brotli = compressBrotli(dia2);

  await Promise.all([
    write(sample.case + ".original.json", original),
    write(sample.case + ".dia1", dia1),
    write(sample.case + ".dia2", dia2),
    write(sample.case + ".original.json.gz", originalGzip),
    write(sample.case + ".original.json.br", originalBrotli),
    write(sample.case + ".dia1.gz", dia1Gzip),
    write(sample.case + ".dia1.br", dia1Brotli),
    write(sample.case + ".dia2.gz", dia2Gzip),
    write(sample.case + ".dia2.br", dia2Brotli),
  ]);

  rows.push({
    case: sample.case,
    objects: sample.objects,
    originalBytes: Buffer.byteLength(original),
    originalGzipBytes: originalGzip.byteLength,
    originalBrotliBytes: originalBrotli.byteLength,
    dia1Bytes: Buffer.byteLength(dia1),
    dia2Bytes: Buffer.byteLength(dia2),
    dia1GzipBytes: dia1Gzip.byteLength,
    dia2GzipBytes: dia2Gzip.byteLength,
    dia1BrotliBytes: dia1Brotli.byteLength,
    dia2BrotliBytes: dia2Brotli.byteLength,
  });
}

const results = {
  benchmark: "npm JSON DIA1 and DIA2 compression",
  runtime: `Bun ${Bun.version}`,
  gzipLevel,
  brotliQuality,
  brotliMode: "text",
  rows,
};

await write("sizes.json", JSON.stringify(results, undefined, 2) + "\n");
console.table(rows);

function assertRoundTrip(
  original: string,
  encoded: string,
  format: string,
): void {
  if (JSON.stringify(decodeDialect(encoded)) !== original) {
    throw new Error(format + " round-trip failed");
  }
}

function compressGzip(value: string): Buffer {
  return gzipSync(Buffer.from(value), { level: gzipLevel });
}

function compressBrotli(value: string): Buffer {
  return brotliCompressSync(Buffer.from(value), {
    params: {
      [zlibConstants.BROTLI_PARAM_MODE]: zlibConstants.BROTLI_MODE_TEXT,
      [zlibConstants.BROTLI_PARAM_QUALITY]: brotliQuality,
      [zlibConstants.BROTLI_PARAM_SIZE_HINT]: Buffer.byteLength(value),
    },
  });
}

async function write(name: string, value: string | Uint8Array): Promise<void> {
  await Bun.write(new URL(name, resultDirectory), value);
}
