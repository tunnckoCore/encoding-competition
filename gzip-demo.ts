import { constants as zlibConstants, gzipSync } from "node:zlib";

import { writeBenchmarkResults } from "./benchmark-output.ts";
import { decodeDialect, encodeDialect } from "./packages/dia1/src/index.ts";

const gzipLevel = zlibConstants.Z_BEST_COMPRESSION;

const byteLength = (value: string): number => Buffer.byteLength(value);
const gzipByteLength = (value: string): number =>
  gzipSync(Buffer.from(value), { level: gzipLevel }).byteLength;

const fixtures = [
  {
    name: "r50k_base.js (minified JS)",
    path: "./fixtures/code/r50k_base.js",
  },
  {
    name: "models.gen.ts (generated TS)",
    path: "./fixtures/code/models.gen.ts",
  },
  { name: "bun.d.ts (type declarations)", path: "./fixtures/code/bun.d.ts" },
  {
    name: "Tailwind CDN 3.4.17 (minified JS)",
    path: "./fixtures/code/tailwindcss-3.4.17.js",
  },
] as const;

console.log(`gzip level: ${gzipLevel}`);

const rows = [];
for (const fixture of fixtures) {
  console.log(`encoding ${fixture.name}...`);
  const source = await Bun.file(new URL(fixture.path, import.meta.url)).text();
  const dia1Wrapped = JSON.stringify(
    encodeDialect(source, { deduplicate: true }),
  );
  if (decodeDialect(JSON.parse(dia1Wrapped)) !== source) {
    throw new Error(`${fixture.name} DIA1 round trip failed`);
  }

  const gzipBytes = gzipByteLength(source);
  const gzipDia1Bytes = gzipByteLength(dia1Wrapped);

  rows.push({
    fixture: fixture.name,
    sourceBytes: byteLength(source),
    gzipBytes,
    dia1WrappedBytes: byteLength(dia1Wrapped),
    gzipDia1Bytes,
    gzipDia1Delta: gzipDia1Bytes - gzipBytes,
  });
}

await writeBenchmarkResults("code-compression.json", {
  benchmark: "code compression",
  gzipLevel,
  dia1: { deduplicate: true, jsonWrapped: true },
  rows,
});

console.table(rows);
