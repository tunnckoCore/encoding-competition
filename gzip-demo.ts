import { constants as zlibConstants, gzipSync } from "node:zlib";

import fixture from "./fixture.json" with { type: "json" };
import { decodeDialect, encodeDialect } from "./packages/dia1/src/index.ts";

const gzipLevel = zlibConstants.Z_BEST_COMPRESSION;

const byteLength = (value: string): number => Buffer.byteLength(value);
const gzipByteLength = (value: string): number =>
  gzipSync(Buffer.from(value), { level: gzipLevel }).byteLength;

const npmJson = JSON.stringify(fixture);
const npmDia1Wrapped = JSON.stringify(
  encodeDialect(fixture, { deduplicate: true }),
);
if (JSON.stringify(decodeDialect(JSON.parse(npmDia1Wrapped))) !== npmJson) {
  throw new Error("NPM DIA1 round trip failed");
}

const javascript = await Bun.file(
  new URL("./fixture-javascript.js", import.meta.url),
).text();
const javascriptDia1Wrapped = JSON.stringify(
  encodeDialect(javascript, { deduplicate: true }),
);
if (decodeDialect(JSON.parse(javascriptDia1Wrapped)) !== javascript) {
  throw new Error("JavaScript DIA1 round trip failed");
}

const rows = [
  { format: "JSON", fixture: "NPM API", value: npmJson },
  {
    format: "DIA1 (dedup, JSON-wrapped)",
    fixture: "NPM API",
    value: npmDia1Wrapped,
  },
  { format: "JavaScript", fixture: "~250 KB bundle", value: javascript },
  {
    format: "DIA1 (dedup, JSON-wrapped)",
    fixture: "~250 KB bundle",
    value: javascriptDia1Wrapped,
  },
].map(({ fixture: name, format, value }) => {
  const bytes = byteLength(value);
  const gzipBytes = gzipByteLength(value);

  return {
    fixture: name,
    format,
    bytes,
    gzipBytes,
    gzipPercent: `${((gzipBytes / bytes) * 100).toFixed(1)}%`,
  };
});

console.log(`gzip level: ${gzipLevel}`);
console.table(rows);
