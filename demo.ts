import { encode as encodeToon, decode as decodeToon } from "@toon-format/toon";
import { encode as encodeGPT } from "gpt-tokenizer";
import fixture from "./fixture.json" with { type: "json" };
import canonFixture from "./fixture-canonicalized.json" with { type: "json" };
import { writeBenchmarkResults } from "./benchmark-output.ts";

import {
  /*encodeHbs, decodeHbs*/ createHbs,
} from "./packages/hbs/src/index.ts";
import { encodeTgj, decodeTgj } from "./packages/tgj/src/index.ts";
import { encodeDialect, decodeDialect } from "./packages/dia1/src/index.ts";

const sharedTokens = {
  sharedTokens: [
    "https://github.com/tunnckocore",
    "https://github.com",
    "https://www.npmjs.com/package/",
    "https://www.npmjs.com",
  ],
} as const;

const json = JSON.stringify(fixture);
const canon = JSON.stringify(canonFixture);

const tgj = encodeTgj(fixture);
const tgjShared = encodeTgj(fixture, sharedTokens);
const dia1 = encodeDialect(fixture);
const toon = encodeToon(fixture);
const hbs = createHbs();
const hbs3 = hbs.encode(fixture);

if (JSON.stringify(decodeTgj(tgj)) !== json) {
  throw new Error("TGJ round trip failed");
}
if (JSON.stringify(decodeTgj(tgjShared, sharedTokens)) !== json) {
  throw new Error("TGJ shared-token round trip failed");
}
if (JSON.stringify(decodeDialect(dia1)) !== json) {
  throw new Error("DIA1 round trip failed");
}
if (JSON.stringify(hbs.decode(hbs3).value) !== canon) {
  throw new Error("HBS3 round trip failed");
}
if (JSON.stringify(decodeToon(toon)) !== json) {
  throw new Error("TOON round trip failed");
}

const size = (value: string): number => new TextEncoder().encode(value).length;

type SizeRow = {
  format: "TOON" | "JSON" | "HBS3" | "TGJ" | "DIA1";
  bytes: number;
  tokens: number;
};

const rows: SizeRow[] = [
  { format: "TOON", bytes: size(toon), tokens: encodeGPT(toon).length },
  { format: "JSON", bytes: size(json), tokens: encodeGPT(json).length },
  { format: "HBS3", bytes: size(hbs3), tokens: encodeGPT(hbs3).length },
  { format: "TGJ", bytes: size(tgj), tokens: encodeGPT(tgj).length },
  { format: "DIA1", bytes: size(dia1), tokens: encodeGPT(dia1).length },
];

await writeBenchmarkResults("size-wars.json", {
  benchmark: "size wars",
  tokenizer: "gpt-tokenizer",
  rows,
});

console.table(rows);
