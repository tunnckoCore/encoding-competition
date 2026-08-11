import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vite-plus/test";

import vectorSetJson from "../src/vectors.json" with { type: "json" };
import type { ConformanceVector, ConformanceVectorSet } from "../src/types.ts";

const vectorSet = vectorSetJson as ConformanceVectorSet;

describe("HBS3 conformance vectors", () => {
  it("has unique vector ids", () => {
    const ids = allVectors(vectorSet).map((vector) => vector.id);

    expect(new Set(ids).size).toBe(ids.length);
  });

  it("validates the bundled reference adapters through the CLI contract", () => {
    const cliPath = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    const encodePath = fileURLToPath(
      new URL("../test-adapters/reference-encode.ts", import.meta.url),
    );
    const decodePath = fileURLToPath(
      new URL("../test-adapters/reference-decode.ts", import.meta.url),
    );
    const result = spawnSync(
      "bun",
      [
        cliPath,
        "check-commands",
        "--encode",
        "bun",
        encodePath,
        "--decode",
        "bun",
        decodePath,
      ],
      {
        encoding: "utf8",
        maxBuffer: 20 * 1024 * 1024,
      },
    );
    const stdout = result.stdout ?? "";
    const stderr = result.stderr ?? "";

    expect(`${stderr}\n${stdout}`).toContain(
      "pass: HBS3 conformance commands match all vectors",
    );
    expect(result.status, `${stderr}\n${stdout}`).toBe(0);
  }, 60_000);
});

function allVectors(vectorSet: ConformanceVectorSet): ConformanceVector[] {
  return [...vectorSet.vectors, ...vectorSet.rejects];
}
