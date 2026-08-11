import { describe, expect, it } from "vite-plus/test";

import {
  canonicalizeNumber,
  canonicalizeString,
  sortObjectKeys,
} from "../src/canonical.ts";

describe("canonical JSON utilities", () => {
  it("canonicalizes string escapes and surrogate code units", () => {
    expect(canonicalizeString('a"b\\c')).toBe('"a\\"b\\\\c"');
    expect(canonicalizeString("\b\t\n\f\r")).toBe('"\\b\\t\\n\\f\\r"');
    expect(canonicalizeString("\u0000\u001f")).toBe('"\\u0000\\u001f"');
    expect(canonicalizeString("\ud800\udc00")).toBe('"𐀀"');
    expect(canonicalizeString("\ud800")).toBe('"\\ud800"');
    expect(canonicalizeString("\udc00")).toBe('"\\udc00"');
    expect(canonicalizeString("plain")).toBe('"plain"');
  });

  it("canonicalizes finite numbers and rejects non-finite numbers", () => {
    expect(canonicalizeNumber(0)).toBe("0");
    expect(canonicalizeNumber(-0)).toBe("0");
    expect(canonicalizeNumber(-12.5)).toBe("-12.5");
    expect(canonicalizeNumber(1e21)).toBe("1e+21");

    expect(() => canonicalizeNumber(Number.NaN)).toThrow(/non-finite/i);
    expect(() => canonicalizeNumber(Number.POSITIVE_INFINITY)).toThrow(
      /non-finite/i,
    );
  });

  it("sorts object keys", () => {
    expect(sortObjectKeys({ b: 2, a: 1 })).toEqual(["a", "b"]);
    expect(sortObjectKeys({ "10": true, "2": true, a: true })).toEqual([
      "10",
      "2",
      "a",
    ]);
  });
});
