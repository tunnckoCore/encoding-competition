import { createHash } from "node:crypto";

export const tokenPrefix = "*";
export const directTokens = "?|^<>;%~$KQXY&V!DW'OJHF";
export const tokenBanks = "DEIBOPRH";

const preferredSuffixes =
  "!$&(),-./:=>@ACKMNST[_abcdfghijklmnpqrstuvwxyz" +
  "#%'+0123456789;<?FGJLQUVWXYZ]^`eo{|}~";
const allSuffixes = preferredSuffixes + tokenBanks;

export const simpleTokenSuffixes = preferredSuffixes;
export const tokenCapacity =
  directTokens.length +
  simpleTokenSuffixes.length +
  tokenBanks.length * allSuffixes.length;
export const alphabetFingerprint = createHash("sha256")
  .update(directTokens + tokenPrefix + simpleTokenSuffixes + tokenBanks)
  .digest("hex")
  .slice(0, 16);

const tokenCodes = [
  ...directTokens.split(""),
  ...simpleTokenSuffixes.split("").map((suffix) => tokenPrefix + suffix),
  ...tokenBanks
    .split("")
    .flatMap((bank) =>
      allSuffixes.split("").map((suffix) => tokenPrefix + bank + suffix),
    ),
];

export const tokenIndex = new Map(
  tokenCodes.map((token, index) => [token, index]),
);

export function tokenFor(index: number): string {
  if (!Number.isInteger(index) || index < 0 || index >= tokenCapacity) {
    throw new Error("dialect token index exceeds the alphabet");
  }

  return tokenCodes[index]!;
}

export function tokenByteLength(index: number): number {
  return tokenFor(index).length;
}

export function isTokenLiteral(character: string): boolean {
  return character === tokenPrefix || directTokens.includes(character);
}
