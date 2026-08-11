export const tokenPrefix = "*";
export const directTokens = ">+()!'I<NXW$H_UBq~|;^OD%LF#VEQ?JMGR&YK";
export const tokenBanks = "DEIBOPRH";

const preferredSuffixes =
  "!$&()f-:/.=>@ACKMNST[_abcd,ghijklmnpqrstuvwxyz" +
  "#%'+0123456789;<?FGJLQUVWXYZ]^`eo{|}~";
const allSuffixes = preferredSuffixes + tokenBanks;

export const simpleTokenSuffixes = preferredSuffixes;
export const tokenCapacity =
  directTokens.length +
  simpleTokenSuffixes.length +
  tokenBanks.length * allSuffixes.length;

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

const tokenLiterals = tokenPrefix + directTokens;
const tokenLiteralCodes = new Uint8Array(128);
for (const character of tokenLiterals) {
  tokenLiteralCodes[character.charCodeAt(0)] = 1;
}

const tokenLiteralClass = tokenLiterals.replace(
  /[\\\]\-^]/g,
  (character) => "\\" + character,
);
export const tokenLiteralPattern = new RegExp(`[${tokenLiteralClass}]`, "g");

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
  return tokenLiteralCodes[character.charCodeAt(0)] === 1;
}
