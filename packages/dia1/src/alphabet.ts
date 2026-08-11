export const tokenPrefix = "*";
export const directTokens = ">+()!,I<NXW$H_UBq~|;^OD%LF#VEQ?JMGR&YK";
export const tokenBanks = "DEIBOPRH";
export const stringDelimiter = "'";
export const stringEscape = "`";

const preferredSuffixes =
  "!$&()f-:/.=>@ACKMNST[_abcd,ghijklmnpqrstuvwxyz" +
  "#%'+0123456789;<?FGJLQUVWXYZ]^`eo{|}~";
const allSuffixes = preferredSuffixes + tokenBanks;
export const simpleTokenSuffixes = preferredSuffixes;

const bankTokenCapacity = tokenBanks.length * allSuffixes.length;
const longTokenDigits = 3;
const shortTokenCapacity =
  directTokens.length + simpleTokenSuffixes.length + bankTokenCapacity;

export const compactTokenCapacity = shortTokenCapacity;
export const tokenCapacity =
  shortTokenCapacity + allSuffixes.length ** longTokenDigits;

const tokenLiterals =
  tokenPrefix + directTokens + stringDelimiter + stringEscape;
const tokenLiteralCodes = new Uint8Array(128);
for (const character of tokenLiterals) {
  tokenLiteralCodes[character.charCodeAt(0)] = 1;
}

export function tokenFor(index: number): string {
  if (!Number.isInteger(index) || index < 0 || index >= tokenCapacity) {
    throw new Error("dialect token index exceeds the alphabet");
  }

  if (index < directTokens.length) {
    return directTokens[index]!;
  }

  let offset = index - directTokens.length;
  if (offset < simpleTokenSuffixes.length) {
    return tokenPrefix + simpleTokenSuffixes[offset]!;
  }

  offset -= simpleTokenSuffixes.length;
  if (offset < bankTokenCapacity) {
    const bank = Math.floor(offset / allSuffixes.length);
    const suffix = offset % allSuffixes.length;

    return tokenPrefix + tokenBanks[bank]! + allSuffixes[suffix]!;
  }

  offset -= bankTokenCapacity;
  let token = tokenPrefix + tokenPrefix;
  for (let position = longTokenDigits - 1; position >= 0; position -= 1) {
    const divisor = allSuffixes.length ** position;
    token += allSuffixes[Math.floor(offset / divisor) % allSuffixes.length]!;
  }

  return token;
}

export function tokenIndexFor(token: string): number | undefined {
  if (token.length === 1) {
    const index = directTokens.indexOf(token);

    return index < 0 ? undefined : index;
  }
  if (token.length === 2 && token[0] === tokenPrefix) {
    const suffix = simpleTokenSuffixes.indexOf(token[1]!);

    return suffix < 0 ? undefined : directTokens.length + suffix;
  }
  if (token.length === 3 && token[0] === tokenPrefix) {
    const bank = tokenBanks.indexOf(token[1]!);
    const suffix = allSuffixes.indexOf(token[2]!);
    if (bank < 0 || suffix < 0) {
      return undefined;
    }

    return (
      directTokens.length +
      simpleTokenSuffixes.length +
      bank * allSuffixes.length +
      suffix
    );
  }
  if (
    token.length === longTokenDigits + 2 &&
    token.startsWith(tokenPrefix + tokenPrefix)
  ) {
    let offset = 0;
    for (const character of token.slice(2)) {
      const digit = allSuffixes.indexOf(character);
      if (digit < 0) {
        return undefined;
      }

      offset = offset * allSuffixes.length + digit;
    }

    return shortTokenCapacity + offset;
  }

  return undefined;
}

export function tokenByteLength(index: number): number {
  return tokenFor(index).length;
}

export function isTokenLiteral(character: string): boolean {
  return tokenLiteralCodes[character.charCodeAt(0)] === 1;
}

if (new Set(allSuffixes).size !== allSuffixes.length) {
  throw new Error("dialect alphabet contains duplicate token suffixes");
}
if (new Set(directTokens).size !== directTokens.length) {
  throw new Error("dialect alphabet contains duplicate direct tokens");
}
for (const marker of tokenPrefix + "tfzsp=[{-0123456789" + stringDelimiter) {
  if (directTokens.includes(marker)) {
    throw new Error("dialect alphabet direct token shadows a body marker");
  }
}
