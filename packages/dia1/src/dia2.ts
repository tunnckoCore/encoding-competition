import {
  brotliCompressSync,
  brotliDecompressSync,
  constants as zlibConstants,
} from "node:zlib";

const FORMAT = "dia2";
const BASE91 =
  "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}~";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", {
  fatal: true,
  ignoreBOM: true,
});
const base91Indexes = createBase91Indexes();

export type DecodedDia2Envelope = {
  dia1: string;
  headerBytes: number;
};

type BrotliDecodeResult = {
  buffer: Uint8Array;
  engine: { bytesWritten: number };
};

export function encodeDia2Envelope(
  dia1Header: string,
  dia1Body: string,
  maximumHeaderBytes: number,
): string {
  if (!dia1Header.startsWith("dia1.")) {
    throw new Error("dia2 can only wrap a dia1 header");
  }

  const header = textEncoder.encode(dia1Header);
  if (header.byteLength > maximumHeaderBytes) {
    throw new Error("dia2 header exceeds the encoder limit");
  }

  const compressed = brotliCompressSync(header, {
    params: {
      [zlibConstants.BROTLI_PARAM_MODE]: zlibConstants.BROTLI_MODE_TEXT,
      [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
      [zlibConstants.BROTLI_PARAM_SIZE_HINT]: header.byteLength,
    },
  });
  const packed = encodeBase91(compressed);

  return (
    FORMAT +
    "." +
    header.byteLength +
    "." +
    packed.length +
    ":" +
    packed +
    dia1Body
  );
}

export function decodeDia2Envelope(
  encoded: string,
  maximumHeaderBytes: number,
): DecodedDia2Envelope {
  const match = /^dia2\.(\d+)\.(\d+):/.exec(encoded);
  if (!match) {
    throw new Error("malformed dia2 envelope");
  }

  const headerBytes = parseHeaderBytes(match[1]!, maximumHeaderBytes);
  const packedBytes = parsePackedBytes(match[2]!, headerBytes);
  const packedEnd = match[0].length + packedBytes;
  if (packedEnd > encoded.length) {
    throw new Error("dia2 packed header exceeds the available payload");
  }

  const packed = encoded.slice(match[0].length, packedEnd);
  if (Buffer.byteLength(packed) !== packedBytes) {
    throw new Error("dia2 packed header contains a non-ASCII character");
  }

  const compressed = decodeBase91(packed);
  let decoded: Uint8Array;

  try {
    const result = brotliDecompressSync(compressed, {
      info: true,
      maxOutputLength: headerBytes,
    }) as unknown as BrotliDecodeResult;
    if (result.engine.bytesWritten !== compressed.byteLength) {
      throw new Error("trailing compressed bytes");
    }

    decoded = result.buffer;
  } catch {
    throw new Error("dia2 envelope contains an invalid packed header");
  }

  if (decoded.byteLength !== headerBytes) {
    throw new Error("dia2 header byte length does not match the envelope");
  }

  let dia1Header: string;
  try {
    dia1Header = textDecoder.decode(decoded);
  } catch {
    throw new Error("dia2 header is not valid UTF-8");
  }

  if (!dia1Header.startsWith("dia1.")) {
    throw new Error("dia2 envelope does not contain a dia1 header");
  }

  return {
    dia1: dia1Header + encoded.slice(packedEnd),
    headerBytes,
  };
}

function encodeBase91(bytes: Uint8Array): string {
  let bits = 0;
  let output = "";
  let queue = 0;

  for (const byte of bytes) {
    queue |= byte << bits;
    bits += 8;

    if (bits <= 13) {
      continue;
    }

    let value = queue & 8191;
    if (value > 88) {
      queue >>>= 13;
      bits -= 13;
    } else {
      value = queue & 16_383;
      queue >>>= 14;
      bits -= 14;
    }

    output += BASE91[value % 91]! + BASE91[Math.floor(value / 91)]!;
  }

  if (bits > 0) {
    output += BASE91[queue % 91]!;
    if (bits > 7 || queue > 90) {
      output += BASE91[Math.floor(queue / 91)]!;
    }
  }

  return output;
}

function decodeBase91(encoded: string): Uint8Array {
  const output = new Uint8Array(encoded.length);
  let outputLength = 0;
  let bits = 0;
  let pending = -1;
  let queue = 0;

  for (const character of encoded) {
    const code = character.charCodeAt(0);
    const digit = code < base91Indexes.length ? base91Indexes[code]! : -1;
    if (digit < 0) {
      throw new Error("dia2 packed header contains an invalid character");
    }

    if (pending < 0) {
      pending = digit;
      continue;
    }

    pending += digit * 91;
    queue |= pending << bits;
    bits += (pending & 8191) > 88 ? 13 : 14;

    while (bits >= 8) {
      output[outputLength] = queue & 255;
      outputLength += 1;
      queue >>>= 8;
      bits -= 8;
    }

    pending = -1;
  }

  if (pending >= 0) {
    output[outputLength] = (queue | (pending << bits)) & 255;
    outputLength += 1;
  }

  const bytes = output.slice(0, outputLength);
  if (encodeBase91(bytes) !== encoded) {
    throw new Error("dia2 packed header is not canonical base91");
  }

  return bytes;
}

function createBase91Indexes(): Int16Array {
  const indexes = new Int16Array(128);
  indexes.fill(-1);

  for (let index = 0; index < BASE91.length; index += 1) {
    indexes[BASE91.charCodeAt(index)] = index;
  }

  return indexes;
}

function parseHeaderBytes(value: string, maximum: number): number {
  if (!/^(?:0|[1-9]\d*)$/.test(value)) {
    throw new Error("dia2 header byte length is not canonical");
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error("dia2 header byte length exceeds the decoder limit");
  }

  return parsed;
}

function parsePackedBytes(value: string, headerBytes: number): number {
  if (!/^[1-9]\d*$/.test(value)) {
    throw new Error("dia2 packed header byte length is not canonical");
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > headerBytes * 2 + 1024) {
    throw new Error("dia2 packed header byte length exceeds the decoder limit");
  }

  return parsed;
}
