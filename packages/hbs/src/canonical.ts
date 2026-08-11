export function canonicalizeString(input: string): string {
  let output = '"';

  for (let index = 0; index < input.length; index += 1) {
    const charCode = input.charCodeAt(index);

    if (charCode === 0x22) {
      output += '\\"';
    } else if (charCode === 0x5c) {
      output += "\\\\";
    } else if (charCode === 0x08) {
      output += "\\b";
    } else if (charCode === 0x09) {
      output += "\\t";
    } else if (charCode === 0x0a) {
      output += "\\n";
    } else if (charCode === 0x0c) {
      output += "\\f";
    } else if (charCode === 0x0d) {
      output += "\\r";
    } else if (charCode < 0x20) {
      output += `\\u${charCode.toString(16).padStart(4, "0")}`;
    } else if (charCode >= 0xd800 && charCode <= 0xdbff) {
      const nextCharCode = input.charCodeAt(index + 1);

      if (nextCharCode >= 0xdc00 && nextCharCode <= 0xdfff) {
        output += input.charAt(index) + input.charAt(index + 1);
        index += 1;
      } else {
        output += `\\u${charCode.toString(16).padStart(4, "0")}`;
      }
    } else if (charCode >= 0xdc00 && charCode <= 0xdfff) {
      output += `\\u${charCode.toString(16).padStart(4, "0")}`;
    } else {
      output += input[index];
    }
  }

  return `${output}"`;
}

export function canonicalizeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new Error(
      `Non-finite number (${value}) is not representable in canonical JSON`,
    );
  }

  if (value === 0) {
    return "0";
  }

  return value.toString();
}

export function sortObjectKeys(object: Record<string, unknown>): string[] {
  return Object.keys(object).sort();
}
