#!/usr/bin/env bun

import type {
  ConformanceVector,
  ConformanceVectorSet,
  DecodeResult,
} from "./types.ts";

type CommandArgs = {
  vectors?: string;
  encode: string[];
  decode: string[];
};

type CommandRun = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

type VectorResult = {
  id: string;
  hbs?: string;
  decoded?: DecodeResult;
  encodeError?: string;
  decodeError?: string;
};

const defaultVectorSetUrl = new URL("./vectors.json", import.meta.url);

async function main(): Promise<number> {
  const [command, ...args] = Bun.argv.slice(2);

  if (command === undefined || command === "help" || command === "--help") {
    printUsage();
    return command === undefined ? 1 : 0;
  }

  if (command === "print-vectors") {
    console.log(await Bun.file(parseVectorPath(args)).text());
    return 0;
  }

  if (command === "check-commands") {
    const parsed = parseCommandArgs(args);
    const vectorSet = await readVectorSet(parsed.vectors);
    return printValidation(await checkCommands(vectorSet, parsed));
  }

  throw new Error(`unknown command: ${command}`);
}

function parseVectorPath(args: string[]): string | URL {
  if (args.length === 0) {
    return defaultVectorSetUrl;
  }

  if (args.length === 2 && args[0] === "--vectors") {
    return args[1]!;
  }

  throw new Error("expected optional --vectors <path>");
}

function parseCommandArgs(args: string[]): CommandArgs {
  let vectors: string | undefined;
  let target: "encode" | "decode" | undefined;
  const encode: string[] = [];
  const decode: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;

    if (arg === "--vectors" && target === undefined) {
      vectors = args[index + 1];
      if (!vectors) {
        throw new Error("--vectors requires a path");
      }
      index += 1;
      continue;
    }

    if (arg === "--encode") {
      target = "encode";
      continue;
    }

    if (arg === "--decode") {
      target = "decode";
      continue;
    }

    if (target === "encode") {
      encode.push(arg);
      continue;
    }

    if (target === "decode") {
      decode.push(arg);
      continue;
    }

    throw new Error(`unexpected check-commands argument: ${arg}`);
  }

  if (encode.length === 0) {
    throw new Error("check-commands requires --encode <command>");
  }

  if (decode.length === 0) {
    throw new Error("check-commands requires --decode <command>");
  }

  return vectors === undefined
    ? { encode, decode }
    : { vectors, encode, decode };
}

async function readVectorSet(
  path: string | URL = defaultVectorSetUrl,
): Promise<ConformanceVectorSet> {
  return (await Bun.file(path).json()) as ConformanceVectorSet;
}

function allVectors(vectorSet: ConformanceVectorSet): ConformanceVector[] {
  return [...vectorSet.vectors, ...vectorSet.rejects];
}

async function checkCommands(
  vectorSet: ConformanceVectorSet,
  commands: CommandArgs,
): Promise<string[]> {
  const errors: string[] = [];

  for (const vector of allVectors(vectorSet)) {
    compareVector(vector, await runVector(vector, commands), errors);
  }

  return errors;
}

async function runVector(
  vector: ConformanceVector,
  commands: CommandArgs,
): Promise<VectorResult> {
  if (vector.kind === "roundtrip") {
    const encoded = await runJsonCommand(commands.encode, {
      id: vector.id,
      options: vector.options,
      input: vector.input,
    });
    const decoded = await runJsonCommand(commands.decode, {
      id: vector.id,
      options: vector.options,
      hbs: vector.hbs,
    });
    const decodedResult = parseDecodeCommandResult(decoded);

    const result: VectorResult = {
      id: vector.id,
      ...decodedResult,
    };

    if (encoded.exitCode === 0) {
      result.hbs = encoded.stdout.trim();
    } else {
      result.encodeError = commandError(encoded);
    }

    return result;
  }

  if (vector.kind === "encode") {
    const encoded = await runJsonCommand(commands.encode, {
      id: vector.id,
      options: vector.options,
      input: vector.input,
    });

    const result: VectorResult = { id: vector.id };

    if (encoded.exitCode === 0) {
      result.hbs = encoded.stdout.trim();
    } else {
      result.encodeError = commandError(encoded);
    }

    return result;
  }

  if (vector.kind === "decode") {
    const decoded = await runJsonCommand(commands.decode, {
      id: vector.id,
      options: vector.options,
      hbs: vector.hbs,
    });
    const decodedResult = parseDecodeCommandResult(decoded);

    return {
      id: vector.id,
      ...decodedResult,
    };
  }

  if (vector.kind === "reject-encode") {
    const encoded = await runJsonCommand(commands.encode, {
      id: vector.id,
      options: vector.options,
      input: vector.input,
    });

    return {
      id: vector.id,
      encodeError: encoded.exitCode === 0 ? "" : commandError(encoded),
    };
  }

  const decoded = await runJsonCommand(commands.decode, {
    id: vector.id,
    options: vector.options,
    hbs: vector.hbs,
  });

  return {
    id: vector.id,
    decodeError: decoded.exitCode === 0 ? "" : commandError(decoded),
  };
}

async function runJsonCommand(
  command: string[],
  input: Record<string, unknown>,
): Promise<CommandRun> {
  const proc = Bun.spawn(command, {
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });

  proc.stdin.write(JSON.stringify(input));
  proc.stdin.end();

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  return { exitCode, stdout, stderr };
}

function compareVector(
  vector: ConformanceVector,
  result: VectorResult,
  errors: string[],
): void {
  if (vector.kind === "roundtrip") {
    comparePositiveCommandErrors(vector.id, result, errors);
    if (result.encodeError !== undefined || result.decodeError !== undefined) {
      return;
    }
    if (result.hbs !== vector.hbs) {
      errors.push(`${vector.id}: encoded HBS mismatch`);
    }
    compareDecode(vector.id, result.decoded, vector.expectedDecode, errors);
    return;
  }

  if (vector.kind === "encode") {
    if (result.encodeError !== undefined) {
      errors.push(`${vector.id}: encode command failed: ${result.encodeError}`);
      return;
    }
    if (result.hbs !== vector.hbs) {
      errors.push(`${vector.id}: encoded HBS mismatch`);
    }
    return;
  }

  if (vector.kind === "decode") {
    if (result.decodeError !== undefined) {
      errors.push(`${vector.id}: decode command failed: ${result.decodeError}`);
      return;
    }
    compareDecode(vector.id, result.decoded, vector.expectedDecode, errors);
    return;
  }

  if (vector.kind === "reject-encode") {
    compareError(
      vector.id,
      result.encodeError,
      vector.expectedError,
      "encode",
      errors,
    );
    return;
  }

  if (vector.kind === "reject-decode") {
    compareError(
      vector.id,
      result.decodeError,
      vector.expectedError,
      "decode",
      errors,
    );
  }
}

function parseDecodeCommandResult(run: CommandRun): {
  decoded?: DecodeResult;
  decodeError?: string;
} {
  if (run.exitCode !== 0) {
    return { decodeError: commandError(run) };
  }

  try {
    return { decoded: JSON.parse(run.stdout) as DecodeResult };
  } catch (error) {
    return {
      decodeError: `decode stdout is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }
}

function comparePositiveCommandErrors(
  id: string,
  result: VectorResult,
  errors: string[],
): void {
  if (result.encodeError !== undefined) {
    errors.push(`${id}: encode command failed: ${result.encodeError}`);
  }
  if (result.decodeError !== undefined) {
    errors.push(`${id}: decode command failed: ${result.decodeError}`);
  }
}

function compareDecode(
  id: string,
  actual: DecodeResult | undefined,
  expected: DecodeResult,
  errors: string[],
): void {
  if (actual === undefined) {
    errors.push(`${id}: missing decoded result`);
    return;
  }

  if (stableJson(actual) !== stableJson(expected)) {
    errors.push(`${id}: decoded result mismatch`);
  }
}

function compareError(
  id: string,
  actual: string | undefined,
  expected: string,
  action: "encode" | "decode",
  errors: string[],
): void {
  if (!actual) {
    errors.push(`${id}: expected ${action} failure`);
    return;
  }

  if (!actual.toLowerCase().includes(expected.toLowerCase())) {
    errors.push(
      `${id}: ${action} error does not include ${JSON.stringify(expected)}`,
    );
  }
}

function commandError(run: CommandRun): string {
  return (
    run.stderr.trim() ||
    run.stdout.trim() ||
    `implementation command exited with ${run.exitCode}`
  );
}

function printValidation(errors: string[]): number {
  if (errors.length === 0) {
    console.log("pass: HBS3 conformance commands match all vectors");
    return 0;
  }

  for (const error of errors) {
    console.error(`fail: ${error}`);
  }

  return 1;
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortJson(item));
  }

  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item !== undefined) {
        out[key] = sortJson(item);
      }
    }
    return out;
  }

  return value;
}

function printUsage(): void {
  console.log(`Usage:
  bun packages/hbs-conformance/src/cli.ts print-vectors [--vectors path]
  bun packages/hbs-conformance/src/cli.ts check-commands [--vectors path] --encode <cmd...> --decode <cmd...>

External command contract:
  encode stdin: {"id": "...", "options": {...}, "input": ...}
  encode stdout: HBS3 text
  decode stdin: {"id": "...", "options": {...}, "hbs": "..."}
  decode stdout: DecodeResult JSON
  expected failures should exit non-zero and write an error message to stderr/stdout
`);
}

try {
  process.exitCode = await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
