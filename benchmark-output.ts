import { mkdir } from "node:fs/promises";

const resultsDirectory = new URL("./benchmark-results/", import.meta.url);

export const writeBenchmarkResults = async <Result>(
  fileName: string,
  result: Result,
): Promise<void> => {
  await mkdir(resultsDirectory, { recursive: true });
  const output = `${JSON.stringify(result, undefined, 2)}\n`;
  await Bun.write(new URL(fileName, resultsDirectory), output);
};
