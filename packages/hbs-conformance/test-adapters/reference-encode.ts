#!/usr/bin/env bun

import { encodeHbs } from "@tunnckocore/hbs";
import type { HbsOptions } from "../src/types.ts";

const input = (await new Response(Bun.stdin.stream()).json()) as {
  options: HbsOptions;
  input: unknown;
};

console.log(encodeHbs(input.input, input.options));
