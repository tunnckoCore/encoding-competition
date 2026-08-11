#!/usr/bin/env bun

import { decodeHbs } from "@tunnckocore/hbs";
import type { HbsOptions } from "../src/types.ts";

const input = (await new Response(Bun.stdin.stream()).json()) as {
  options: HbsOptions;
  hbs: string;
};

console.log(JSON.stringify(decodeHbs(input.hbs, input.options)));
