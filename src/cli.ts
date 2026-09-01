#!/usr/bin/env node
/**
 * The bin. All logic lives in `./cli/run.ts`; this file is the one place the
 * CLI reads `process`, and it reads only globals, so the built output still
 * runs on any runtime with a Node-compatible `process` (Node, Bun, Deno).
 */

import { runCli } from "./cli/run.ts";

void runCli(process.argv.slice(2), {
  write: (text) => void process.stdout.write(text),
  writeError: (text) => void process.stderr.write(text),
  columns: process.stdout.columns,
  color:
    process.env["NO_COLOR"] === undefined &&
    process.env["TERM"] !== "dumb" &&
    process.stdout.isTTY === true,
}).then((code) => {
  if (code !== 0) process.exitCode = code;
});
