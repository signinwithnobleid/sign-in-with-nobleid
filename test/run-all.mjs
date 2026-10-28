#!/usr/bin/env node
/**
 * npm test: the mock's conformance tests, the SDK tests, the html-sdk and
 * WordPress tests, then every server example whose toolchain is installed.
 * Missing toolchains are reported as SKIPPED, never as passed.
 *
 *   node test/run-all.mjs [--no-setup] [--only <example>,<example>]
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EXAMPLES, runExample } from "./run-example.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const setup = !args.includes("--no-setup");
const onlyIdx = args.indexOf("--only");
const only = onlyIdx >= 0 ? args[onlyIdx + 1].split(",") : null;

const summary = [];
let failed = 0;

const suites = ["test/mock.test.mjs", "test/sdk.test.mjs", "test/html-sdk.test.mjs", "test/wordpress.test.mjs", "test/profile.test.mjs"];
const unit = spawnSync(process.execPath, ["--test", "--test-reporter=spec", ...suites], { cwd: ROOT, stdio: "inherit" });
summary.push(`node test suites (${suites.length} files): ${unit.status === 0 ? "passed" : "FAILED"}`);
if (unit.status !== 0) failed++;

for (const ex of EXAMPLES) {
  if (only && !only.includes(ex.name)) continue;
  const r = await runExample(ex, { setup });
  if (r.skipped) {
    summary.push(`${ex.name}: SKIPPED (${r.reason})`);
    continue;
  }
  const pass = r.results.filter((x) => x.ok).length;
  const fail = r.results.length - pass;
  failed += fail;
  summary.push(`${ex.name}: ${pass} passed, ${fail} failed`);
}

console.log("\n== summary ==\n" + summary.join("\n"));
process.exit(failed ? 1 : 0);
