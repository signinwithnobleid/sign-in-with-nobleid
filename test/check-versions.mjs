#!/usr/bin/env node
// The registry packages (npm, PyPI, crates.io) share one version. This
// checks that they agree, and with an argument (a release tag such as
// v0.1.0) that they match it. CI runs it on every push; the publish
// workflow runs it before anything is uploaded.
//
//   node test/check-versions.mjs          # all the same?
//   node test/check-versions.mjs v0.1.0   # all equal to 0.1.0?

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");
const field = (p, re) => {
  const m = read(p).match(re);
  if (!m) throw new Error(`no version found in ${p}`);
  return m[1];
};

const found = {
  "packages/node/package.json": JSON.parse(read("packages/node/package.json")).version,
  "packages/python/pyproject.toml": field("packages/python/pyproject.toml", /^version\s*=\s*"([^"]+)"/m),
  "packages/python/src/nobleid_signin/__init__.py": field("packages/python/src/nobleid_signin/__init__.py", /^__version__\s*=\s*"([^"]+)"/m),
  "packages/rust/Cargo.toml": field("packages/rust/Cargo.toml", /^version\s*=\s*"([^"]+)"/m),
  "packages/rust/Cargo.lock": field("packages/rust/Cargo.lock", /name = "nobleid-signin"\nversion = "([^"]+)"/),
  "package-lock.json": JSON.parse(read("package-lock.json")).packages["packages/node"].version,
};

const tag = process.argv[2];
const want = tag ? tag.replace(/^v/, "") : found["packages/node/package.json"];
if (tag && !/^v\d+\.\d+\.\d+$/.test(tag)) {
  console.error(`release tag must look like v1.2.3, got ${JSON.stringify(tag)}`);
  process.exit(1);
}
const wrong = Object.entries(found).filter(([, v]) => v !== want);
for (const [file, v] of Object.entries(found)) console.log(`${v === want ? "ok " : "BAD"} ${v.padEnd(10)} ${file}`);
if (wrong.length) {
  console.error(`expected every package at ${want}${tag ? ` (tag ${tag})` : ""}`);
  process.exit(1);
}
