#!/usr/bin/env node
/**
 * Run one (or every) server example end to end against the local mock.
 *
 *   node test/run-example.mjs <name> [--no-setup]
 *   node test/run-example.mjs --all [--no-setup]
 *
 * For each example with an examples/<name>/e2e.json this starts the mock
 * in-process, runs the example's setup commands, starts the example on a free
 * port with ISSUER / CLIENT_ID / CLIENT_SECRET / REDIRECT_URI / PORT in its
 * environment, runs the shared scenarios (test/e2e/driver.mjs), and stops the
 * example. Only processes started here are stopped.
 */
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createMock } from "../mock-oidc/server.mjs";
import { runScenarios } from "./e2e/driver.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLIENTS = JSON.parse(fs.readFileSync(path.join(ROOT, "test/clients.json"), "utf8")).clients;
// Each server example declares how to build and start it in examples/<name>/e2e.json.
export const EXAMPLES = fs
  .readdirSync(path.join(ROOT, "examples"))
  .filter((d) => fs.existsSync(path.join(ROOT, "examples", d, "e2e.json")))
  .sort()
  .map((d) => ({ name: d, cwd: path.join("examples", d), ...JSON.parse(fs.readFileSync(path.join(ROOT, "examples", d, "e2e.json"), "utf8")) }));

const freePort = () =>
  new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

const has = (cmd) => spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;

async function waitForHttp(url, timeoutMs, child) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (child.exitCode !== null) throw new Error(`example exited early with code ${child.exitCode}`);
    try {
      await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(2000) });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error(`example did not answer on ${url} within ${timeoutMs / 1000}s`);
}

function stop(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode) return resolve();
    const t = setTimeout(() => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    }, 5000);
    child.on("exit", () => {
      clearTimeout(t);
      resolve();
    });
    try {
      process.kill(-child.pid, "SIGTERM"); // the example's own process group, created below
    } catch {
      resolve();
    }
  });
}

export async function runExample(ex, { setup = true, log = console.log } = {}) {
  const missing = (ex.requires || []).filter((c) => !has(c));
  if (missing.length) {
    log(`# SKIP ${ex.name}: toolchain not found (${missing.join(", ")}) — not run`);
    return { name: ex.name, skipped: true, reason: "missing " + missing.join(", "), results: [] };
  }
  const cwd = path.join(ROOT, ex.cwd);
  const client = CLIENTS.find((c) => c.type === (ex.client || "confidential"));
  const mock = createMock({ clients: CLIENTS });
  const mockPort = await mock.listen(0);
  const port = ex.port || (await freePort());
  const appUrl = `http://localhost:${port}`;
  const vars = { PORT: String(port), ISSUER: mock.issuer, APP_URL: appUrl, ROOT };
  const sub = (s) => String(s).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");
  const env = {
    ...process.env,
    ISSUER: mock.issuer,
    CLIENT_ID: client.client_id,
    CLIENT_SECRET: client.client_secret || "",
    REDIRECT_URI: appUrl + (ex.callbackPath || "/callback"),
    PORT: String(port),
    APP_URL: appUrl,
    ...Object.fromEntries(Object.entries(ex.env || {}).map(([k, v]) => [k, sub(v)])),
  };
  log(`# ${ex.name}: mock ${mock.issuer}, app ${appUrl}`);

  let child;
  try {
    if (setup) {
      for (const cmd of ex.setup || []) {
        log(`# setup: ${cmd}`);
        const r = spawnSync("sh", ["-c", sub(cmd)], { cwd, env, stdio: ["ignore", "inherit", "inherit"] });
        if (r.status !== 0) throw new Error(`setup failed: ${cmd}`);
      }
    }
    const logFile = path.join(ROOT, "test", ".logs", ex.name + ".log");
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    const out = fs.openSync(logFile, "w");
    child = spawn(sub(ex.start[0]), ex.start.slice(1).map(sub), { cwd, env, stdio: ["ignore", out, out], detached: true });
    await waitForHttp(appUrl + (ex.readyPath || "/"), (ex.readyTimeout || 60) * 1000, child);
    const results = await runScenarios({ appUrl, mockUrl: `http://localhost:${mockPort}`, clientId: client.client_id, profile: ex.profile, log });
    return { name: ex.name, results, logFile };
  } catch (e) {
    log(`not ok - ${ex.name}: ${e.message}`);
    return { name: ex.name, results: [{ name: "start", ok: false, error: e.message }] };
  } finally {
    if (child) await stop(child);
    await mock.close();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const args = process.argv.slice(2);
  const setup = !args.includes("--no-setup");
  const names = args.filter((a) => !a.startsWith("--"));
  const list = args.includes("--all") ? EXAMPLES : EXAMPLES.filter((e) => names.includes(e.name));
  if (!list.length) {
    console.error("usage: node test/run-example.mjs <name>|--all [--no-setup]\nknown: " + EXAMPLES.map((e) => e.name).join(", "));
    process.exit(2);
  }
  let failed = 0;
  const summary = [];
  for (const ex of list) {
    const r = await runExample(ex, { setup });
    const pass = r.results.filter((x) => x.ok).length;
    const fail = r.results.length - pass;
    failed += fail;
    summary.push(r.skipped ? `${ex.name}: SKIPPED (${r.reason})` : `${ex.name}: ${pass} passed, ${fail} failed`);
    if (fail && r.logFile) console.log(`# app log: ${path.relative(ROOT, r.logFile)}`);
  }
  console.log("\n" + summary.join("\n"));
  process.exit(failed ? 1 : 0);
}
