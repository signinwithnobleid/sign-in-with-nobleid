/**
 * The button set: the files in brand/buttons/ are current, complete and
 * accessible, and the browser SDK draws the same set with the same names.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { LABELS, MARK, SHAPES, SIZES, THEMES, everyButton, padding, radius, contrast } from "../scripts/button-spec.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIR = path.join(ROOT, "brand", "buttons");
const manifest = JSON.parse(fs.readFileSync(path.join(DIR, "manifest.json"), "utf8")).buttons;

test("brand/buttons is what scripts/build-buttons.mjs makes", () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, "scripts", "build-buttons.mjs"), "--check"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("every label in every theme, shape and size, named predictably", () => {
  const want = [...everyButton()];
  assert.equal(want.length, 3 * 5 * 3 * 3);
  const files = fs.readdirSync(DIR).filter((f) => f.endsWith(".svg")).sort();
  assert.deepEqual(files, want.map((b) => b.file).sort());
  for (const b of want) assert.match(b.file, /^nobleid-(sign-in|continue|icon)-(white|black|green|outline-white|outline-black)-(rounded|pill|square)-(sm|md|lg)\.svg$/);
  assert.ok(want.some((b) => b.label === "sign-in" && b.theme === "black" && b.shape === "pill"), "a black pill exists");
  assert.deepEqual(manifest.map((b) => b.file).sort(), files);
});

test("each file: right size, an accessible name, outlines only, nothing active", () => {
  for (const b of manifest) {
    const svg = fs.readFileSync(path.join(DIR, b.file), "utf8");
    const h = SIZES[b.size].h;
    assert.equal(b.height, h, b.file);
    assert.ok(h >= 40, b.file);
    if (b.label === "icon") assert.equal(b.width, h, b.file);
    assert.ok(svg.startsWith(`<svg xmlns="http://www.w3.org/2000/svg" width="${b.width}" height="${h}" viewBox="0 0 ${b.width} ${h}" role="img" aria-label="${LABELS[b.label]}"><title>${LABELS[b.label]}</title>`), b.file);
    assert.doesNotMatch(svg, /<(script|text|image|use|foreignObject|style)\b|href=|on\w+=/i, b.file);
    const r = radius(b.shape, h);
    if (r) assert.ok(svg.includes(` rx="${String(r - 0.5).replace(/\.0$/, "")}"`), `${b.file} radius`);
    else assert.doesNotMatch(svg, / rx="/, b.file);
    const t = THEMES[b.theme];
    assert.ok(svg.includes(`fill="${t.bg || "none"}" stroke="${t.border}"`), `${b.file} colours`);
    assert.ok(svg.includes(`fill="${MARK[t.mark]}"><path transform`), `${b.file} mark colour`);
  }
});

test("text meets WCAG AA (4.5:1) and the mark 3:1 on every solid theme", () => {
  for (const [name, t] of Object.entries(THEMES)) {
    if (!t.bg) continue; // outline themes: the integrator's surface decides; docs/brand.md says how to check
    assert.ok(contrast(t.text, t.bg) >= 4.5, `${name} text ${contrast(t.text, t.bg).toFixed(2)}`);
    assert.ok(contrast(MARK[t.mark], t.bg) >= 3, `${name} mark ${contrast(MARK[t.mark], t.bg).toFixed(2)}`);
  }
  // Why green is #00734D and not the mark's #009966.
  assert.ok(contrast("#FFFFFF", "#009966") < 4.5);
});

test("the white mark is the master with only its colour changed", () => {
  const green = fs.readFileSync(path.join(ROOT, "brand", "nobleid-mark.svg"), "utf8");
  const white = fs.readFileSync(path.join(ROOT, "brand", "nobleid-mark-white.svg"), "utf8");
  assert.equal(white, green.replace('fill="#009966"', 'fill="#FFFFFF"'));
});

/* The SDK draws the same set: load it with a tiny DOM and compare to the spec. */
function sdk() {
  const el = (tag) => ({
    tagName: tag,
    attrs: {},
    children: [],
    style: { cssText: "" },
    text: "",
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    appendChild(c) { this.children.push(c); return c; },
    addEventListener() {},
    set textContent(v) { this.text = String(v); },
    get textContent() { return this.text + this.children.map((c) => c.textContent || "").join(""); },
  });
  const window = { document: { readyState: "complete", createElement: el, querySelectorAll: () => [], addEventListener() {} }, console };
  window.window = window;
  vm.runInContext(fs.readFileSync(path.join(ROOT, "sdk", "nobleid-auth.js"), "utf8"), vm.createContext(window));
  return window.NobleID;
}

test("SDK: theme, shape, size and label take the file names and draw the same button", () => {
  const NobleID = sdk();
  for (const b of everyButton()) {
    const btn = NobleID.createButton({ loginUrl: "/login", theme: b.theme, shape: b.shape, size: b.size, label: b.label });
    const css = btn.style.cssText;
    const s = SIZES[b.size];
    const t = THEMES[b.theme];
    const where = b.file;
    assert.match(css, new RegExp(`height:${s.h}px`), where);
    assert.match(css, new RegExp(`border-radius:${radius(b.shape, s.h)}px`), where);
    assert.ok(css.includes(`background:${t.bg || "transparent"}`), where);
    assert.ok(css.includes(`border:1px solid ${t.border}`), where);
    assert.ok(css.includes(`color:${t.text}`), where);
    assert.ok(css.includes(`font:600 ${s.font}px/1`), where);
    assert.match(css, /outline-offset:2px/, where);
    const mark = btn.children[0];
    assert.equal(mark.getAttribute("src"), `https://www.nobleid.org/brand/nobleid-mark${t.mark === "white" ? "-white" : ""}.svg`, where);
    assert.equal(mark.getAttribute("width"), String(s.mark), where);
    assert.equal(btn.getAttribute("aria-label"), LABELS[b.label], where);
    if (b.label === "icon") {
      assert.equal(btn.children.length, 1, where);
      assert.match(css, new RegExp(`width:${s.h}px`), where);
    } else {
      const [l, r] = padding(b.shape, b.size);
      assert.ok(css.includes(`padding:0 ${r}px 0 ${l}px`), where);
      assert.ok(css.includes(`gap:${s.gap}px`), where);
      assert.equal(btn.textContent, LABELS[b.label], where);
    }
  }
});

test("SDK: 2.1 option values still work; unknown values fall back", () => {
  const NobleID = sdk();
  const legacy = NobleID.createButton({ loginUrl: "/login", theme: "dark", label: "Continue with NobleID" });
  assert.ok(legacy.style.cssText.includes(`background:${THEMES.black.bg}`));
  assert.equal(legacy.textContent, "Continue with NobleID");
  assert.ok(NobleID.createButton({ loginUrl: "/login", theme: "light" }).style.cssText.includes("background:#FFFFFF"));
  const odd = NobleID.createButton({ loginUrl: "/login", theme: "constructor", shape: "__proto__", size: "xl", label: "Log in" });
  assert.ok(odd.style.cssText.includes("background:#FFFFFF"));
  assert.match(odd.style.cssText, /border-radius:8px/);
  assert.match(odd.style.cssText, /height:44px/);
  assert.equal(odd.textContent, "Sign in with NobleID");
  assert.deepEqual(Object.keys(SHAPES), ["rounded", "pill", "square"]);
});
