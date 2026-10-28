/**
 * profileFromClaims (packages/node) against the shared cases in
 * test/profile-vectors.json, which every helper's tests also read.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { profileFromClaims, NobleIdError } from "../packages/node/index.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { cases } = JSON.parse(fs.readFileSync(path.join(ROOT, "test/profile-vectors.json"), "utf8"));

const camel = (k) => k.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
function camelize(v) {
  if (Array.isArray(v)) return v.map(camelize);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [camel(k), camelize(x)]));
  return v;
}

for (const c of cases) {
  test(`profileFromClaims: ${c.name}`, () => {
    if (c.error) {
      assert.throws(() => profileFromClaims(c.id_token, c.userinfo), (e) => e instanceof NobleIdError && e.code === c.error);
      return;
    }
    assert.deepEqual(profileFromClaims(c.id_token, c.userinfo), camelize(c.profile));
  });
}

test("profileFromClaims: the inputs are not changed", () => {
  const c = cases[0];
  const before = JSON.stringify([c.id_token, c.userinfo]);
  profileFromClaims(c.id_token, c.userinfo);
  assert.equal(JSON.stringify([c.id_token, c.userinfo]), before);
});

test("profileFromClaims: end to end with the Node helper and the mock provider", async () => {
  const { createMock } = await import("../mock-oidc/server.mjs");
  const { createNobleIdClient } = await import("../packages/node/index.mjs");
  const clients = JSON.parse(fs.readFileSync(path.join(ROOT, "test/clients.json"), "utf8")).clients;
  const conf = clients.find((x) => x.type === "confidential");
  const mock = createMock({ clients });
  await mock.listen(0);
  try {
    const nobleid = await createNobleIdClient({
      clientId: conf.client_id,
      clientSecret: conf.client_secret,
      issuer: mock.issuer,
      allowInsecureLocalhost: true,
    });
    const { url, transaction } = await nobleid.startSignIn({
      redirectUri: "http://localhost/callback",
      scope: "openid profile email orcid affiliations",
    });
    const r = await fetch(url, { redirect: "manual" });
    const callback = new URL(r.headers.get("location"));
    const { tokens, claims } = await nobleid.finishSignIn(callback, transaction);
    const userinfo = await nobleid.userinfo(tokens.access_token, claims.sub);

    const fromIdToken = profileFromClaims(claims);
    assert.deepEqual(fromIdToken.affiliations, [], "the list is userinfo only");
    assert.deepEqual(fromIdToken.researchInterests, []);

    const p = profileFromClaims(claims, userinfo);
    assert.equal(p.sub, claims.sub);
    assert.equal(p.name, "Ada Example");
    assert.equal(p.orcid, "https://orcid.org/0000-0002-1825-0097");
    assert.equal(p.emailVerified, true);
    assert.deepEqual(p.affiliation, { name: "Example University", ror: null });
    assert.deepEqual(p.affiliations, [{ organization: "Example University", role: "Researcher", startYear: 2021, ror: null }]);
    assert.deepEqual(p.researchInterests, ["Bibliometrics", "Open science"]);
  } finally {
    await mock.close();
  }
});
