/**
 * NobleID Sign-In SDK v2.1.1
 * https://www.nobleid.org/developers/sign-in
 * Licensed under the Apache License, Version 2.0.
 *
 * "Sign in with NobleID" for any website: OpenID Connect, authorization code
 * flow with PKCE (S256). Dependency-free; ES5 syntax; needs a browser with
 * fetch, Promise, URLSearchParams and Web Crypto (any current browser).
 *
 * Two ways to use it:
 *
 * 1. Your server does the sign-in (confidential client; recommended whenever
 *    you have a backend). The button is only a link to your own route, which
 *    builds the authorize URL and exchanges the code with your client secret:
 *
 *      <div data-nobleid-login-url="/auth/nobleid/start"></div>
 *      <script src="https://www.nobleid.org/sdk/nobleid-auth.js" async></script>
 *
 * 2. Browser-only app (public client, no secret). The SDK runs the whole flow:
 *
 *      NobleID.renderButton("signin", {
 *        clientId: "nbcl_your_client_id",
 *        redirectUri: "https://app.example/callback",
 *        scope: "openid profile",
 *        theme: "light",                 // "light" | "dark"
 *        size: "md",                     // "sm" | "md" | "lg"  (min height 40px)
 *        label: "Sign in with NobleID",  // or "Continue with NobleID"
 *      });
 *
 *      // on https://app.example/callback
 *      NobleID.handleCallback({ clientId: "nbcl_your_client_id", redirectUri: "https://app.example/callback" })
 *        .then(function (r) { console.log(r.claims.nobleid, r.claims.name); });
 *
 * handleCallback checks, in this order: a sign-in was started in this tab,
 * `state` matches, the `iss` response parameter is NobleID (RFC 9207); only
 * then does it surface an `error`. It then exchanges the code (PKCE, no
 * secret), checks the ID token's iss / aud / nonce / exp, and reads the
 * claims from the userinfo endpoint. It does not verify the ID token
 * signature itself: the token came straight from NobleID's token endpoint
 * over TLS, which OpenID Connect Core §3.1.3.7 accepts for the code flow. If
 * you send the ID token to your own server, verify it there (ES256, keys at
 * NobleID.endpoints.jwks).
 *
 * Tokens live in memory only; the SDK never writes them to storage, URLs or
 * logs. A browser-only app cannot keep a token secret from scripts running on
 * its own page: if you have a server, prefer mode 1 (a backend-for-frontend).
 *
 * Source of truth: sign-in-with-nobleid/sdk/nobleid-auth.js. The copy served
 * at www.nobleid.org/sdk/ is byte-identical; edit the kit, then copy it over.
 */
(function (global) {
  "use strict";

  var DEFAULT_ISSUER = "https://id.nobleid.org";
  var DEFAULT_AUTHORIZE_URL = "https://www.nobleid.org/oauth/authorize";
  var MARK_URL = "https://www.nobleid.org/brand/nobleid-mark.svg";
  var STORAGE_KEY = "nobleid_oauth";
  var MAX_FLOW_AGE_MS = 10 * 60 * 1000;
  var CLOCK_SKEW_S = 60;
  var VERSION = "2.1.1";

  var LABELS = ["Sign in with NobleID", "Continue with NobleID"];

  var cfg = {};
  setEndpoints(DEFAULT_ISSUER, DEFAULT_AUTHORIZE_URL);

  function setEndpoints(issuer, authorizeUrl) {
    cfg.issuer = issuer;
    cfg.authorize = authorizeUrl;
    cfg.token = issuer + "/oauth/token";
    cfg.userinfo = issuer + "/oauth/userinfo";
    cfg.revoke = issuer + "/oauth/revoke";
    cfg.jwks = issuer + "/.well-known/jwks.json";
  }

  /* ───────────── encoding / crypto ───────────── */

  function base64UrlEncode(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlDecodeToString(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = atob(b64);
    try {
      // UTF-8 decode (names are not ASCII-only)
      return decodeURIComponent(
        Array.prototype.map
          .call(bin, function (c) {
            return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
          })
          .join("")
      );
    } catch (e) {
      return bin;
    }
  }

  /**
   * 32 random bytes as a 43-character base64url string (RFC 7636 §4.1).
   * @returns {string}
   */
  function randomString() {
    var bytes = new Uint8Array(32);
    global.crypto.getRandomValues(bytes);
    return base64UrlEncode(bytes);
  }

  /**
   * PKCE S256 code challenge for a verifier.
   * @param {string} verifier
   * @returns {Promise<string>}
   */
  function codeChallengeS256(verifier) {
    return global.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)).then(function (d) {
      return base64UrlEncode(new Uint8Array(d));
    });
  }

  /**
   * Decode a JWT payload WITHOUT verifying it. Only for a token received
   * directly from the token endpoint over TLS.
   * @param {string} jwt
   * @returns {object|null}
   */
  function decodeJwtPayload(jwt) {
    var parts = String(jwt || "").split(".");
    if (parts.length !== 3) return null;
    try {
      var v = JSON.parse(base64UrlDecodeToString(parts[1]));
      return v && typeof v === "object" ? v : null;
    } catch (e) {
      return null;
    }
  }

  /** Compare two strings without an early exit on the first differing character. */
  function constantTimeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || !a.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function requireCrypto() {
    if (!global.crypto || !global.crypto.subtle || !global.crypto.getRandomValues) {
      throw new Error("[NobleID] Web Crypto is unavailable. Serve your page over https (or http://localhost).");
    }
  }

  function fail(code, description) {
    var e = new Error("[NobleID] " + code + (description ? ": " + description : ""));
    e.code = code;
    e.description = description || "";
    return e;
  }

  function isLocalHttp(url) {
    return /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(url);
  }

  /* ───────────── configuration ───────────── */

  /**
   * Point the SDK at another provider origin. For testing against a local
   * mock or a staging provider only; production needs no configuration.
   * The issuer must be https (http is allowed for localhost only).
   *
   * @param {{issuer?: string, authorizationEndpoint?: string}} opts
   * @returns {object} the current endpoints
   */
  function configure(opts) {
    opts = opts || {};
    var issuer = String(opts.issuer || DEFAULT_ISSUER).replace(/\/+$/, "");
    var authorize = String(opts.authorizationEndpoint || (opts.issuer ? issuer + "/oauth/authorize" : DEFAULT_AUTHORIZE_URL));
    var ok = function (u) {
      return /^https:\/\/[^\s/?#@]+(\/[^\s]*)?$/i.test(u) || isLocalHttp(u);
    };
    if (!ok(issuer) || !ok(authorize)) throw fail("invalid_request", "issuer and authorizationEndpoint must be https URLs (http only for localhost)");
    setEndpoints(issuer, authorize);
    syncPublicEndpoints();
    return api.endpoints;
  }

  /* ───────────── flow state (sessionStorage, single use) ───────────── */

  function saveFlow(flow) {
    global.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(flow));
  }

  function takeFlow() {
    var raw = null;
    try {
      raw = global.sessionStorage.getItem(STORAGE_KEY);
      global.sessionStorage.removeItem(STORAGE_KEY);
    } catch (e) {}
    if (!raw) return null;
    try {
      var f = JSON.parse(raw);
      return f && typeof f === "object" ? f : null;
    } catch (e) {
      return null;
    }
  }

  /* ───────────── authorize ───────────── */

  /**
   * Build the authorize URL for a PUBLIC client and remember state, nonce and
   * the PKCE verifier (in sessionStorage, for this tab) for handleCallback.
   *
   * @param {{clientId: string, redirectUri: string, scope?: string, prompt?: string,
   *          loginHint?: string, maxAge?: number}} opts
   * @returns {Promise<string>} the URL to send the browser to
   */
  function createAuthorizeUrl(opts) {
    opts = opts || {};
    if (!opts.clientId) return Promise.reject(fail("invalid_request", "clientId is required"));
    if (!opts.redirectUri) return Promise.reject(fail("invalid_request", "redirectUri is required"));
    try {
      requireCrypto();
    } catch (e) {
      return Promise.reject(e);
    }

    var state = randomString();
    var nonce = randomString();
    var verifier = randomString();
    var scope = opts.scope || "openid profile";
    if ((" " + scope + " ").indexOf(" openid ") === -1) scope = "openid " + scope;

    return codeChallengeS256(verifier).then(function (challenge) {
      saveFlow({
        state: state,
        nonce: nonce,
        codeVerifier: verifier,
        clientId: opts.clientId,
        redirectUri: opts.redirectUri,
        issuer: cfg.issuer,
        createdAt: Date.now(),
      });
      var q = new URLSearchParams();
      q.set("response_type", "code");
      q.set("client_id", opts.clientId);
      q.set("redirect_uri", opts.redirectUri);
      q.set("scope", scope);
      q.set("state", state);
      q.set("nonce", nonce);
      q.set("code_challenge", challenge);
      q.set("code_challenge_method", "S256");
      if (opts.prompt) q.set("prompt", opts.prompt);
      if (opts.loginHint) q.set("login_hint", opts.loginHint);
      if (opts.maxAge != null) q.set("max_age", String(opts.maxAge));
      return cfg.authorize + "?" + q.toString();
    });
  }

  /**
   * createAuthorizeUrl, then navigate to it.
   * @param {object} opts see createAuthorizeUrl
   * @returns {Promise<void>}
   */
  function signIn(opts) {
    return createAuthorizeUrl(opts).then(function (url) {
      global.location.assign(url);
    });
  }

  /* ───────────── callback (public clients) ───────────── */

  function readJson(res) {
    return res.text().then(function (t) {
      if (!t) return {};
      try {
        var v = JSON.parse(t);
        return v && typeof v === "object" ? v : {};
      } catch (e) {
        return {};
      }
    });
  }

  function httpError(res, body) {
    var e = fail(typeof body.error === "string" ? body.error : "http_" + res.status, typeof body.error_description === "string" ? body.error_description : "");
    e.status = res.status;
    var ra = res.headers && res.headers.get ? res.headers.get("Retry-After") : null;
    if (ra) e.retryAfter = isNaN(Number(ra)) ? ra : Number(ra);
    return e;
  }

  function postForm(url, fields) {
    return global
      .fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body: new URLSearchParams(fields).toString(),
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
      })
      .then(function (res) {
        return readJson(res).then(function (body) {
          if (!res.ok) throw httpError(res, body);
          return body;
        });
      });
  }

  /**
   * Complete the sign-in on your redirect URI (public clients).
   *
   * Order of checks: a sign-in was started in this tab (single use), `state`
   * matches, `iss` is the issuer, then any `error` from NobleID is surfaced,
   * then the code is exchanged and the ID token's iss / aud / nonce / exp are
   * checked. Removes the code from the address bar.
   *
   * Error codes (err.code): invalid_state, invalid_issuer, the provider's own
   * code (e.g. access_denied, login_required), invalid_request, expired,
   * invalid_token, userinfo_failed, slow_down (err.retryAfter when sent).
   *
   * @param {{clientId?: string, redirectUri?: string, userinfo?: boolean, cleanUrl?: boolean}} [opts]
   * @returns {Promise<{tokens: object, claims: object, idTokenClaims: object, scope: string[]}>}
   */
  function handleCallback(opts) {
    opts = opts || {};
    var params = new URLSearchParams(global.location.search);
    var flow = takeFlow(); // single use: removed before anything else happens

    if (opts.cleanUrl !== false && global.history && global.history.replaceState) {
      try {
        global.history.replaceState(null, "", global.location.pathname);
      } catch (e) {}
    }

    return Promise.resolve().then(function () {
      if (!flow || typeof flow.state !== "string") throw fail("invalid_state", "no sign-in in progress in this browser tab");
      if (!constantTimeEqual(params.get("state") || "", flow.state)) {
        throw fail("invalid_state", "state does not match (possible forged callback)");
      }
      var issuer = cfg.issuer;
      if (params.get("iss") !== issuer) throw fail("invalid_issuer", "the response did not come from " + issuer);
      if (params.get("error")) throw fail(params.get("error"), params.get("error_description") || "");
      var code = params.get("code");
      if (!code) throw fail("invalid_request", "no authorization code in the URL");
      // A flow saved by 2.0.x has no issuer field; 2.0.x could only use the default issuer.
      var flowIssuer = typeof flow.issuer === "string" ? flow.issuer : DEFAULT_ISSUER;
      if (flowIssuer !== issuer) throw fail("invalid_request", "sign-in was started against another issuer");
      if (typeof flow.createdAt !== "number" || Date.now() - flow.createdAt > MAX_FLOW_AGE_MS) {
        throw fail("expired", "sign-in took too long; try again");
      }
      var clientId = opts.clientId || flow.clientId;
      var redirectUri = opts.redirectUri || flow.redirectUri;
      if (clientId !== flow.clientId || redirectUri !== flow.redirectUri) {
        throw fail("invalid_request", "clientId/redirectUri differ from the ones used to start sign-in");
      }

      return postForm(issuer + "/oauth/token", {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: flow.codeVerifier,
      }).then(function (tokens) {
        var idc = tokens.id_token ? decodeJwtPayload(tokens.id_token) : null;
        if (!idc) throw fail("invalid_token", "no ID token in the token response");
        var aud = Object.prototype.toString.call(idc.aud) === "[object Array]" ? idc.aud : [idc.aud];
        var nowS = Date.now() / 1000;
        if (idc.iss !== issuer) throw fail("invalid_token", "ID token iss mismatch");
        if (aud.indexOf(clientId) === -1) throw fail("invalid_token", "ID token aud mismatch");
        if (aud.length > 1 && idc.azp !== clientId) throw fail("invalid_token", "ID token azp mismatch");
        if (typeof idc.nonce !== "string" || !constantTimeEqual(idc.nonce, flow.nonce)) throw fail("invalid_token", "ID token nonce mismatch");
        if (typeof idc.exp !== "number" || idc.exp < nowS - CLOCK_SKEW_S) throw fail("invalid_token", "ID token expired");
        if (typeof idc.iat === "number" && idc.iat > nowS + CLOCK_SKEW_S) throw fail("invalid_token", "ID token issued in the future");
        if (typeof idc.sub !== "string" || !idc.sub) throw fail("invalid_token", "ID token has no sub");
        var scope = String(tokens.scope || "").split(" ").filter(Boolean); // what the user actually granted
        if (opts.userinfo === false) return { tokens: tokens, claims: idc, idTokenClaims: idc, scope: scope };
        return global
          // The token goes in a form body (RFC 6750 §2.2) rather than an
          // Authorization header: that keeps this a CORS "simple request",
          // so it works from any origin without a preflight.
          .fetch(issuer + "/oauth/userinfo", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
            body: "access_token=" + encodeURIComponent(tokens.access_token),
            credentials: "omit",
            cache: "no-store",
            redirect: "error",
          })
          .then(function (res) {
            return readJson(res).then(function (body) {
              if (!res.ok) {
                var e = httpError(res, body);
                if (res.status !== 429) {
                  e.code = "userinfo_failed";
                  e.message = "[NobleID] userinfo_failed: HTTP " + res.status;
                }
                throw e;
              }
              return body;
            });
          })
          .then(function (claims) {
            if (claims.sub !== idc.sub) throw fail("invalid_token", "userinfo sub differs from ID token sub");
            return { tokens: tokens, claims: claims, idTokenClaims: idc, scope: scope };
          });
      });
    });
  }

  /**
   * Revoke a refresh or access token (call on sign-out). Public clients send
   * only their client id. Resolves true; NobleID answers 200 even for tokens
   * it does not know.
   *
   * @param {{clientId: string, token: string, tokenTypeHint?: "refresh_token"|"access_token"}} opts
   * @returns {Promise<boolean>}
   */
  function revoke(opts) {
    opts = opts || {};
    if (!opts.clientId || !opts.token) return Promise.reject(fail("invalid_request", "clientId and token are required"));
    var fields = { token: opts.token, client_id: opts.clientId };
    if (opts.tokenTypeHint) fields.token_type_hint = opts.tokenTypeHint;
    return postForm(cfg.revoke, fields).then(function () {
      return true;
    });
  }

  /* ───────────── official button ───────────── */

  var THEMES = {
    light: { bg: "#FFFFFF", text: "#101828", border: "#D0D5DD", hover: "#F9FAFB", muted: "#475467", ok: "#027A48" },
    dark: { bg: "#101828", text: "#FFFFFF", border: "#101828", hover: "#1D2939", muted: "#D0D5DD", ok: "#6CE9A6" },
  };
  var SIZES = {
    sm: { h: 40, pad: 12, font: 14, mark: 20, gap: 10 },
    md: { h: 44, pad: 14, font: 15, mark: 22, gap: 10 },
    lg: { h: 48, pad: 16, font: 16, mark: 24, gap: 12 },
  };
  var FONT = "Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";

  /** Same-site path or https URL (http only for localhost); no whitespace, control characters or backslashes. */
  function isSafeHref(url) {
    if (typeof url !== "string" || !url || url.length > 2048) return false;
    if (/[\u0000- \u007f-\u009f\\]/.test(url)) return false;
    if (url.charAt(0) === "/") return url.charAt(1) !== "/";
    return /^https:\/\/[^/?#]+/i.test(url) || isLocalHttp(url);
  }

  /**
   * Create the official "Sign in with NobleID" button element.
   * With `loginUrl` it is a link to your server's sign-in route (confidential
   * client); otherwise it runs signIn(opts) as a public client.
   *
   * @param {{loginUrl?: string, clientId?: string, redirectUri?: string, scope?: string,
   *          theme?: "light"|"dark", size?: "sm"|"md"|"lg",
   *          label?: "Sign in with NobleID"|"Continue with NobleID",
   *          onError?: function(Error): void}} opts
   * @returns {HTMLElement}
   */
  function createButton(opts) {
    opts = opts || {};
    var theme = THEMES[opts.theme] || THEMES.light;
    var size = SIZES[opts.size] || SIZES.md;
    var label = LABELS.indexOf(opts.label) !== -1 ? opts.label : LABELS[0];
    var useLink = !!opts.loginUrl;
    if (useLink && !isSafeHref(opts.loginUrl)) {
      throw fail("invalid_request", "loginUrl must be a same-site path or an https URL");
    }

    var doc = global.document;
    var el = doc.createElement(useLink ? "a" : "button");
    if (useLink) el.setAttribute("href", opts.loginUrl);
    else el.setAttribute("type", "button");
    el.setAttribute("data-nobleid-button", VERSION);
    el.setAttribute("aria-label", label);
    el.style.cssText = [
      "display:inline-flex",
      "align-items:center",
      "gap:" + size.gap + "px",
      "height:" + size.h + "px",
      "min-height:40px",
      "padding:0 " + (size.pad + 4) + "px 0 " + size.pad + "px",
      "box-sizing:border-box",
      "border:1px solid " + theme.border,
      "border-radius:8px",
      "background:" + theme.bg,
      "color:" + theme.text,
      "font:600 " + size.font + "px/1 " + FONT,
      "text-decoration:none",
      "white-space:nowrap",
      "cursor:pointer",
    ].join(";");
    el.addEventListener("mouseenter", function () {
      el.style.background = theme.hover;
    });
    el.addEventListener("mouseleave", function () {
      el.style.background = theme.bg;
    });

    var img = doc.createElement("img");
    img.setAttribute("src", MARK_URL);
    img.setAttribute("alt", "");
    img.setAttribute("width", String(size.mark));
    img.setAttribute("height", String(size.mark));
    img.style.cssText = "display:block;flex:none";
    el.appendChild(img);

    var span = doc.createElement("span");
    span.textContent = label;
    el.appendChild(span);

    if (!useLink) {
      var busy = false;
      el.addEventListener("click", function () {
        if (busy) return;
        busy = true;
        signIn(opts).catch(function (e) {
          busy = false;
          if (typeof opts.onError === "function") opts.onError(e);
          else if (global.console) global.console.error(e);
        });
      });
    }
    return el;
  }

  function resolveContainer(container) {
    var el = typeof container === "string" ? global.document.getElementById(container) : container;
    if (!el) throw fail("invalid_request", "container not found");
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }

  /**
   * Render the button into a container (element or element id), replacing its content.
   * @param {string|HTMLElement} container
   * @param {object} opts see createButton
   * @returns {HTMLElement} the button
   */
  function renderButton(container, opts) {
    var el = resolveContainer(container);
    var btn = createButton(opts);
    clear(el);
    el.appendChild(btn);
    return btn;
  }

  /* ───────────── researcher badge (presentational) ───────────── */

  var ORCID_PATH = /^\/\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/;
  // The name is self-entered. Bidirectional controls and tick lookalikes in it
  // could make part of it read like a verification marker, so they are dropped.
  var NAME_SPOOF = /[\u200e\u200f\u202a-\u202e\u2066-\u2069\u221a\u237b\u2611\u2705\u2713\u2714]|\ud83d[\uddf8\uddf9]|\ud800\udd02|\ud83e\udfb1/g;

  /** Returns the URL string if it is https://www.nobleid.org/... (or https://orcid.org/<iD> for kind "orcid"), else null. */
  function safeProfileUrl(value, kind) {
    if (typeof value !== "string" || value.length > 512 || /[\u0000- \u007f-\u009f\\]/.test(value)) return null;
    var m = /^https:\/\/([^/?#]+)(\/[^?#]*)?$/.exec(value);
    if (!m) return null;
    var host = m[1];
    var path = m[2] || "/";
    if (kind === "orcid") return host === "orcid.org" && ORCID_PATH.test(path) ? value : null;
    return host === "www.nobleid.org" && /^\/[A-Za-z0-9]{1,64}$/.test(path) ? value : null;
  }

  /**
   * Render a small, read-only researcher badge from claims your app already
   * received (ID token or userinfo). Shows the name, the NobleID (linked to
   * nobleid_uri when that is the NobleID's own profile) and only the
   * verification markers that are present and true:
   * identity_verified, nobleid_verified_researcher, a verified ORCID iD
   * (linked), and verified_authorship_count > 0. Links go only to
   * https://www.nobleid.org/ and https://orcid.org/; anything else is shown
   * as plain text or dropped. Built with DOM APIs only.
   *
   * @param {string|HTMLElement} container
   * @param {object} claims
   * @param {{theme?: "light"|"dark"}} [opts]
   * @returns {HTMLElement} the badge element
   */
  function renderResearcherBadge(container, claims, opts) {
    opts = opts || {};
    claims = claims && typeof claims === "object" ? claims : {};
    var el = resolveContainer(container);
    var theme = THEMES[opts.theme] || THEMES.light;
    var doc = global.document;

    var badge = doc.createElement("div");
    badge.setAttribute("data-nobleid-badge", VERSION);
    badge.setAttribute("role", "group");
    badge.setAttribute("aria-label", "NobleID researcher");
    badge.style.cssText = [
      "display:inline-flex",
      "flex-direction:column",
      "gap:6px",
      "padding:12px 14px",
      "border:1px solid " + theme.border,
      "border-radius:8px",
      "background:" + theme.bg,
      "color:" + theme.text,
      "font:400 14px/1.4 " + FONT,
      "max-width:100%",
      "box-sizing:border-box",
    ].join(";");

    var head = doc.createElement("div");
    head.style.cssText = "display:flex;align-items:center;gap:8px";
    var img = doc.createElement("img");
    img.setAttribute("src", MARK_URL);
    img.setAttribute("alt", "");
    img.setAttribute("width", "20");
    img.setAttribute("height", "20");
    head.appendChild(img);
    var name = doc.createElement("strong");
    var shown = typeof claims.name === "string" ? claims.name.replace(NAME_SPOOF, "").replace(/\s+/g, " ").replace(/^ | $/g, "").slice(0, 200) : "";
    name.textContent = shown || "NobleID member";
    name.setAttribute("dir", "auto");
    name.style.cssText = "unicode-bidi:isolate";
    head.appendChild(name);
    badge.appendChild(head);

    if (typeof claims.nobleid === "string" && /^[A-Za-z0-9]{1,64}$/.test(claims.nobleid)) {
      var idLine = doc.createElement("div");
      var href = safeProfileUrl(claims.nobleid_uri, "nobleid");
      // Link only to this NobleID's own profile, never to someone else's.
      if (href !== "https://www.nobleid.org/" + claims.nobleid) href = null;
      var idNode = doc.createElement(href ? "a" : "span");
      if (href) link(idNode, href, theme);
      idNode.textContent = claims.nobleid;
      idLine.appendChild(idNode);
      badge.appendChild(idLine);
    }

    var markers = doc.createElement("ul");
    markers.style.cssText = "list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:4px 12px;color:" + theme.muted;
    var add = function (text, node) {
      var li = doc.createElement("li");
      var tick = doc.createElement("span");
      tick.setAttribute("aria-hidden", "true");
      tick.style.color = theme.ok;
      tick.textContent = "✓ ";
      li.appendChild(tick);
      if (node) li.appendChild(node);
      else li.appendChild(doc.createTextNode(text));
      markers.appendChild(li);
    };
    if (claims.identity_verified === true) add("ID verified");
    if (claims.nobleid_verified_researcher === true) add("Verified researcher");
    var orcidHref = claims.orcid_verified === true ? safeProfileUrl(claims.orcid, "orcid") : null;
    if (orcidHref) {
      var a = doc.createElement("a");
      link(a, orcidHref, theme);
      a.textContent = "ORCID " + orcidHref.slice("https://orcid.org/".length);
      add(null, a);
    }
    var n = claims.verified_authorship_count;
    if (typeof n === "number" && n > 0 && n % 1 === 0 && n < 1e7) add(n + (n === 1 ? " verified authorship" : " verified authorships"));
    if (markers.firstChild) badge.appendChild(markers);

    clear(el);
    el.appendChild(badge);
    return badge;
  }

  function link(a, href, theme) {
    a.setAttribute("href", href);
    a.setAttribute("target", "_blank");
    a.setAttribute("rel", "noopener noreferrer");
    a.style.color = theme.text;
  }

  /* ───────────── data-attribute auto-init ───────────── */

  /** True when url (absolute or relative) resolves to this page's own origin. */
  function isThisOrigin(url) {
    try {
      return new global.URL(url, global.location.href).origin === global.location.origin;
    } catch (e) {
      return false;
    }
  }

  function autoInit() {
    var nodes = global.document.querySelectorAll("[data-nobleid-client-id],[data-nobleid-login-url]");
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      if (n.getAttribute("data-nobleid-initialized")) continue;
      n.setAttribute("data-nobleid-initialized", "true");
      try {
        var loginUrl = n.getAttribute("data-nobleid-login-url") || undefined;
        var redirectUri = n.getAttribute("data-nobleid-redirect-uri") || undefined;
        // HTML sanitisers usually keep data-* attributes, so markup a visitor
        // wrote could carry these. From markup, only this page's own origin.
        if ((loginUrl && !isThisOrigin(loginUrl)) || (redirectUri && !isThisOrigin(redirectUri))) {
          throw fail("invalid_request", "data-nobleid-login-url and data-nobleid-redirect-uri must be on this page's origin; use NobleID.renderButton for anything else");
        }
        renderButton(n, {
          loginUrl: loginUrl,
          clientId: n.getAttribute("data-nobleid-client-id") || undefined,
          redirectUri: redirectUri,
          scope: n.getAttribute("data-nobleid-scope") || undefined,
          theme: n.getAttribute("data-nobleid-theme") || undefined,
          size: n.getAttribute("data-nobleid-size") || undefined,
          label: n.getAttribute("data-nobleid-label") || undefined,
        });
      } catch (e) {
        if (global.console) global.console.error(e);
      }
    }
  }

  var api = {
    version: VERSION,
    issuer: cfg.issuer,
    endpoints: {},
    configure: configure,
    renderButton: renderButton,
    createButton: createButton,
    renderResearcherBadge: renderResearcherBadge,
    createAuthorizeUrl: createAuthorizeUrl,
    signIn: signIn,
    handleCallback: handleCallback,
    revoke: revoke,
    security: {
      randomString: randomString,
      codeChallengeS256: codeChallengeS256,
      decodeJwtPayloadUnverified: decodeJwtPayload,
    },
  };

  function syncPublicEndpoints() {
    api.issuer = cfg.issuer;
    api.endpoints = {
      authorization: cfg.authorize,
      token: cfg.token,
      userinfo: cfg.userinfo,
      revocation: cfg.revoke,
      jwks: cfg.jwks,
    };
  }
  syncPublicEndpoints();

  global.NobleID = api;

  if (global.document && global.document.querySelectorAll) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", autoInit);
    } else {
      autoInit();
    }
  }
})(typeof window !== "undefined" ? window : this);
