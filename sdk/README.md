# Browser SDK: `nobleid-auth.js`

The official "Sign in with NobleID" button and a browser-only OpenID Connect
client. Version 2.2.0. No dependencies, ES5 syntax, about 30 KB unminified (comments included).

Hosted at `https://www.nobleid.org/sdk/nobleid-auth.js`, which always serves
the latest release. A script you load from another site runs with full
access to your page, so on pages with anything to protect, self-host a
reviewed copy of [`nobleid-auth.js`](nobleid-auth.js) and update it when you
choose. Types: [`nobleid-auth.d.ts`](nobleid-auth.d.ts).

## Mode 1: your server signs people in (recommended)

If you have a backend, register a **confidential** app and do the sign-in on
the server (see the [Node](../examples/node-openid-client/),
[Python](../examples/python-flask-authlib/) and other examples). The SDK only
draws the button, as a link to your own route:

```html
<div data-nobleid-login-url="/auth/nobleid/start" data-nobleid-theme="white"></div>
<script src="https://www.nobleid.org/sdk/nobleid-auth.js" async></script>
```

or

```js
NobleID.renderButton("signin", { loginUrl: "/auth/nobleid/start", theme: "black", shape: "pill" });
```

`loginUrl` must be a same-site path (`/…`) or an `https://` URL. Anything
else (`javascript:`, `//host`, whitespace or backslash tricks) is refused.

## Mode 2: browser-only app (public client)

Register a **public** app (no secret). The SDK runs the authorization code
flow with PKCE S256, `state` and `nonce`:

```js
// sign-in page
NobleID.renderButton("signin", {
  clientId: "nbcl_your_client_id",
  redirectUri: "https://app.example/callback",
  scope: "openid profile",
  theme: "white",
  shape: "rounded",
  size: "md",
  label: "sign-in",
  onError: function (e) { console.warn(e.code); },
});

// https://app.example/callback
NobleID.handleCallback({ clientId: "nbcl_your_client_id", redirectUri: "https://app.example/callback" })
  .then(function (r) {
    // r.claims (userinfo), r.idTokenClaims, r.scope (granted), r.tokens (keep in memory only)
  })
  .catch(function (e) {
    // e.code: access_denied, invalid_state, invalid_issuer, expired, invalid_token, slow_down, …
  });
```

`handleCallback` checks, in order: a sign-in was started in this tab (each
is usable once), `state` (constant time), `iss` (RFC 9207), and only then
reports an `error` from NobleID. It then exchanges the code, checks the ID
token's `iss`, `aud`, `nonce`, `exp`, and reads userinfo. It removes the code
from the address bar.

It does not verify the ID token signature: the token comes straight from
NobleID's token endpoint over TLS (OpenID Connect Core §3.1.3.7). If you send
the ID token to a server, verify it there (ES256 via `NobleID.endpoints.jwks`).

Keep tokens in memory. Do not put them in `localStorage`, cookies readable
by scripts, URLs or logs, and do not request `offline_access` from a
browser-only app. If you have a server, use mode 1.

Sign out:

```js
NobleID.revoke({ clientId: "nbcl_your_client_id", token: r.tokens.access_token, tokenTypeHint: "access_token" });
```

## API

| Member | Purpose |
|---|---|
| `NobleID.renderButton(container, opts)` | Render the button into an element or element id. |
| `NobleID.createButton(opts)` | Create the button element. |
| `NobleID.createAuthorizeUrl(opts)` | Public clients: build the authorize URL and remember the flow. |
| `NobleID.signIn(opts)` | `createAuthorizeUrl` + navigate. |
| `NobleID.handleCallback(opts)` | Public clients: finish sign-in on the redirect URI. |
| `NobleID.revoke(opts)` | Revoke a token. |
| `NobleID.renderResearcherBadge(container, claims, opts)` | Presentational badge (below). |
| `NobleID.configure({ issuer, authorizationEndpoint })` | **Testing only**: point at a local mock or staging. Defaults to production. |
| `NobleID.endpoints`, `NobleID.issuer`, `NobleID.version` | Read-only information. |

Data attributes for auto-rendering: `data-nobleid-login-url`,
`data-nobleid-client-id`, `data-nobleid-redirect-uri`, `data-nobleid-scope`,
`data-nobleid-theme`, `data-nobleid-shape`, `data-nobleid-size`, `data-nobleid-label`.
From data attributes, `data-nobleid-login-url` and `data-nobleid-redirect-uri`
must be on the page's own origin (HTML sanitisers usually keep `data-*`, so
markup your visitors write could carry them). To link to another origin, call
`NobleID.renderButton` from your own script.

## Button rules

The options use the same names as the files in [`brand/buttons/`](../brand/buttons/),
`nobleid-<label>-<theme>-<shape>-<size>.svg`, so the SDK button and the
image look alike:

| Option | Values (default first) |
|---|---|
| `label` | `sign-in` ("Sign in with NobleID"), `continue` ("Continue with NobleID"), `icon` (the mark alone; its accessible name is "Sign in with NobleID") |
| `theme` | `white`, `black`, `green`, `outline-white`, `outline-black` |
| `shape` | `rounded` (8 px corners), `pill`, `square` |
| `size` | `md` (44 px), `sm` (40 px), `lg` (48 px) |

- An unknown value falls back to the default, so no other wording can appear.
  The 2.1 values still work: `theme: "light"` is `white`, `"dark"` is
  `black`, and the full label wordings are accepted.
- Minimum height 40 px. The browser's focus ring is kept, 2 px clear of the
  button.
- The mark loads from `https://www.nobleid.org/brand/nobleid-mark.svg`, or
  `nobleid-mark-white.svg` on the black, green and outline-white themes;
  allow `https://www.nobleid.org` in your CSP `img-src`, or use the SVGs in
  [`brand/`](../brand/).
- Which theme on which background, clear space and contrast:
  [docs/brand.md](../docs/brand.md).

## Researcher badge

```js
NobleID.renderResearcherBadge("who", r.claims, { theme: "light" });
```

Shows the name, the NobleID (linked to `nobleid_uri` only when that is
`https://www.nobleid.org/<the same NobleID>`) and only the markers
that are present and `true`: "ID verified" (`identity_verified`), "Verified
researcher" (`nobleid_verified_researcher`), the ORCID iD (when `orcid` is
present with `orcid_verified: true`, linked), and the number of verified
authorships (`verified_authorship_count > 0`, in userinfo under the `works` scope). Built with DOM text APIs only.
Bidirectional-text controls and tick symbols are removed from the name, so a
name cannot imitate a marker. Links go only to `https://www.nobleid.org/<NobleID>` and
`https://orcid.org/<iD>`, with `rel="noopener noreferrer"`; anything else is
shown as plain text or dropped.

## Content-Security-Policy

```
script-src 'self' https://www.nobleid.org/sdk/nobleid-auth.js;   (or 'self' if you self-host the SDK)
img-src https://www.nobleid.org;
connect-src https://id.nobleid.org;
```

## Testing

To try the SDK without a NobleID account, run the [local mock](../mock-oidc/)
and point the SDK at it **on both pages**, the one with the button and the
callback page, before anything else runs:

```html
<script src="nobleid-auth.js"></script>
<script>
  NobleID.configure({ issuer: "http://localhost:9400", authorizationEndpoint: "http://127.0.0.1:9400/oauth/authorize" });
</script>
```

Use the mock's public test client `nbcl_mockpublic00000000000000`; its
redirect URI `http://localhost/callback.html` accepts any port. Without the
call on the callback page, `handleCallback` fails with `invalid_issuer`.
The issuer must be `https`, except for `localhost`. Remove the call before
you go live. Tests: `node --test test/sdk.test.mjs`.

## Changes in 2.2.0

- The button comes in every label, theme, shape and size of the button files:
  new `shape` option (`rounded`, `pill`, `square`) and `data-nobleid-shape`;
  new themes `black`, `green`, `outline-white`, `outline-black`; `label: "icon"`
  for the mark alone; option values are the file-name words (`sign-in`,
  `continue`). 2.1 values keep working.
- The black theme (2.1's `dark`) shows the white mark, as the black files do.
- The button keeps the browser's focus ring 2 px clear of its border.

## Changes in 2.1.1

- Buttons rendered from data attributes accept a login URL or redirect URI
  on the page's own origin only. The JavaScript API is unchanged.

## Changes in 2.1.0

- `handleCallback` checks `state`, then `iss`, before reporting an `error`
  (a forged error with a wrong state is `invalid_state`; with a wrong or
  missing `iss` it is `invalid_issuer`). The flow is consumed before any check.
- Constant-time `state` and `nonce` comparison; `iat` and `azp` checks.
- `NobleID.configure()` for tests; `NobleID.renderResearcherBadge()`.
- Stricter `loginUrl` validation (control characters, backslashes).
- Result includes `scope` (granted scopes); `429 slow_down` errors carry `retryAfter` when the `Retry-After` header is readable.
- All 2.0 public functions keep their signatures.
