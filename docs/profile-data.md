# Fill your app's profile from NobleID

When a person signs in with NobleID and agrees, your app can fill its own
profile from theirs: name, photo, ORCID iD, institution, role and more. It
works the same for journals, repositories, lab sites and any other app.

The same page is on the website:
https://www.nobleid.org/developers/sign-in/profile-data

## 1. Ask for the data

1. In **Dashboard → OAuth apps**, edit your app and tick the scopes you will
   use. No review is needed. A new app has only `openid` and `profile`.
2. Ask for the same scopes in your sign-in request. Asking for one your app
   does not have stops sign-in with `invalid_scope`.
3. Each person sees every piece of data on the consent screen and can untick
   any of it. Read the granted `scope` in the token response.

| Scope | What it fills |
|---|---|
| `profile` | Name, username, photo, website and research interests |
| `email` | Email address, and whether the person confirmed it |
| `orcid` | ORCID iD, when the person proved it by signing in to ORCID |
| `affiliations` | Main institution with its ROR iD, and each role and start year |
| `works` | The works the person registered on NobleID |

## 2. Map the claims to your fields

| Claim | Type | Scope | In | Fills |
|---|---|---|---|---|
| `sub` | string | `openid` | ID token, userinfo | Account key. Never changes. |
| `nobleid` | string | `openid` | ID token, userinfo | NobleID |
| `nobleid_uri` | URL | `openid` | ID token, userinfo | Link to NobleID |
| `name` | string | `profile` | ID token, userinfo | Display name |
| `given_name` | string | `profile` | ID token, userinfo | First name |
| `family_name` | string | `profile` | ID token, userinfo | Last name |
| `preferred_username` | string | `profile` | ID token, userinfo | Suggested username. It can change. |
| `picture` | https URL | `profile` | ID token, userinfo | Photo. Copy it if you keep it: the URL changes with the photo. |
| `website` | http(s) URL | `profile` | ID token, userinfo | Website |
| `profile` | URL | `profile` | ID token, userinfo | Link to the NobleID profile. Absent when the profile is not public. |
| `research_interests` | string[] | `profile` | userinfo | Research interests, keywords |
| `email` | string | `email` | ID token, userinfo | Email |
| `email_verified` | boolean | `email` | ID token, userinfo | Link to an existing account by email only when `true`. |
| `orcid` | URL | `orcid` | ID token, userinfo | ORCID iD (`https://orcid.org/…`). Sent only when proven through ORCID. |
| `affiliation` | `{ name, ror? }` | `affiliations` | ID token, userinfo | Institution. `ror` is an `https://ror.org/…` URL. |
| `affiliations` | `{ organization, role?, start_year?, ror? }[]` | `affiliations` | userinfo | Position, role, history. The main one comes first; `start_year` is a number. |
| `works_endpoint` | URL | `works` | userinfo | Publications list: titles, ARKs, DOIs and dates. |

- A claim with no value is left out. It is never `null` or an empty string.
  A missing claim means "not shared or not known", never false.
- Text is trimmed. URLs are absolute, and `picture` is always https.
- Affiliations are what the person entered. NobleID does not check them. An
  ORCID iD is sent only after the person proved it.
- NobleID does not send a phone number, postal address, country or bio.

## 3. Fill only what is empty

Never overwrite what the person edited in your app. Their own edits win.

- On the first sign-in, fill the fields that are empty.
- On each later sign-in, read the claims again. Update a field only if it
  still holds what NobleID sent last time. Keep that last value next to the
  account to compare.
- Never clear a field because a claim is missing. The person may have
  unticked that scope.
- Key the account on `sub`, never on email, username or name.

## The helpers

Each helper in `packages/` has the same function. It takes the verified ID
token claims and, optionally, the userinfo response for the same `sub`, and
returns a plain profile in which every field is present (`null`, `[]` or
`false` when not shared). Userinfo wins where both carry a claim. It refuses
userinfo for another `sub` with `invalid_token`. It also guards against odd
input: `orcid` only when `orcid_verified` is `true`, `picture` only https,
`website` only http(s), and a `start_year` sent as a string by servers before
27 Oct 2026 is read as a number.

| Helper | Function | Field names |
|---|---|---|
| Node | `profileFromClaims(claims, userinfo)` | camelCase (`givenName`, `startYear`) |
| Python | `profile_from_claims(claims, userinfo)` | snake_case |
| Go | `nobleid.ProfileFromClaims(signIn.Claims.Raw, userinfo)` | Go fields, snake_case JSON tags; `""`, `0` or `nil` when not shared |
| Rust | `profile_from_claims(&id_claims, Some(&userinfo))` or `profile_from_json` | snake_case, `Option` |
| PHP | `Profile::fromClaims($claims, $userinfo)` | snake_case |

All five are tested against the same cases in
[`test/profile-vectors.json`](../test/profile-vectors.json).

### Node

```js
import { profileFromClaims } from "nobleid-signin";

const { tokens, claims } = await nobleid.finishSignIn(callbackUrl, transaction);
const userinfo = await nobleid.userinfo(tokens.access_token, claims.sub);
const p = profileFromClaims(claims, userinfo);

// What you fill from NobleID, in your own field names.
const fromNobleId = { displayName: p.name, orcid: p.orcid, institution: p.affiliation?.name ?? null };
const changes = fillProfile(user.profile, fromNobleId, user.lastFromNobleId);
await saveProfile(user.id, changes);
await saveLastFromNobleId(user.id, fromNobleId); // compare against it next time

// Fill a field when it is empty, or when it still holds what NobleID sent
// last time. Never clear a field because a value is missing.
function fillProfile(current, fresh, last = {}) {
  const changes = {};
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  for (const [key, value] of Object.entries(fresh)) {
    if (value === null || value === undefined) continue;
    const now = current[key];
    const empty = now == null || now === "" || (Array.isArray(now) && now.length === 0);
    if (empty || (key in last && same(now, last[key]))) changes[key] = value;
  }
  return changes;
}
```

### Python

```python
from nobleid_signin import profile_from_claims

r = nobleid.finish_sign_in()
info = nobleid.userinfo(r["tokens"]["access_token"], r["claims"]["sub"])
p = profile_from_claims(r["claims"], info)
from_nobleid = {"display_name": p["name"], "orcid": p["orcid"], "institution": (p["affiliation"] or {}).get("name")}
```

### Go

```go
signIn, err := client.FinishSignIn(ctx, r.URL.Query(), tx)
info, err := client.UserInfo(ctx, signIn.Tokens.AccessToken, signIn.Claims.Subject)
p, err := nobleid.ProfileFromClaims(signIn.Claims.Raw, info)
```

### Rust

```rust
let sign_in = nobleid.finish_sign_in(&query, tx).await?;
let info = nobleid.userinfo(&sign_in.tokens.access_token, Some(sign_in.claims.subject().as_str())).await?;
let p = nobleid_signin::profile_from_claims(&sign_in.claims, Some(&info))?;
```

### PHP

```php
use NobleId\SignIn\Profile;

$r = $nobleid->finishSignIn($_GET, $tx);
$info = $nobleid->userinfo($r['tokens']['access_token'], $r['claims']['sub']);
$p = Profile::fromClaims($r['claims'], $info);
```

## On a research platform

Each [platform guide](integrations/README.md) has a "Profile fields" section
with what that platform fills from NobleID.
