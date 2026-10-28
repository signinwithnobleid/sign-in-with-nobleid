# Discourse

Written for current Discourse (checked against the `main` branch, October 2026),
where the official OpenID Connect plugin (`discourse-openid-connect`) is
bundled with core. Before July 2025 it was a separate plugin, and some settings
below (`openid connect email verified claim fallback`, `openid connect email
claim`, the logout extras) were added after the split. On older sites, update
Discourse first.

**Tested?** Documented from the platform's documentation and source code; not run.

## Settings

**Admin → Settings**, filter on `openid connect`:

| Setting | Value |
|---|---|
| `openid connect enabled` | on |
| `openid connect discovery document` | `https://id.nobleid.org/.well-known/openid-configuration` |
| `openid connect client id` | `nbcl_your_client_id` |
| `openid connect client secret` | `nbcs_your_client_secret` |
| `openid connect authorize scope` | `openid profile email` (the default is `openid` alone, which gives Discourse no name or email) |
| `openid connect token scope` | empty |
| `openid connect use pkce` | on (recommended; S256) |
| `openid connect match by email` | on (default). Safe: see below. |
| `openid connect email verified claim fallback` | off (default) |
| `openid connect email claim` | `email` (default) |
| `openid connect overrides email` | off. See the caution below. |
| `openid connect rp initiated logout` | **off**. NobleID has no end-session endpoint. |
| `openid connect rp initiated logout redirect` | empty |
| `openid connect allow association change` | your choice |
| `openid connect authorize parameters` | empty |
| `openid connect claims` | empty |

Discourse reads every endpoint from the discovery document, including the
authorization endpoint on `www.nobleid.org`.

### Redirect URI

`https://forum.example.org/auth/oidc/callback`. Use your forum's base URL, plus
the subfolder if Discourse is installed in one.

## How Discourse behaves with NobleID

- **Client authentication**: `client_secret_basic`, chosen from discovery.
  With PKCE on, the secret is still sent.
- **ID token**: Discourse checks `iss`, `aud`, `exp` and the `nonce` it sent.
  It does not check the signature, relying on the direct TLS call to the token
  endpoint, so ES256 needs no setting. It then calls userinfo and refuses the
  sign-in if the userinfo `sub` differs from the ID token's.
- **Account key**: `sub`. Changing the NobleID email or username does not
  create a second Discourse account.
- **Matching existing accounts by email**: Discourse links to an existing
  account only when `email_verified` is `true`. Keep `openid connect email
  verified claim fallback` off so that a missing claim counts as unverified.
- **Email unticked**: if the user unticks `email` on NobleID's consent screen,
  Discourse asks them for an email and verifies it itself.

### Caution: `openid connect overrides email`

When on, every sign-in replaces the user's Discourse email with the one NobleID
sends. Turn it on only if NobleID is the only way into the forum and you want
NobleID to own the email address. Leave it off if users also sign in with a
password or another provider.

### Logout

Leave `openid connect rp initiated logout` off. NobleID publishes no
`end_session_endpoint`. Logging out of Discourse ends the Discourse session
only. The user stays signed in at nobleid.org.

## Profile fields

| NobleID claim | Discourse field | Scope |
|---|---|---|
| `name` | Name | `profile` |
| `preferred_username` | Username (suggested) | `profile` |
| `email` | Email | `email` |
| `picture` | Avatar | `profile` |

Discourse uses these when it creates the account. Later sign-ins change the email only with **openid connect overrides email** on (see above).

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).

## Sources

- Plugin topic: https://meta.discourse.org/t/openid-connect-authentication-plugin/103632
- Bundling announcement: https://meta.discourse.org/t/bundling-more-popular-plugins-with-discourse-core/373574
- Settings and implementation: https://github.com/discourse/discourse, directory
  `plugins/discourse-openid-connect/` (`config/settings.yml`,
  `lib/omniauth_open_id_connect.rb`, `lib/openid_connect_authenticator.rb`)
- Email matching rules: `lib/auth/managed_authenticator.rb` in the same repository
