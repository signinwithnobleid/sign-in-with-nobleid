# Platform integrations

How to add "Sign in with NobleID" to common research platforms, using each
platform's own OpenID Connect support.

| Platform | Guide | Works directly? | Tested? |
|---|---|---|---|
| WordPress | [wordpress.md](wordpress.md) | Yes | Request shape checked against the mock; plugin not run |
| Open Journal Systems (OJS) | [ojs.md](ojs.md) | No, with the released plugin (RS256 only). Works through Keycloak. | Documented, not run |
| DSpace 7.2+ / 8 / 9 | [dspace.md](dspace.md) | Yes | Documented, not run |
| Dataverse 6.1+ | [dataverse.md](dataverse.md) | Yes | Documented, not run |
| JupyterHub | [jupyterhub.md](jupyterhub.md) | Yes | Checked against the local mock |
| Discourse | [discourse.md](discourse.md) | Yes | Documented, not run |
| Moodle 4.5 / 5.x | [moodle.md](moodle.md) | Yes | Documented, not run |
| Keycloak (as a broker) | [keycloak.md](keycloak.md) | Yes | Documented, not run |

"Documented, not run" means the guide was written from the platform's
documentation and source code. Nobody has run that platform against NobleID or
the mock. Report problems to info@nobleid.org if they are security issues,
otherwise open an issue.

## NobleID values

Every guide uses these.

| Setting | Value |
|---|---|
| Issuer | `https://id.nobleid.org` |
| Discovery URL | `https://id.nobleid.org/.well-known/openid-configuration` |
| Authorization endpoint | `https://www.nobleid.org/oauth/authorize` (note: **www**.nobleid.org, not id.) |
| Token endpoint | `https://id.nobleid.org/oauth/token` |
| Userinfo endpoint | `https://id.nobleid.org/oauth/userinfo` |
| JWKS URL | `https://id.nobleid.org/.well-known/jwks.json` |
| Revocation endpoint | `https://id.nobleid.org/oauth/revoke` |
| End-session / logout URL | none. Leave it empty. Signing out is local to your platform. |
| ID token signing | ES256 only |
| PKCE | S256. Required for public clients; recommended for the server-side (confidential) clients in these guides. |
| Client authentication | `client_secret_basic` or `client_secret_post` |
| Client ID / secret | `nbcl_your_client_id` / `nbcs_your_client_secret`, from your NobleID application settings. Keep the secret out of version control. |

The authorization endpoint is on a different host from the issuer. Platforms
that read the discovery document get this right on their own. If you type
endpoints in by hand, copy them from the table.

## Scopes

- Minimum: `openid profile email`.
- Optional: `orcid` (the user's ORCID iD and `orcid_verified`, only if they
  connected ORCID by signing in with it), `works` (`works_count`,
  `works_endpoint`), `affiliations` (self-asserted: the primary
  `affiliation` in the ID token and userinfo, the full `affiliations` list
  in userinfo only).
- Each guide has a "Profile fields" section: what that platform fills from
  NobleID. For the general rules (fill only empty fields, refresh on sign-in)
  see [Fill your app's profile from NobleID](../profile-data.md).
- `offline_access` returns a refresh token. Ask for it only if the platform
  uses refresh tokens. Refresh tokens rotate on every use. Reusing an old one
  revokes the whole chain.
- On the consent screen the user can untick any scope except `openid`. Expect
  `email` to be missing sometimes.

## Accounts

- Key accounts on `sub`. It is the only identifier that never changes.
- Link a NobleID sign-in to an existing local account by email only when
  `email_verified` is `true`. Several platforms cannot check this. Each guide
  says what yours does and how to stay safe.

## Redirect URI

Each platform builds its own callback URL. Copy it from the platform's settings
page and register it in your NobleID application exactly, character for
character. Each guide shows the usual shape with `example.org` as a placeholder.
