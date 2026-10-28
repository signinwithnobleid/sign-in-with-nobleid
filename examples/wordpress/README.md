# WordPress

WordPress needs no code: configure the **OpenID Connect Generic Client**
plugin. The full guide, with every field value, is
[docs/integrations/wordpress.md](../../docs/integrations/wordpress.md).

Short version:

| Field | Value |
|---|---|
| Login Type | OpenID Connect button on login form |
| Client ID / Client Secret Key | from your NobleID app (confidential) |
| OpenID Scope | `openid email profile` |
| Login Endpoint URL | `https://www.nobleid.org/oauth/authorize` |
| Userinfo Endpoint URL | `https://id.nobleid.org/oauth/userinfo` |
| Token Validation Endpoint URL | `https://id.nobleid.org/oauth/token` |
| End Session Endpoint URL | leave empty |
| JWKS URI | `https://id.nobleid.org/.well-known/jwks.json` |
| Issuer | `https://id.nobleid.org` |
| Identity Key | `sub` |
| Nickname Key | `preferred_username` |
| Email Formatting | `{email}` |
| Redirect URI to register | `https://YOUR-SITE/wp-admin/admin-ajax.php?action=openid-connect-authorize` |

`test/wordpress.test.mjs` replays the plugin's exact requests against the
local mock: `node --test test/wordpress.test.mjs`.
