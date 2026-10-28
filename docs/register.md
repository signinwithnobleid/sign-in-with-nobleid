# Register an app

Register at **https://www.nobleid.org/dashboard/oauth-apps** while signed in.

Before you can register, your NobleID account needs a confirmed email address
and two-step login (an authenticator app), and you must have used the code in
the current session.

## Confidential or public

| | Confidential | Public |
|---|---|---|
| For | Apps with a server (web backends, BFFs, CMS plugins) | Single-page apps and native apps with no server |
| Client secret | Yes (`nbcs_…`), shown once | None |
| PKCE (S256) | Optional, recommended | Required |
| Token endpoint auth | `client_secret_basic` or `client_secret_post` | `none` (send `client_id`) |
| Introspection | Yes | No |

If you have a server, register a confidential client and keep tokens on the
server, even for a single-page front end (a backend-for-frontend).

Store the secret in your secret manager or environment, never in source
control. To rotate it, create a new secret in the dashboard: the old one
keeps working for 24 hours so you can deploy. Once every server uses the new
one, end the overlap with **Revoke previous secret**. If a secret leaked,
rotate it with **Stop accepting the current secret now** ticked, so the old
one stops working at once.

## Redirect URIs

- Exact match: scheme, host, port, path and query. No wildcards. The one
  exception is the loopback port, below.
- `https` only. No fragments, no user:password.
- `http` only for `localhost`, `127.0.0.1` and `[::1]` (local development).
  For an `http` loopback URI the port may differ from the registered one
  (RFC 8252 §7.3, for native apps that bind a free port). The host must still
  match as written (`localhost` and `127.0.0.1` are different), and so must
  the path and query. Any program on the person's machine can listen on a
  loopback port, so remove loopback URIs from apps used in production.
- Reverse-DNS custom schemes such as `com.example.app:/callback` only for
  public native clients.
- Up to 10 per app.

## Logo and links

Logo, homepage and policy links must be `https`.

## What people see on the consent screen

- **Unverified apps** (every app starts unverified) show a warning and the
  redirect host.
- NobleID may **verify** an app; it then shows a badge.
- Changing the name, logo, domains or redirect URIs removes the badge until
  the app is reviewed again.
- NobleID can **suspend** an app; all its tokens stop working.

The person can untick any scope except `openid`. Read the granted `scope`.
