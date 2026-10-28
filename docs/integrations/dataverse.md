# Dataverse

Written for Dataverse 6.1 and later (checked against 6.12.1). PKCE settings and
the JVM / MicroProfile configuration route first appear in 6.1. On 5.x and 6.0
use the admin-API route without the PKCE fields.

**Tested?** Documented from the platform's documentation and source code; not run.

## How Dataverse's OIDC client behaves

- It reads NobleID's discovery document from the issuer, so it finds the
  authorization endpoint on `www.nobleid.org` itself.
- It asks for `openid email profile`. The scope list is fixed in code.
- It authenticates to the token endpoint with `client_secret_basic`. With PKCE
  enabled it sends the S256 challenge as well. It sends a `nonce` and `state`.
- It reads the user from the **userinfo** endpoint and does not validate the
  ID token. NobleID's ES256 signing therefore needs no setting.
- The account is keyed on `sub`. `preferred_username`, `given_name`,
  `family_name` and `email` prefill the account-creation page on the first
  sign-in.
- It does not link to an existing local account by email on its own.
- There is no logout call to NobleID. Signing out is local.

## Option A: JVM / MicroProfile settings (one provider)

Set these as JVM options or environment variables. This is the simplest route
for a single provider. Changes need a restart.

| Option | Environment variable | Value |
|---|---|---|
| `dataverse.auth.oidc.enabled` | `DATAVERSE_AUTH_OIDC_ENABLED` | `true` |
| `dataverse.auth.oidc.auth-server-url` | `DATAVERSE_AUTH_OIDC_AUTH_SERVER_URL` | `https://id.nobleid.org` |
| `dataverse.auth.oidc.client-id` | `DATAVERSE_AUTH_OIDC_CLIENT_ID` | `nbcl_your_client_id` |
| `dataverse.auth.oidc.client-secret` | `DATAVERSE_AUTH_OIDC_CLIENT_SECRET` | `nbcs_your_client_secret` |
| `dataverse.auth.oidc.pkce.enabled` | `DATAVERSE_AUTH_OIDC_PKCE_ENABLED` | `true` (recommended) |
| `dataverse.auth.oidc.pkce.method` | `DATAVERSE_AUTH_OIDC_PKCE_METHOD` | `S256` (never `PLAIN`) |
| `dataverse.auth.oidc.title` | `DATAVERSE_AUTH_OIDC_TITLE` | `NobleID` |
| `dataverse.auth.oidc.subtitle` | `DATAVERSE_AUTH_OIDC_SUBTITLE` | `Sign in with NobleID` |

`auth-server-url` is the **issuer**, without `/.well-known/…`. Dataverse
appends that itself.

## Option B: admin API (one of several providers)

Create `nobleid.json`:

```json
{
  "id": "nobleid",
  "factoryAlias": "oidc",
  "title": "NobleID",
  "subtitle": "Sign in with NobleID",
  "factoryData": "type: oidc | issuer: https://id.nobleid.org | clientId: nbcl_your_client_id | clientSecret: nbcs_your_client_secret | pkceEnabled: true | pkceMethod: S256",
  "enabled": true
}
```

Load it:

```sh
curl -X POST -H 'Content-type: application/json' \
  --upload-file nobleid.json \
  http://localhost:8080/api/admin/authenticationProviders
```

The file contains the client secret. Delete it after loading, or keep it out of
version control. Watch the application server log. Dataverse fetches the
discovery document on load and disables the provider if it cannot.

## Redirect URI

Register `<dataverse.siteUrl>/oauth2/callback.xhtml`. Its usual shape is
`https://dataverse.example.org/oauth2/callback.xhtml`. It must match your
`dataverse.siteUrl` exactly, including any port.

## Notes

- No logout URL setting exists, and none is needed.
- `orcid`, `works` and `affiliations` cannot be requested, because the scope
  list is fixed. Dataverse's ORCID field is not filled from NobleID.
- If the user unticks `email` on NobleID's consent screen, they type an email
  on Dataverse's account-creation page instead.

## Profile fields

| NobleID claim | Dataverse field | Scope |
|---|---|---|
| `given_name` | Given Name | `profile` |
| `family_name` | Family Name | `profile` |
| `preferred_username` | Username (suggested) | `profile` |
| `email` | Email | `email` |

Dataverse fills these on the account-creation page at the first sign-in. The person can change them there.

Its scope list is fixed, so its Affiliation and ORCID fields are not filled from NobleID.

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).

## Sources

- OpenID Connect login options: https://guides.dataverse.org/en/latest/installation/oidc.html
- OAuth login options (redirect URL): https://guides.dataverse.org/en/latest/installation/oauth2.html
- Implementation: https://github.com/IQSS/dataverse, file
  `src/main/java/edu/harvard/iq/dataverse/authorization/providers/oauth2/oidc/OIDCAuthProvider.java`
  at tag `v6.12.1`
