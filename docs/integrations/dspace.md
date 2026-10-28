# DSpace

Written for DSpace 8.x and 9.x. The OIDC plugin and its keys have not changed
since DSpace 7.2, where they first appeared, so 7.2–7.6 should behave the same.

**Tested?** Documented from the platform's documentation and source code; not run.

## How DSpace's OIDC login behaves

Read this before you enable it:

- It uses the authorization code flow. It sends the client secret in the
  request body (`client_secret_post`), then reads the user from the
  **userinfo** endpoint. It does not read or verify the ID token, so NobleID's
  ES256 signing needs no setting.
- It sends no `state`, `nonce` or PKCE. Nothing can be configured to add them.
- It finds the DSpace account (EPerson) **by email**, not by `sub`. It does not
  read `email_verified`. A NobleID account whose email is not verified would
  sign in as the DSpace EPerson with that address. That includes administrators.
- If the user unticks `email` on NobleID's consent screen, DSpace refuses the
  sign-in.
- There is no logout call to NobleID. Signing out ends the DSpace session only.

**Recommended: put Keycloak in front** ([keycloak.md](keycloak.md)). Keycloak
runs the sign-in with `state`, `nonce` and PKCE, and then presents a Keycloak
realm to DSpace. It keeps unverified emails out only if you set **Trust Email
On** on the NobleID identity provider **and** **Realm settings → Login →
Verify email On** in the realm DSpace uses; without both, the email problem
above comes back through Keycloak. DSpace's default OIDC settings
are already written for a Keycloak realm.

Connect DSpace to NobleID directly only where no existing EPerson matters,
for example a test instance, or a repository that lets NobleID sign-ins
create new accounts but has no local accounts (and no administrators) whose
email someone else could put on a NobleID account.

## Configure

Add to `[dspace]/config/local.cfg`:

```properties
# Keep password login and add OIDC. Repeating the key appends a method.
plugin.sequence.org.dspace.authenticate.AuthenticationMethod = org.dspace.authenticate.PasswordAuthentication
plugin.sequence.org.dspace.authenticate.AuthenticationMethod = org.dspace.authenticate.OidcAuthentication

# Full endpoint URLs. Leave auth-server-url and auth-server-realm unset; they
# only build Keycloak-style defaults.
authentication-oidc.authorize-endpoint = https://www.nobleid.org/oauth/authorize
authentication-oidc.token-endpoint = https://id.nobleid.org/oauth/token
authentication-oidc.user-info-endpoint = https://id.nobleid.org/oauth/userinfo

authentication-oidc.client-id = nbcl_your_client_id
# Better: leave this out of local.cfg and set the environment variable
#   authentication__D__oidc__P__client__D__secret=nbcs_your_client_secret
authentication-oidc.client-secret = nbcs_your_client_secret

# Must match the redirect URI registered with NobleID exactly.
authentication-oidc.redirect-url = ${dspace.server.url}/api/authn/oidc

# Comma-separated in DSpace config; sent space-separated.
authentication-oidc.scopes = openid,email,profile

# true: first NobleID sign-in creates an EPerson. false: only existing EPersons.
authentication-oidc.can-self-register = false

authentication-oidc.user-info.email = email
authentication-oidc.user-info.first-name = given_name
authentication-oidc.user-info.last-name = family_name
```

The class name is case-sensitive: `OidcAuthentication`, not
`OIDCAuthentication`. Setting `plugin.sequence…` in `local.cfg` replaces the
list in `authentication.cfg`, so list every method you want to keep.

Restart the backend. The Angular UI shows the OIDC login option on its own
once the REST API reports it.

### Redirect URI

`${dspace.server.url}/api/authn/oidc`. Its usual shape is
`https://repo.example.org/server/api/authn/oidc`. Register exactly the value
your `dspace.server.url` produces.

### Fields not used

- No discovery URL, issuer, JWKS or logout URL setting exists. DSpace uses only
  the three endpoints above.
- `orcid`, `works` and `affiliations` add nothing in DSpace. It maps only
  email, first name and last name.

## Profile fields

| NobleID claim | DSpace field | Scope |
|---|---|---|
| `email` | EPerson email (`authentication-oidc.user-info.email`) | `email` |
| `given_name` | First name (`authentication-oidc.user-info.first-name`) | `profile` |
| `family_name` | Last name (`authentication-oidc.user-info.last-name`) | `profile` |

DSpace reads only these three. Ticking ORCID iD or Affiliations on your app adds nothing here.

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).

## Sources

- DSpace 9 Authentication Plugins (OIDC section):
  https://wiki.lyrasis.org/display/DSDOC9x/Authentication+Plugins
- DSpace 8 Authentication Plugins:
  https://wiki.lyrasis.org/display/DSDOC8x/Authentication+Plugins
- Default config:
  https://github.com/DSpace/DSpace/blob/dspace-9_x/dspace/config/modules/authentication-oidc.cfg
- Implementation: `dspace-api/src/main/java/org/dspace/authenticate/OidcAuthenticationBean.java`
  and `oidc/impl/OidcClientImpl.java` in the same repository
- Environment-variable config names (`__P__` for `.`, `__D__` for `-`):
  `dspace-services/src/main/java/org/dspace/servicemanager/config/DSpaceEnvironmentConfiguration.java`
