# Open Journal Systems (OJS)

Written for OJS 3.3, 3.4 and 3.5 with PKP's **OpenID Authentication Plugin**
(`openid`), releases 3.4.1.0 (OJS 3.3), 4.1.0.0 (OJS 3.4) and 5.1.0.0 (OJS 3.5),
all published 17 July 2025. The same plugin serves OMP and OPS.

**Tested?** Documented from the plugin's documentation and source code; not run.

## The released plugin cannot verify NobleID's ID tokens

The plugin does support a custom provider by discovery URL ("Custom OpenID
Provider"). But every released version reads only RSA keys from the provider's
JWKS and verifies ID tokens as RS256. NobleID signs ID tokens with ES256 only,
so the plugin finds no usable key and every NobleID sign-in fails with its
certificate error. The released plugin also sends no `state`, `nonce` or PKCE.

Use one of these two routes:

1. **Broker through Keycloak.** This works today. See below.
2. **Connect directly** once PKP releases the plugin's development branch. See
   the last section.

## Route 1: Keycloak between OJS and NobleID

Keycloak validates NobleID's ES256 tokens and issues its own RS256 tokens to
OJS, which the plugin accepts.

1. Set up NobleID as an identity provider in Keycloak by following
   [keycloak.md](keycloak.md). Use alias `nobleid`.
2. In the same realm, create a client for OJS:
   - **Clients → Create client**. Client type `OpenID Connect`. Client ID
     `ojs` (or anything you like).
   - **Client authentication**: On. **Standard flow**: On. Everything else
     off.
   - **Valid redirect URIs**: the redirect URL that the OJS plugin settings
     page shows for the custom provider (step 4). Usually
     `https://journal.example.org/index.php/index/openid/doAuthentication?provider=custom`.
   - Copy the client secret from the **Credentials** tab.
3. Send users straight to NobleID instead of Keycloak's login form:
   **Authentication → browser → Identity Provider Redirector ⚙️ → Default
   Identity Provider** = `nobleid`. If the realm serves other applications,
   duplicate the browser flow, set the redirector in the copy, and select the
   copy under the OJS client's **Advanced → Authentication flow overrides →
   Browser Flow**.
4. In OJS: **Settings → Website → Plugins → Installed Plugins → Generic Plugins → OpenID
   Authentication Plugin → Settings**. Tick **Custom OpenID Provider** and
   fill in:

   | Field | Value |
   |---|---|
   | OpenID Provider URL | `https://sso.example.org/realms/<realm>/.well-known/openid-configuration` |
   | Client identifier | the Keycloak client ID from step 2 |
   | Client secret | the Keycloak client secret from step 2 |
   | Custom login button settings | label `Sign in with NobleID` |

   Copy the redirect URL shown next to the custom provider into the Keycloak
   client (step 2).
5. Decide on **Legacy Login** (keep OJS passwords working alongside NobleID).
   Keep it on until at least one administrator account has been linked and
   tested.

What OJS receives: `given_name`, `family_name` and `email` as Keycloak passes
them through from NobleID. OJS links its accounts to Keycloak's `sub`, and
Keycloak links that to NobleID's `sub`. Neither link changes if the user
changes their email.

Logout: the plugin sends the user to Keycloak's end-session endpoint, which
ends the Keycloak session. NobleID has no end-session endpoint, so the user
stays signed in at nobleid.org. That is expected.

## Route 2: connect directly (not yet released)

The plugin's `main` branch (changes from August–September 2026) reads the
JWKS with a parser that accepts EC keys, checks `iss`, `aud` and `nonce`, and
sends `state`, `nonce` and PKCE S256. It is not in any release as of
19 October 2026, and we have not run it against NobleID or the mock. When a
release contains it, configure:

| Field | Value |
|---|---|
| Custom OpenID Provider | ticked |
| OpenID Provider URL | `https://id.nobleid.org/.well-known/openid-configuration` |
| Client identifier | `nbcl_your_client_id` |
| Client secret | `nbcs_your_client_secret` |
| Custom login button settings | label `Sign in with NobleID` |

- Register the redirect URL that the settings page shows. Its usual shape is
  `https://journal.example.org/index.php/index/openid/doAuthentication?provider=custom`.
  The `index` segment is the site context, used when the plugin is enabled
  site-wide. The `?provider=custom` part is part of the URL. Register it too.
- The plugin reads the endpoints from discovery, including the authorization
  endpoint on `www.nobleid.org`.
- The plugin asks for `openid profile email`. It sends the client secret in
  the request body (`client_secret_post`), which NobleID accepts.
- NobleID publishes no `end_session_endpoint`, so the plugin's logout is local.

## Profile fields

| NobleID claim | OJS field | Scope |
|---|---|---|
| `given_name` | Given name | `profile` |
| `family_name` | Family name | `profile` |
| `email` | Email | `email` |

Route 1 passes these three on when OJS creates the account. The person fills the rest of their OJS profile.

For an ORCID iD in OJS, use PKP's ORCID plugin. It checks the iD with ORCID itself.

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).

## Sources

- Plugin: https://github.com/pkp/openid (branches `stable-3_3_0`,
  `stable-3_4_0`, `stable-3_5_0` and `main`; see `handler/OpenIDHandler.php`)
- PKP documentation hub: https://docs.pkp.sfu.ca/
- Keycloak default identity provider:
  https://www.keycloak.org/docs/latest/server_admin/index.html#default_identity_provider
