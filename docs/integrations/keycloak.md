# Keycloak (NobleID as an identity provider)

Written for Keycloak 26.x (labels checked in 26.8). Keycloak brokers the
sign-in: users choose NobleID on the Keycloak login page, and your applications
keep talking to Keycloak. This is also the working route for platforms whose
own OIDC client cannot handle NobleID (see [ojs.md](ojs.md)).

**Tested?** Documented from the platform's documentation and source code; not run.

## 1. Add the provider

**Identity providers → Add provider → OpenID Connect v1.0**.

| Field | Value |
|---|---|
| Redirect URI | read-only. Copy it and register it with NobleID. Shape: `https://sso.example.org/realms/<realm>/broker/nobleid/endpoint` |
| Alias | `nobleid` (the alias is part of the redirect URI, so set it before you register) |
| Display name | `NobleID` |
| Use discovery endpoint | On |
| Discovery endpoint | `https://id.nobleid.org/.well-known/openid-configuration` |

Discovery fills in the rest. Check the values:

| Field | Value |
|---|---|
| Authorization URL | `https://www.nobleid.org/oauth/authorize` (www host; correct) |
| Token URL | `https://id.nobleid.org/oauth/token` |
| Logout URL | **empty**. NobleID has no end-session endpoint. |
| User Info URL | `https://id.nobleid.org/oauth/userinfo` |
| Issuer | `https://id.nobleid.org` |
| Validate Signatures | On |
| Use JWKS URL | On |
| JWKS URL | `https://id.nobleid.org/.well-known/jwks.json` |
| Use PKCE | On |
| PKCE Method | `S256` |
| Client authentication | `Client secret sent as HTTP Basic authentication` (`Client secret sent in the request body` also works) |
| Client ID | `nbcl_your_client_id` |
| Client Secret | `nbcs_your_client_secret` (or a vault reference) |

Keycloak verifies NobleID's ES256 ID tokens with the JWKS URL. No algorithm
setting is needed. It downloads keys again when NobleID rotates them.

**Advanced** section:

| Field | Value |
|---|---|
| Pass login_hint | Off |
| Pass max_age | Off |
| Pass current locale | Off |
| Backchannel logout | Off |
| Disable user info | Off (some claims are only in userinfo) |
| Disable nonce | Off |
| Scopes | `openid profile email`. Add `orcid` if you map the ORCID iD. |
| Prompt | Unspecified |
| Accepts prompt=none forward from client | Off unless you rely on silent sign-in |

**Advanced settings**:

| Field | Value |
|---|---|
| Trust Email | On. Keycloak then copies NobleID's `email_verified` (true or false) onto the user, instead of trusting every address. |
| Account linking only | Off |
| Hide on login page | Off, or On if apps send `kc_idp_hint=nobleid` |
| Verify essential claim | Off. See "Only identity-verified users" below for an optional use. |
| First login flow override | `first broker login` (default). See below. |
| Sync mode | `Import`. Use `Force` if you want profile changes on NobleID to update Keycloak on every sign-in. |
| Case-sensitive username | Off |

**Also turn on Realm settings → Login → Verify email.** Trust Email only
copies `email_verified`; without Verify email, Keycloak lets a NobleID user
whose address is not verified straight in, with that address on their
Keycloak account. With it on, Keycloak sends its own confirmation email first.

## 2. Mappers

**Identity providers → nobleid → Mappers → Add mapper**.

**Username**: Keycloak's default username is NobleID's `preferred_username`,
which can collide with a local username and is not guaranteed to stay the
same. Key on `sub` instead:

| Field | Value |
|---|---|
| Mapper type | `Username Template Importer` |
| Template | `${ALIAS}.${CLAIM.sub}` |
| Target | `LOCAL` |
| Sync mode override | `Import` |

Keycloak's link to the NobleID account is always keyed on `sub`. This mapper
only makes the local username stable and collision-free too.

**NobleID claims**. Add an `Attribute Importer` per claim:

| Name | Claim | User Attribute Name | Needs scope |
|---|---|---|---|
| nobleid | `nobleid` | `nobleid` | `openid` |
| orcid | `orcid` | `orcid` | `orcid` (present only if the user connected ORCID by signing in with it) |
| identity_verified | `identity_verified` | `identity_verified` | `profile` |

Set **Sync mode override** to `Force` on these, so a later sign-in updates
them.

By default (Unmanaged Attributes `Disabled`), Keycloak ignores user attributes
that the realm's user profile does not declare. Declare `nobleid`, `orcid` and `identity_verified` under **Realm
settings → User profile → Create attribute**. Let administrators view them and
nobody edit them, so users cannot set them themselves. Alternatively, set
**Realm settings → General → Unmanaged Attributes** to `Only administrators
can view`.

To pass these on to your applications, add a `User Attribute` mapper to a
client scope.

## 3. First sign-in and existing accounts

The default `first broker login` flow is the safe one:

1. **Create User If Unique** creates a new Keycloak user when no user has the
   same email or username.
2. If one does, **Confirm Link Existing Account** asks the user, then **Verify
   Existing Account By Email** (if SMTP is configured) or **By
   Re-authentication** proves they own the existing account before linking.

Do not build a flow with **Automatically Set Existing User** to link by email
silently. It links whatever account has the matching email, without proof.
Keycloak's own documentation warns against it. It is defensible only if every
local account's email was verified by you and you accept NobleID's email
verification as equal to yours. Even then, it cannot check `email_verified`
itself.

## Only identity-verified users (optional)

To admit only NobleID users whose identity check passed, set **Verify
essential claim** On, **Essential claim** `identity_verified`, **Essential
claim value** `true`. This claim comes with the `profile` scope. Do not use
`email_verified` here. Keycloak's essential-claim check does not see standard
claims such as `email_verified`, so every sign-in would be refused.

## Logout

NobleID has no end-session endpoint, so leave **Logout URL** empty and
**Backchannel logout** off. Keycloak logout ends the Keycloak session. The user
stays signed in at nobleid.org.

## Profile fields

| NobleID claim | Keycloak user | Scope |
|---|---|---|
| `given_name` | First name (built in) | `profile` |
| `family_name` | Last name (built in) | `profile` |
| `email` | Email (built in) | `email` |
| `picture` | attribute `picture` | `profile` |
| `website` | attribute `website` | `profile` |
| `orcid` | attribute `orcid` | `orcid` |
| `affiliation.name` | attribute `affiliation` | `affiliations` |

Add an `Attribute Importer` per attribute and declare each attribute, as in section 2. Keycloak reads a nested claim with a dot: `affiliation.name`.

With **Sync mode override** `Force`, Keycloak overwrites the attribute at every sign-in. Use `Import` (first sign-in only) for anything people edit in Keycloak.

Add `orcid` and `affiliations` to the provider's Scopes field, and tick ORCID iD and Affiliations on your app.

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).

## Sources

- OpenID Connect v1.0 identity providers:
  https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker_oidc
- General identity provider configuration (Trust Email, Sync mode, essential claim):
  https://www.keycloak.org/docs/latest/server_admin/index.html#_general-idp-config
- Mappers: https://www.keycloak.org/docs/latest/server_admin/index.html#_mappers
- First login flow: https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker_first_login
- Source: https://github.com/keycloak/keycloak, tag `26.8.0`:
  `docs/documentation/server_admin/topics/identity-broker/`,
  `services/src/main/java/org/keycloak/broker/oidc/mappers/UsernameTemplateMapper.java`,
  `services/src/main/java/org/keycloak/broker/oidc/OIDCIdentityProvider.java`
