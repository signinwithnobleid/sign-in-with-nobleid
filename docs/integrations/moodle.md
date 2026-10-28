# Moodle

Written for Moodle 4.5 LTS and 5.0–5.3. Field names were checked in the 4.5 and 5.3 source. The
OAuth 2 screens have not changed in this range.

**Tested?** Documented from the platform's documentation and source code; not run.

## How Moodle's OAuth 2 login behaves

- It reads NobleID's discovery document when you enter the **Service base
  URL** and creates the endpoints itself, including the authorization endpoint
  on `www.nobleid.org`.
- It reads the user from the **userinfo** endpoint. It does not use the ID
  token, so ES256 needs no setting.
- It sends `state`. It does not send PKCE or a `nonce`, and Moodle has no PKCE
  option.
- It requires a username and an email from userinfo. A user who unticks
  `email` on NobleID's consent screen cannot sign in.
- It cannot read `email_verified`. Its own **Require email verification**
  option is the safeguard: keep it on.
- There is no logout call to NobleID. Signing out is local.

## 1. Create the service

**Site administration → Server → OAuth 2 services → Create new service:
Custom**.

| Field | Value |
|---|---|
| Name | `NobleID` |
| Client ID | `nbcl_your_client_id` |
| Client secret | `nbcs_your_client_secret` |
| Authenticate token requests via HTTP headers | your choice. On sends `client_secret_basic`, off sends `client_secret_post`. NobleID accepts both. |
| Service base URL | `https://id.nobleid.org` (the issuer. Moodle appends `/.well-known/openid-configuration`.) |
| Logo URL | optional |
| This service will be used | `Login page only` |
| Name displayed on the login page | `Sign in with NobleID` |
| Scopes included in a login request | `openid profile email` |
| Scopes included in a login request for offline access | leave empty (used only for internal services) |
| Additional parameters included in a login request | leave empty |
| Additional parameters included in a login request for offline access | leave empty |
| Login domains | leave empty, or restrict to your institution's email domains |
| Require email verification | **on** |

Save. The services list should show discovery as successful.

## 2. Check the endpoints

Click the **Configure endpoints** icon for the service. Discovery should have
created at least:

| Name | URL |
|---|---|
| `authorization_endpoint` | `https://www.nobleid.org/oauth/authorize` |
| `token_endpoint` | `https://id.nobleid.org/oauth/token` |
| `userinfo_endpoint` | `https://id.nobleid.org/oauth/userinfo` |

There is no `end_session_endpoint`, and none is needed.

## 3. User field mappings

Click the **Configure user field mappings** icon. Discovery creates
`given_name → firstname`, `family_name → lastname`, `email → email`,
`picture → picture` and a few others NobleID does not send. Add one:

| External field name | Internal field name |
|---|---|
| `sub` | `username` |

Without it, Moodle keys the link between NobleID and the Moodle account on the
email address, and a user who changes their NobleID email loses the link.
With it, the link is keyed on `sub`, which never changes. Moodle lowercases the
value, and new accounts get it as their Moodle username.

Optional: to store the ORCID iD, add `orcid` to the login scopes and map
`orcid` to a custom profile field.

## 4. Enable the authentication plugin

**Site administration → Plugins → Authentication → Manage authentication** →
enable **OAuth 2**. The **Sign in with NobleID** button then appears on the
login page.

## Redirect URI

`https://moodle.example.org/admin/oauth2callback.php`. Use your `$CFG->wwwroot`
plus `/admin/oauth2callback.php`, and register exactly that.

## Linking existing accounts

With **Require email verification** on, Moodle does not trust the email from
NobleID on its own:

- If a Moodle account already has that email, Moodle emails a confirmation
  link before connecting the NobleID login to it.
- A new account must confirm its email before first use.

If you turn it off, Moodle asks you to tick "I understand that disabling email
verification can be a security issue". Don't. Moodle cannot see whether NobleID
verified the address.

## Profile fields

| NobleID claim | Moodle field | Scope |
|---|---|---|
| `given_name` | `firstname` | `profile` |
| `family_name` | `lastname` | `profile` |
| `email` | `email` | `email` |
| `picture` | `picture` | `profile` |
| `orcid` | a text custom profile field (optional) | `orcid` |

Discovery creates the first four mappings (section 3).

For the ORCID iD: create a text custom profile field, add `orcid` to the service's login scopes, tick ORCID iD on your app, and map `orcid` to the field.

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).

## Sources

- OAuth 2 services: https://docs.moodle.org/en/OAuth_2_services
- OAuth 2 authentication: https://docs.moodle.org/en/OAuth_2_authentication
- Implementation: https://github.com/moodle/moodle (branch `MOODLE_502_STABLE`):
  `public/lib/classes/oauth2/discovery/openidconnect.php`,
  `public/lib/classes/oauth2/client.php`, `public/auth/oauth2/classes/auth.php`
