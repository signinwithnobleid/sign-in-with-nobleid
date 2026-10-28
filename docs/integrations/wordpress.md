# WordPress

Uses the **OpenID Connect Generic Client** plugin (slug
`daggerhart-openid-connect-generic`). Written for plugin version **3.11.x**
(3.11.3 checked). Older versions behave differently around ID token
verification; update first.

**Tested?** The plugin's exact request shape (its authorize URL format, a
`client_secret_post` token request with its extra `scope` parameter, no PKCE,
no nonce, ID token checked against the JWKS with a configured issuer,
userinfo with a Bearer header) is exercised against the local mock by
`test/wordpress.test.mjs`. The plugin itself (PHP inside WordPress) was not
run.

## 1. Register the app on NobleID

At https://www.nobleid.org/dashboard/oauth-apps create a **confidential**
app with this redirect URI, exactly (replace the host with yours):

```
https://YOUR-SITE/wp-admin/admin-ajax.php?action=openid-connect-authorize
```

If you enable the plugin's **Alternate Redirect URI** option, the redirect
URI becomes `https://YOUR-SITE/openid-connect-authorize` instead. Copy the
value the plugin's settings page shows and register that.

## 2. Plugin settings (Settings → OpenID Connect Client)

| Field | Value |
|---|---|
| Login Type | `OpenID Connect button on login form` |
| Client ID | `nbcl_your_client_id` |
| Client Secret Key | `nbcs_your_client_secret` (or define it in `wp-config.php`, see below) |
| OpenID Scope | `openid email profile` |
| Login Endpoint URL | `https://www.nobleid.org/oauth/authorize` |
| Userinfo Endpoint URL | `https://id.nobleid.org/oauth/userinfo` |
| Token Validation Endpoint URL | `https://id.nobleid.org/oauth/token` |
| End Session Endpoint URL | **leave empty** (NobleID has none) |
| JWKS URI | `https://id.nobleid.org/.well-known/jwks.json` |
| Issuer | `https://id.nobleid.org` |
| ACR values | leave empty |
| Identity Key | `sub` |
| Nickname Key | `preferred_username` |
| Email Formatting | `{email}` |
| Display Name Formatting | `{name}` |
| Identify with User Name | unticked |
| Enable Refresh Token | unticked (the scope above does not ask for `offline_access`) |
| Disable SSL Verify | **unticked** |
| Allow Internal IDP | unticked |
| Link Existing Users | off (see below) |
| Create user if does not exist | your choice |

**Set the Issuer field.** The login endpoint is on `www.nobleid.org`, but the
issuer is `https://id.nobleid.org`. If the Issuer field is empty, the plugin
derives the issuer from the login endpoint's host and every ID token fails
validation.

**Set the JWKS URI.** With a JWKS URI, the plugin (3.11.x) verifies the ID
token signature, `aud` and `iss`. Without one it decodes the ID token without
verifying it and logs a security warning. Do not run without it.

The plugin's discovery import also works with
`https://id.nobleid.org/.well-known/openid-configuration`; check afterwards
that the Issuer and JWKS fields are filled and the end-session field is
empty.

To keep the secret out of the database, define it in `wp-config.php`:

```php
define( 'OIDC_CLIENT_ID', getenv( 'NOBLEID_CLIENT_ID' ) );
define( 'OIDC_CLIENT_SECRET', getenv( 'NOBLEID_CLIENT_SECRET' ) );
```

## 3. Linking existing WordPress users

With **Link Existing Users** ticked, the plugin matches an existing account
by email address (or by username, with **Identify with User Name**).
NobleID releases `email_verified`, but the plugin does not check it before
linking, so someone could put an administrator's address on a NobleID account
and sign in as that administrator. **Keep it unticked** and link existing
accounts by hand.

The plugin always records the NobleID `sub` on the WordPress user and finds
returning users by it, whatever the Identity Key. The Identity Key only picks
the username for new accounts: `sub` is unique and never changes;
`preferred_username` reads better but can change and can collide with an
existing username.

## What the plugin does and does not do

- Confidential client with `client_secret_post`. No PKCE and no nonce:
  NobleID allows both omissions for confidential clients. It does use
  `state`.
- It sends an extra `scope` parameter on the token request. NobleID ignores
  `scope` on the code exchange, as the local mock does.
- It does not check the `iss` response parameter (RFC 9207). The ID token's
  `iss` is checked when the Issuer and JWKS fields are set.
- Logout signs the person out of WordPress only. NobleID has no end-session
  endpoint and the plugin does not revoke the token; access tokens expire
  after 15 minutes.

Sources: plugin source (version 3.11.3, `includes/openid-connect-generic-client.php`,
`includes/openid-connect-generic-jwt-validator.php`,
`includes/openid-connect-generic-settings-page.php`), https://wordpress.org/plugins/daggerhart-openid-connect-generic/

## Profile fields

| NobleID claim | WordPress field | Scope |
|---|---|---|
| `given_name` | First Name | `profile` |
| `family_name` | Last Name | `profile` |
| `preferred_username` | Nickname (Nickname Key) | `profile` |
| `name` | Display name (Display Name Formatting `{name}`) | `profile` |
| `email` | Email (Email Formatting `{email}`) | `email` |
| `website` | Website, with the code below | `profile` |
| `orcid` | A user meta field, with the code below | `orcid` |

The plugin fills the first five when it creates the account. On each later sign-in it calls the `openid-connect-generic-update-user-using-current-claim` action with the claims, so a small plugin can fill what is still empty:

```php
<?php
/*
 * Plugin Name: NobleID profile fields
 * Description: Fills empty profile fields from Sign in with NobleID. Never overwrites what the person edited.
 */
add_action( 'openid-connect-generic-update-user-using-current-claim', function ( $user, $claims ) {
    if ( empty( $user->user_url ) && ! empty( $claims['website'] ) ) {
        wp_update_user( array( 'ID' => $user->ID, 'user_url' => esc_url_raw( $claims['website'] ) ) );
    }
    // Sent only when the person proved the iD by signing in to ORCID.
    if ( ! empty( $claims['orcid'] ) && ! empty( $claims['orcid_verified'] ) && ! get_user_meta( $user->ID, 'orcid', true ) ) {
        update_user_meta( $user->ID, 'orcid', esc_url_raw( $claims['orcid'] ) );
    }
}, 10, 2 );
```

For `orcid`, add `orcid` to the plugin's OpenID Scope field and tick ORCID iD on your app.

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).
