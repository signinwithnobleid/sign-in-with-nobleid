# FAQ

**Why NobleID instead of a general-purpose social login?**
Because the claims are about the person as a researcher: a verified ORCID iD
(when connected through ORCID's own sign-in), whether NobleID checked a
government-issued ID, a staff-granted researcher badge, their registered
works with ARK identifiers, and how many works NobleID confirmed them as an
author of. See
[what NobleID can and cannot tell you](scopes-and-claims.md#what-nobleid-can-and-cannot-tell-you).

**Which flows are supported?**
The authorization code flow, with PKCE S256, `response_mode=query`. No
implicit flow, no hybrid flow, no device flow, no client credentials.

**Do I need PKCE as a confidential client?**
Not required, but recommended. Public clients must use it.

**Which signing algorithm?**
ES256 only (P-256). Many libraries default to another algorithm; see
[troubleshooting](troubleshooting.md).

**Why is the authorization endpoint on a different host?**
`https://www.nobleid.org/oauth/authorize` is the consent page on the main
site; everything else is on the issuer `https://id.nobleid.org`. Use
discovery and your library handles it.

**Is there a logout / end-session endpoint?**
No. Revoke your tokens and clear your session. See [logout](logout.md).

**Is there a sandbox?**
Use the local mock in [`mock-oidc/`](../mock-oidc/README.md). It mirrors the
provider's protocol behaviour and needs no account.

**Can I get a refresh token?**
Ask for `offline_access`. The person must leave it ticked. It rotates on
every use.

**How long do tokens last?**
Access tokens 15 minutes (read `expires_in`), ID tokens 10 minutes, codes 120
seconds. See [tokens](tokens.md).

**Can I register apps automatically?**
No. There is no dynamic client registration. Use the dashboard.

**Do you support passkeys or SMS?**
No. When a person uses a second factor it is an authenticator-app code; the
ID token's `amr` then contains `"otp"`. There is no `acr`.

**Can my app write to NobleID?**
No. All scopes are read-only.

**Why does my app show an "unverified" warning?**
Every app starts unverified. NobleID may verify an app; changing its name,
logo, domains or redirect URIs removes the badge. See [register](register.md).

**Does the kit handle payments or support links?**
No. Sign in with NobleID has nothing to do with money: no payments, tips,
donations or wallets, in the kit or in the sign-in flow. A sign-in that asks
for money or a payment in NobleID's name is not from NobleID.

**Where do I report a security issue?**
info@nobleid.org. See [SECURITY.md](../SECURITY.md).
