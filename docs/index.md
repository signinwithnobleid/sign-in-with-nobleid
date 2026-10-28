# Sign in with NobleID

Sign in with NobleID is an OpenID Connect provider for researchers. Beyond a
stable account identifier, it can tell your app things a general-purpose
login cannot: a verified ORCID iD, whether NobleID checked a government-issued
ID, a staff-granted researcher badge, and the person's registered works.

| | |
|---|---|
| Issuer | `https://id.nobleid.org` |
| Discovery | `https://id.nobleid.org/.well-known/openid-configuration` |
| Authorization endpoint | `https://www.nobleid.org/oauth/authorize` (different host) |
| Flow | Authorization code, PKCE S256, `response_mode=query` |
| ID token | ES256 |
| Register an app | https://www.nobleid.org/dashboard/oauth-apps |

## Start here

1. [Register an app](register.md)
2. Pick a [quickstart](quickstart/index.md) or a [platform integration](integrations/README.md)
3. Read [scopes and claims](scopes-and-claims.md) and decide what to ask for
4. Go through the [security checklist](security.md#checklist)

## Reference

- [Tokens](tokens.md): endpoints, lifetimes, refresh, revocation, ID token checks
- [Errors](errors.md), including rate limits
- [Logout](logout.md)
- [Troubleshooting](troubleshooting.md), with settings for common libraries
- [Brand and button guide](brand.md)
- [FAQ](faq.md) and [roadmap](roadmap.md)

## Test without an account

The [local mock](../mock-oidc/README.md) behaves like the provider and runs
with Node alone. Every example in this kit is tested against it.
