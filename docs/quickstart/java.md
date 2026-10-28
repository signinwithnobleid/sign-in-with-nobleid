# Java (Spring Boot)

Example: [`examples/java-spring-boot`](../../examples/java-spring-boot/README.md)
(Spring Boot 4.1, Spring Security 7.1).

```yaml
spring.security.oauth2.client:
  registration.nobleid:
    client-id: ${CLIENT_ID}
    client-secret: ${CLIENT_SECRET}
    client-authentication-method: client_secret_basic
    authorization-grant-type: authorization_code
    redirect-uri: ${REDIRECT_URI}   # exactly as registered, e.g. https://app.example/login/oauth2/code/nobleid
    scope: openid,profile,email
  provider.nobleid:
    issuer-uri: https://id.nobleid.org
```

Set `redirect-uri` from configuration, not `{baseUrl}`: `{baseUrl}` is built
from the request's `Host` and scheme, which a client or a misconfigured proxy
can change.

Spring needs, in code (see the example):

- ES256: an `OidcIdTokenDecoderFactory` bean with
  `setJwsAlgorithmResolver(r -> SignatureAlgorithm.ES256)`.
- PKCE for a confidential client: `OAuth2AuthorizationRequestCustomizers.withPkce()`.
- The RFC 9207 `iss` check: Spring Security does not do it; the example adds
  a filter on the callback that checks state, then `iss`.
- `OidcUserService.setRetrieveUserInfo(r -> true)` to always call userinfo.
- Revocation and forced refresh: done with `RestClient`; Spring has no
  revocation client. Do not configure RP-initiated logout.
