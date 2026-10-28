# Ruby (Sinatra + OmniAuth)

Example: [`examples/ruby-sinatra`](../../examples/ruby-sinatra/README.md)
(omniauth 2.1.4, omniauth_openid_connect 0.8.0, Ruby 3.2+).

```ruby
use OmniAuth::Builder do
  provider :nobleid,                       # the example's subclass of :openid_connect
    issuer: ENV.fetch("ISSUER", "https://id.nobleid.org"),
    discovery: true,
    response_type: :code,
    pkce: true,
    send_nonce: true,
    client_signing_alg: :ES256,
    client_auth_method: :basic,
    send_scope_to_token_endpoint: false,
    scope: %i[openid profile email],
    callback_path: "/auth/nobleid/callback",
    client_options: {
      identifier: ENV["CLIENT_ID"], secret: ENV["CLIENT_SECRET"],
      redirect_uri: ENV["REDIRECT_URI"],
    }
end
```

**Use the example's strategy subclass, not the plain gem.** In
omniauth_openid_connect 0.8.0:

- the `nonce` and the PKCE `code_verifier` can be taken from the callback's
  query parameters, which defeats both checks against a crafted callback;
- `iss` (RFC 9207) is never checked, `error` is surfaced before `state`, and
  `state` is not compared in constant time;
- the userinfo `sub` is not compared with the ID token's;
- without `client_signing_alg: :ES256` it accepts the algorithm the token
  header names.

The subclass in `nobleid_strategy.rb` fixes each of these. Never enable
`Rack::OAuth2.debug!` or `OpenIDConnect.debug!`: they log tokens. Logout:
revoke at the discovered `revocation_endpoint`; do not use the gem's
end-session redirect.
