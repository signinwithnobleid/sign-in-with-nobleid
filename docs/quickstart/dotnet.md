# .NET (ASP.NET Core)

Example: [`examples/dotnet-aspnetcore`](../../examples/dotnet-aspnetcore/README.md)
(.NET 10, `Microsoft.AspNetCore.Authentication.OpenIdConnect` 10.0.14).

```csharp
.AddOpenIdConnect("nobleid", o =>
{
    o.Authority = "https://id.nobleid.org";
    o.ClientId = config["CLIENT_ID"];
    o.ClientSecret = config["CLIENT_SECRET"];
    o.ResponseType = OpenIdConnectResponseType.Code;
    o.ResponseMode = OpenIdConnectResponseMode.Query;   // default is form_post: not supported
    o.UsePkce = true;
    o.SaveTokens = true;
    o.GetClaimsFromUserInfoEndpoint = true;
    o.MapInboundClaims = false;
    o.CallbackPath = "/signin-oidc";
    o.TokenValidationParameters.ValidAlgorithms = new[] { "ES256" };
    foreach (var s in new[] { "openid", "profile", "email" }) o.Scope.Add(s);
});
```

Also (see the example):

- Send the registered redirect URI from configuration, not one built from the
  request's scheme and `Host`: set `ctx.ProtocolMessage.RedirectUri` in
  `OnRedirectToIdentityProvider` and `ctx.TokenEndpointRequest.RedirectUri`
  in `OnAuthorizationCodeReceived`.
- Mark the session, correlation, nonce and antiforgery cookies Secure
  (`CookieSecurePolicy.Always`) whenever the app is served over https.

- The handler does not check the RFC 9207 `iss` parameter. Check it in
  `OnMessageReceived`; on .NET 8+ the state is already decrypted into
  `context.Properties` by then.
- .NET 9+ switches to pushed authorization requests automatically when
  discovery lists a PAR endpoint, which NobleID's does. The example sets
  `PushedAuthorizationBehavior = Disable` so its tests can inspect the
  authorize URL; the PAR path was not exercised by this kit's .NET test.
- Userinfo-only claims (`affiliations`, `research_interests`,
  `works_count`) are dropped by the default claim actions: keep
  the raw userinfo JSON in `OnUserInformationReceived`.
- A denial arrives in `OnRemoteFailure` as `OpenIdConnectProtocolException`
  with the code in `ex.Data["error"]`.
- Revocation: `configuration.RevocationEndpoint`; post to it yourself. Sign
  out of the cookie scheme only; there is no end-session endpoint.
