# Go

Helper: [`packages/go`](../../packages/go/README.md) (module
`nobleid.org/signin`, not yet published: use a `replace` directive), over
`github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`. Example:
[`examples/go-nethttp`](../../examples/go-nethttp/README.md).

```go
client, err := nobleid.New(ctx, nobleid.Config{
	ClientID: os.Getenv("CLIENT_ID"), ClientSecret: os.Getenv("CLIENT_SECRET"),
	RedirectURL: os.Getenv("REDIRECT_URI"),
	Scopes: []string{"openid", "profile", "email"},
})
authURL, tx := client.StartSignIn()                       // keep tx server-side
res, err := client.FinishSignIn(ctx, r.URL.Query(), tx)   // state → iss → error → code → ID token
info, err := client.UserInfo(ctx, res.Tokens.AccessToken, res.Claims.Subject)
```

Using the libraries directly:

- `provider.Verifier(&oidc.Config{ClientID: id, SupportedSigningAlgs: []string{oidc.ES256}})`.
- PKCE: `oauth2.GenerateVerifier()`, `oauth2.S256ChallengeOption(v)`, `oauth2.VerifierOption(v)`.
- Set `Endpoint.AuthStyle` explicitly (`oauth2.AuthStyleInHeader`); do not let x/oauth2 probe.
- go-oidc checks neither the `iss` response parameter nor the `nonce`: check both.
- x/oauth2 has no revocation: post to `revocation_endpoint` yourself.
