module nobleid.org/examples/go-nethttp

go 1.25.0

toolchain go1.26.10

require nobleid.org/signin v0.0.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
)

// nobleid.org/signin is not published yet: build it from this repository.
replace nobleid.org/signin => ../../packages/go
