package api

const (
	// AuthenticationMethodTLS is the default authentication method for interacting with Incus remotely.
	AuthenticationMethodTLS = "tls"

	// AuthenticationMethodOIDC is a token based authentication method.
	AuthenticationMethodOIDC = "oidc"

	// AuthenticationMethodTailscale identifies callers by their Tailscale identity.
	AuthenticationMethodTailscale = "tailscale"
)
