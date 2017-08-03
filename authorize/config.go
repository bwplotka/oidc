package authorize

// Config is an authorize configuration.
// TODO(bplotka): Add proper unmarshaller/marshaller for that data struct.
type Config struct {
	// OIDC issuer url.
	Provider string
	// Expected Audience of the token. For a majority of the cases this is expected to be
	// the ID of the client that initialized the login flow. It may occasionally differ if
	// the provider supports the authorizing party (azp) claim.
	ClientID string
	// Claim name that contains user permissions (sometimes called 'group')
	PermsClaim string

	// Permission condition that will authorize token.
	PermCondition Condition
}
