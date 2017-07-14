package authorize

import (
	"fmt"

	"github.com/ghodss/yaml"
)

// Config is an authorize configuration.
type Config struct {
	// OIDC issuer url.
	Provider string
	// Expected Audience of the token. For a majority of the cases this is expected to be
	// the ID of the client that initialized the login flow. It may occasionally differ if
	// the provider supports the authorizing party (azp) claim.
	ClientID string
	// Claim name that contains user permissions (sometimes called 'group')
	PermsClaim string

	// Permission that is required to authorize user.
	RequiredPerms string
}

// ConfigFromYaml parses config from yaml file.
func ConfigFromYaml(yamlContent []byte) (Config, error) {
	var c Config
	if err := yaml.Unmarshal(yamlContent, &c); err != nil {
		return Config{}, fmt.Errorf("Config: Failed to parse config file: %v", err)
	}

	// TODO(bplotka) validate cfg.
	return c, nil
}
