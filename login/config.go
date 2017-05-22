package login

import (
	"fmt"

	"github.com/ghodss/yaml"
)

// Config is a login configuration. It is similar to standard oidc.Config, except bind field that sets the address
// callback server can listen on.
type Config struct {
	// The base path of local server for OIDC callback. This is the base for redirectURL that all clients MUST register
	// first on the OIDC server. It can point to localhost. E.g http://127.0.0.1 -> redirectURL: http://127.0.0.1/callback
	// This is also and address that HTTP's callback server will listen on. Bind Address must include port. You can specify 0 if your
	// OIDC provider support wildcard on port (almost all server does NOT).
	BindAddress string `yaml:"address"`

	// Canonical URL for Provider that will be the target issuer that this server authenticate End Uusers against.
	Provider string `yaml:"provider"`

	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"secret"`

	Scopes     []string `yaml:"scopes"`
	NonceCheck bool     `yaml:"include_nonce"`
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
