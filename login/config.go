package login

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

type Config struct {
	// The base path of local server for OIDC callback.
	// This is the base for redirectURL that all clients MUST register first on the OIDC server. It can point to localhost.
	// E.g http://127.0.0.1 -> redirectURL: http://127.0.0.1/callback
	// This is also and address that HTTP's callback server will listen on.
	Issuer string `yaml:"issuer"`
	// If not specified - issuer address will be used. Bind Address must include port. You can specify 0 if your
	// OIDC provider support wildcard on port (almost all server does NOT).
	BindAddress string `yaml:"address"`

	// Canonical URL for Provider that will be the target issuer that this server authenticate End Uusers against.
	Provider string `yaml:"provider"`

	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"secret"`

	Scopes     []string `yaml:"scopes"`
	NonceCheck bool     `yaml:"include_nonce"`
}

func ConfigFromYaml(yamlContent []byte) (Config, error) {
	var c Config
	if err := yaml.Unmarshal(yamlContent, &c); err != nil {
		return Config{}, fmt.Errorf("Config: Failed to parse config file: %v", err)
	}

	if c.BindAddress == "" {
		c.BindAddress = c.Issuer
	}

	// TODO(bplotka) validate cfg.
	return c, nil
}
