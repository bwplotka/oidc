package login

import (
	"fmt"

	"github.com/ghodss/yaml"
)

// Config is a login configuration. It does not contain oidc configuration.
type Config struct {
	// The base path of local server for OIDC callback. This is the base for redirectURL that all clients MUST register
	// first on the OIDC server. It can point to localhost. E.g http://127.0.0.1 -> redirectURL: http://127.0.0.1/callback
	// This is also and address that HTTP's callback server will listen on. Bind Address must include port. You can specify 0 if your
	// OIDC provider support wildcard on port (almost all server does NOT).
	BindAddress string `json:"address"`
	NonceCheck  bool   `json:"include_nonce"`

	// Useful when you just want to error on wrong/empty refresh token.
	DisableLogin bool `json:"disable_login"`
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

type OIDCConfig struct {
	// Canonical URL for Provider that will be the target issuer that this server authenticate End Users against.
	Provider     string   `json:"provider"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"secret"`
	Scopes       []string `json:"scopes"`
}

// OIDCConfigFromYaml parses config from yaml file.
func OIDCConfigFromYaml(yamlContent []byte) (OIDCConfig, error) {
	var c OIDCConfig
	if err := yaml.Unmarshal(yamlContent, &c); err != nil {
		return OIDCConfig{}, fmt.Errorf("Config: Failed to parse OIDC config file: %v", err)
	}

	// TODO(bplotka) validate cfg.
	return c, nil
}
