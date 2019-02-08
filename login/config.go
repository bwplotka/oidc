package login

import (
	"fmt"
	"net/url"

	"github.com/ghodss/yaml"
)

// Config is a login configuration. It does not contain oidc configuration.
type Config struct {
	NonceCheck bool `json:"include_nonce"`
	// ExtraAuthRequestParams are extra url params in OIDC auth request.
	// For example with Google OIDC provider https://accounts.google.com, you can use "access_type=offline".
	ExtraAuthRequestParams url.Values `json:"extra_auth_request_params"`
}

// ConfigFromYaml parses config from yaml file.
func ConfigFromYaml(yamlContent []byte) (Config, error) {
	var c Config
	if err := yaml.Unmarshal(yamlContent, &c); err != nil {
		return Config{}, fmt.Errorf("Config: Failed to parse config file: %v", err)
	}

	// TODO(bwplotka) validate cfg.
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

	// TODO(bwplotka) validate cfg.
	return c, nil
}
