package k8s

import (
	"fmt"
	"strings"

	"github.com/Bplotka/oidc"
	"github.com/Bplotka/oidc/login"
	cfg "k8s.io/client-go/tools/clientcmd"
	api "k8s.io/client-go/tools/clientcmd/api"
)

var defaultKubeConfigPath = cfg.RecommendedHomeFile

// ConfigCache is an cache for OIDC tokens that installs token inside k8s user config directory in `Users:` sections of yaml.
// It is convenient for initial install of token (possibly refresh-token) for OIDC auth-provider. It stores config following
// set-credentials way of saving credentials:
//
//users:
//- name: <k8sUsers[0]>
//  user:
//    auth-provider:
//      config:
//        client-id: <clientID>
//        client-secret: <clientSecret>
//        extra-scopes: groups
//        id-token: <id-token>
//        idp-issuer-url: <provider>
//        refresh-token: <[optional] refresh-token)
//      name: oidc
//
type ConfigCache struct {
	cfg            login.Config
	users          map[string]struct{}
	kubeConfigPath string
}

// NewConfigCache constructs cache.
func NewConfigCache(loginCfg login.Config, k8sUsers ...string) *ConfigCache {
	users := map[string]struct{}{}
	// For easier lookup.
	for _, u := range k8sUsers {
		users[u] = struct{}{}
	}
	return &ConfigCache{cfg: loginCfg, users: users, kubeConfigPath: defaultKubeConfigPath}
}

func extraScopes(cfg login.Config) []string {
	var extra []string
	for _, scope := range cfg.Scopes {
		// --auth-provider-arg=extra-scopes=( comma separated list of scopes to add to "openid email profile", optional)
		if scope == oidc.ScopeOpenID ||
			scope == oidc.ScopeEmail ||
			scope == oidc.ScopeProfile {
			continue
		}

		// Offline is a special case, it does not make sense to refresh token with this scope.
		if scope == oidc.ScopeOfflineAccess {
			continue
		}

		extra = append(extra, scope)
	}

	return extra
}

// Token retrieves the tokens from all of the registered users in kube config. It does not check if tokens are valid, however if the OIDC clients
// data are different than configured in login.Config or one of the tokens for all specified k8s users is different - it
// returns an error.
func (c *ConfigCache) Token() (*oidc.Token, error) {
	k8sConfig, err := cfg.LoadFromFile(c.kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load k8s config from file %v. Make sure it is there or change"+
			" permissions. Err: %v", c.kubeConfigPath, err)
	}

	token := &oidc.Token{}
	foundUsers := 0
	for name, user := range k8sConfig.AuthInfos {
		if _, ok := c.users[name]; !ok {
			continue
		}
		foundUsers++

		if user == nil || user.AuthProvider == nil || user.AuthProvider.Name != "oidc" {
			return nil, fmt.Errorf("No OIDC auth provider section for user %s", name)
		}

		authConfig := user.AuthProvider.Config
		// Validates fields with given config.
		if authConfig["client-id"] != c.cfg.ClientID {
			return nil, fmt.Errorf("Wrong ClientID for user %s", name)
		}

		if authConfig["client-secret"] != c.cfg.ClientSecret {
			return nil, fmt.Errorf("Wrong ClientSecret for user %s", name)
		}

		if !compareStringSlices(strings.Split(authConfig["extra-scopes"], ","), extraScopes(c.cfg)) {
			return nil, fmt.Errorf("Extra scopes does not match for user %s", name)
		}

		if authConfig["idp-issuer-url"] != c.cfg.Provider {
			return nil, fmt.Errorf("Wrong Issuer Identity Provider for user %s", name)
		}

		if token.RefreshToken == "" {
			token.RefreshToken = authConfig["refresh-token"]
		} else if token.RefreshToken != authConfig["refresh-token"] {
			return nil, fmt.Errorf("Different RefreshTokens among users, found on user %s", name)
		}
	}

	if foundUsers != len(c.users) {
		return nil, fmt.Errorf("Failed to find all of the users. Found %d, need %d", foundUsers, len(c.users))
	}

	return token, nil
}

func compareStringSlices(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y]--
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	if len(diff) == 0 {
		return true
	}
	return false
}

// SetToken saves token as k8s user's credentials inside k8s config directory. It saves the same thing for ALL specified
// k8s users.
func (c *ConfigCache) SetToken(token *oidc.Token) error {
	k8sConfig, err := cfg.LoadFromFile(c.kubeConfigPath)
	if err != nil {
		return fmt.Errorf("Failed to load k8s config from file %v. Make sure it is there or change"+
			" permissions. Err: %v", c.kubeConfigPath, err)
	}

	for name := range c.users {
		validUAuthInfo := &api.AuthInfo{
			AuthProvider: &api.AuthProviderConfig{
				Name: "oidc",
				Config: map[string]string{
					"idp-issuer-url": c.cfg.Provider,
					"client-id":      c.cfg.ClientID,
					"client-secret":  c.cfg.ClientSecret,
					"extra-scopes":   strings.Join(extraScopes(c.cfg), ","),

					"refresh-token": token.RefreshToken,
					"id-token":      token.IDToken,
				},
			},
		}

		k8sConfig.AuthInfos[name] = validUAuthInfo
	}

	return cfg.WriteToFile(*k8sConfig, c.kubeConfigPath)
}

// ClearIDToken removed ID token from config. It is useful when you want to refresh ID token but token did not yet
// expire.
func (c *ConfigCache) ClearIDToken() error {
	k8sConfig, err := cfg.LoadFromFile(c.kubeConfigPath)
	if err != nil {
		return fmt.Errorf("Failed to load k8s config from file %v. Make sure it is there or change"+
			" permissions. Err: %v", c.kubeConfigPath, err)
	}

	for name := range c.users {
		if _, ok := k8sConfig.AuthInfos[name]; !ok {
			continue
		}

		if k8sConfig.AuthInfos[name].AuthProvider == nil {
			continue
		}

		if k8sConfig.AuthInfos[name].AuthProvider.Config == nil {
			continue
		}

		delete(k8sConfig.AuthInfos[name].AuthProvider.Config, "id-token")
	}

	return cfg.WriteToFile(*k8sConfig, c.kubeConfigPath)
}
