package k8s

import (
	"fmt"
	"strings"

	"github.com/bwplotka/oidc"
	"github.com/bwplotka/oidc/login"
	cfg "k8s.io/client-go/tools/clientcmd"
	api "k8s.io/client-go/tools/clientcmd/api"
)

const (
	IssuerUrl                = "idp-issuer-url"
	ClientID                 = "client-id"
	ClientSecret             = "client-secret"
	CertificateAuthority     = "idp-certificate-authority"
	CertificateAuthorityData = "idp-certificate-authority-data"
	ExtraScopes              = "extra-scopes"
	IDToken                  = "id-token"
	RefreshToken             = "refresh-token"

	AccessToken = "access-token"
)

var DefaultKubeConfigPath = cfg.RecommendedHomeFile

// Cache is an cache for OIDC tokens that installs token inside k8s user config directory in `Users:` sections of yaml.
// It is convenient for initial install of token (and possibly refresh-token) for OIDC auth-provider. It stores config following
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
type Cache struct {
	cfg            login.OIDCConfig
	users          map[string]struct{}
	kubeConfigPath string
}

// NewCache constructs cache that installs specified configuration and token under given k8s users inside kubeconfig.
func NewCache(kubeConfigPath string, loginCfg login.OIDCConfig, k8sUsers ...string) *Cache {
	users := map[string]struct{}{}
	// For easier lookup.
	for _, u := range k8sUsers {
		users[u] = struct{}{}
	}
	return &Cache{cfg: loginCfg, users: users, kubeConfigPath: kubeConfigPath}
}

// NewCacheFromUser constructs cache that assumes that required configuration (and optionally refresh token) is already cached
// under given user inside kubeconfig. It returns error if configuration is not there.
func NewCacheFromUser(kubeConfigPath string, k8sUser string) (*Cache, error) {
	users := map[string]struct{}{
		k8sUser: {},
	}

	k8sConfig, err := cfg.LoadFromFile(kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load k8s config from file %v. Make sure it is there or change"+
			" permissions. Err: %v", kubeConfigPath, err)
	}

	loginCfg := login.OIDCConfig{}

	// Try to fill config.
	for name, user := range k8sConfig.AuthInfos {
		if _, ok := users[name]; !ok {
			continue
		}

		if user == nil || user.AuthProvider == nil || user.AuthProvider.Name != "oidc" {
			return nil, fmt.Errorf("No OIDC auth provider section for user %s", name)
		}

		authConfig := user.AuthProvider.Config
		var ok bool

		loginCfg.Provider, ok = authConfig[IssuerUrl]
		if !ok {
			return nil, fmt.Errorf("No IssuerUrl for user %s", name)
		}

		loginCfg.ClientID, ok = authConfig[ClientID]
		if !ok {
			return nil, fmt.Errorf("No ClientID for user %s", name)
		}

		loginCfg.ClientSecret, ok = authConfig[ClientSecret]
		if !ok {
			return nil, fmt.Errorf("No ClientSecret for user %s", name)
		}

		var extraScopes []string
		if scopes, ok := authConfig[ExtraScopes]; ok {
			extraScopes = strings.Split(scopes, ",")
		}
		loginCfg.Scopes = defaultScopesWithExtra(extraScopes)
	}

	return &Cache{cfg: loginCfg, users: users, kubeConfigPath: kubeConfigPath}, nil
}

func extraScopes(configScopes []string) []string {
	var extra []string
	for _, scope := range configScopes {
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

func defaultScopesWithExtra(extraScopes []string) []string {
	scopes := []string{
		oidc.ScopeOpenID,
		oidc.ScopeEmail,
		oidc.ScopeProfile,
		oidc.ScopeOfflineAccess,
	}

	return append(scopes, extraScopes...)
}

// Token retrieves the tokens from all of the registered users in kube config. It does not check if tokens are valid, however if the OIDC clients
// data are different than configured in login.Config or one of the tokens for all specified k8s users is different - it
// returns an error.
func (c *Cache) Token() (*oidc.Token, error) {
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
		if authConfig[ClientID] != c.cfg.ClientID {
			return nil, fmt.Errorf("Wrong ClientID for user %s", name)
		}

		if authConfig[ClientSecret] != c.cfg.ClientSecret {
			return nil, fmt.Errorf("Wrong ClientSecret for user %s", name)
		}

		if !compareStringSlices(strings.Split(authConfig[ExtraScopes], ","), extraScopes(c.cfg.Scopes)) {
			return nil, fmt.Errorf("Extra scopes does not match for user %s", name)
		}

		if authConfig[IssuerUrl] != c.cfg.Provider {
			return nil, fmt.Errorf("Wrong Issuer Identity Provider for user %s", name)
		}

		if token.IDToken == "" {
			token.IDToken = authConfig[IDToken]
		} else if token.IDToken != authConfig[IDToken] {
			// TODO(bwplotka): Allow that?
			return nil, fmt.Errorf("Different IDTokens among users, found on user %s", name)
		}

		if token.AccessToken == "" {
			token.AccessToken = authConfig[AccessToken]
		} else if token.AccessToken != authConfig[AccessToken] {
			// TODO(bwplotka): Allow that?
			return nil, fmt.Errorf("Different AccessTokens among users, found on user %s", name)
		}

		if token.RefreshToken == "" {
			token.RefreshToken = authConfig[RefreshToken]
		} else if token.RefreshToken != authConfig[RefreshToken] {
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

// SaveToken saves token as k8s user's credentials inside k8s config directory. It saves the same thing for ALL specified
// k8s users.
func (c *Cache) SaveToken(token *oidc.Token) error {
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
					IssuerUrl:    c.cfg.Provider,
					ClientID:     c.cfg.ClientID,
					ClientSecret: c.cfg.ClientSecret,
					ExtraScopes:  strings.Join(extraScopes(c.cfg.Scopes), ","),
					RefreshToken: token.RefreshToken,
					IDToken:      token.IDToken,
					AccessToken:  token.AccessToken,
				},
			},
		}

		k8sConfig.AuthInfos[name] = validUAuthInfo
	}

	return cfg.WriteToFile(*k8sConfig, c.kubeConfigPath)
}

// Config returns OIDC configuration.
func (c *Cache) Config() login.OIDCConfig {
	return c.cfg
}
