package login

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/Bplotka/oidc"
	"github.com/ghodss/yaml"
)

const defaultKubeConfigPath = "~/.kube/config"

// K8sConfigCache is an cache for OIDC tokens that installs token inside k8s user config directory in `Users:` sections of yaml.
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
// Tested with k8s version 1.6.3
type K8sConfigCache struct {
	loginCfg       Config
	users          map[string]struct{}
	kubeConfigPath string
}

// NewK8sConfigCache constructs cache.
func NewK8sConfigCache(loginCfg Config, k8sUsers ...string) *K8sConfigCache {
	users := map[string]struct{}{}
	// For easier lookup.
	for _, u := range k8sUsers {
		users[u] = struct{}{}
	}
	return &K8sConfigCache{loginCfg: loginCfg, users: users, kubeConfigPath: defaultKubeConfigPath}
}

// K8sConfig holds the information needed to build connect to remote kubernetes clusters as a given user
type K8sConfig struct {
	Users []*K8sUser `json:"users"`
}

// K8sUser hods information about particular user.
type K8sUser struct {
	Name string       `json:"name"`
	User *K8sAuthInfo `json:"user"`
}

// K8sAuthInfo contains information that describes identity information. This is use to tell the kubernetes cluster who you are.
type K8sAuthInfo struct {
	AuthProvider *K8sAuthProviderConfig `json:"auth-provider,omitempty"`
}

// K8sAuthProviderConfig holds the configuration for a specified auth provider.
type K8sAuthProviderConfig struct {
	Name   string            `json:"name"`
	Config map[string]string `json:"config,omitempty"`
}

func extraScopes(cfg Config) []string {
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

func safeFilePath(path string) string {
	if path[:2] == "~/" {
		usr, _ := user.Current()
		dir := usr.HomeDir

		path = filepath.Join(dir, path[2:])
	}
	return path
}

// Token retrieves the tokens from all of the registered users in kube config. It does not check if tokens are valid, however if the OIDC clients
// data are different than configured in login.Config or one of the tokens for all specified k8s users is different - it
// returns an error.
func (c *K8sConfigCache) Token() (*oidc.Token, error) {
	path := safeFilePath(c.kubeConfigPath)

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to get k8s config from file %v. Make sure it is there or change"+
			" permissions. Err: %v", path, err)
	}

	k8sConfig := K8sConfig{}
	err = yaml.Unmarshal(file, &k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal k8s config to expected struct. Err: %v", err)
	}

	token := &oidc.Token{}
	foundUsers := 0
	for _, user := range k8sConfig.Users {
		if _, ok := c.users[user.Name]; !ok {
			continue
		}
		foundUsers++

		if user.User == nil || user.User.AuthProvider == nil || user.User.AuthProvider.Name != "oidc" {
			return nil, fmt.Errorf("No OIDC auth provider section for user %s", user.Name)
		}

		authConfig := user.User.AuthProvider.Config
		// Validates fields with given config.
		if authConfig["client-id"] != c.loginCfg.ClientID {
			return nil, fmt.Errorf("Wrong ClientID for user %s", user.Name)
		}

		if authConfig["client-secret"] != c.loginCfg.ClientSecret {
			return nil, fmt.Errorf("Wrong ClientSecret for user %s", user.Name)
		}

		if !compareStringSlices(strings.Split(authConfig["extra-scopes"], ","), extraScopes(c.loginCfg)) {
			return nil, fmt.Errorf("Extra scopes does not match for user %s", user.Name)
		}

		if authConfig["idp-issuer-url"] != c.loginCfg.Provider {
			return nil, fmt.Errorf("Wrong Issuer Identity Provider for user %s", user.Name)
		}

		if token.RefreshToken == "" {
			token.RefreshToken = authConfig["refresh-token"]
		} else if token.RefreshToken != authConfig["refresh-token"] {
			return nil, fmt.Errorf("Different RefreshTokens among users, found on user %s", user.Name)
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
func (c *K8sConfigCache) SetToken(token *oidc.Token) error {
	path := safeFilePath(c.kubeConfigPath)

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Failed to get k8s config from file %v. Make sure it is there or change"+
			" permissions. Err: %v", path, err)
	}

	k8sConfig := &K8sConfig{}
	err = yaml.Unmarshal(file, k8sConfig)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal k8s config to expected struct. Err: %v", err)
	}

	processedUsers := map[string]struct{}{}
	for i, user := range k8sConfig.Users {
		if _, ok := c.users[user.Name]; !ok {
			continue
		}

		// Always override with correct values.
		validUser := &K8sUser{
			Name: user.Name,
			User: &K8sAuthInfo{
				AuthProvider: &K8sAuthProviderConfig{
					Name: "oidc",
					Config: map[string]string{
						"idp-issuer-url": c.loginCfg.Provider,
						"client-id":      c.loginCfg.ClientID,
						"client-secret":  c.loginCfg.ClientSecret,
						"extra-scopes":   strings.Join(extraScopes(c.loginCfg), ","),

						"refresh-token": token.RefreshToken,
						"id-token":      token.IDToken,
					},
				},
			},
		}
		k8sConfig.Users[i] = validUser
		processedUsers[user.Name] = struct{}{}
	}

	for userName := range c.users {
		if _, ok := processedUsers[userName]; ok {
			continue
		}

		validUser := &K8sUser{
			Name: userName,
			User: &K8sAuthInfo{
				AuthProvider: &K8sAuthProviderConfig{
					Name: "oidc",
					Config: map[string]string{
						"idp-issuer-url": c.loginCfg.Provider,
						"client-id":      c.loginCfg.ClientID,
						"client-secret":  c.loginCfg.ClientSecret,
						"extra-scopes":   strings.Join(extraScopes(c.loginCfg), ","),

						"refresh-token": token.RefreshToken,
						"id-token":      token.IDToken,
					},
				},
			},
		}
		k8sConfig.Users = append(k8sConfig.Users, validUser)
	}

	mergedConfig, err := merge(file, k8sConfig)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, mergedConfig, os.ModePerm)
}

func merge(original []byte, new *K8sConfig) ([]byte, error) {
	marshaled, err := yaml.Marshal(new)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshall k8s config. Err: %v", err)
	}

	newRaw := map[string]interface{}{}
	err = yaml.Unmarshal(marshaled, &newRaw)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal k8s config from marshalled version. Err: %v", err)
	}

	originalRaw := map[string]interface{}{}
	err = yaml.Unmarshal(original, &originalRaw)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal k8s config from file. Err: %v", err)
	}

	// Merge these two.
	for key := range newRaw {
		originalRaw[key] = newRaw[key]
	}

	merged, err := yaml.Marshal(originalRaw)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshall merged k8s config. Err: %v", err)
	}
	return merged, nil
}
