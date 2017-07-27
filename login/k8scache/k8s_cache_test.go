package k8s

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/Bplotka/oidc"
	"github.com/Bplotka/oidc/login"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testProvider = "https://example.org"
)

func TestK8sCache_Token(t *testing.T) {
	loginCfg := login.OIDCConfig{
		ClientID:     "ID1",
		ClientSecret: "secret1",
		Scopes: []string{
			oidc.ScopeOpenID,
			oidc.ScopeProfile,
			oidc.ScopeEmail,
			oidc.ScopeOfflineAccess,
			"groups",
		},
		Provider: testProvider,
	}

	cache := NewCache(
		"",
		loginCfg,
		"cluster1-access",
		"cluster2-access",
	)

	test := func(configPath string, expectedErr string, expectedRefreshToken string) {
		t.Logf("Testing %s", configPath)

		cache.kubeConfigPath = configPath
		token, err := cache.Token()
		if expectedErr != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), expectedErr)
		} else {
			require.NoError(t, err)
			assert.Equal(t, expectedRefreshToken, token.RefreshToken)
		}
	}

	for _, c := range []struct {
		configPath           string
		expectedErrMsg       string
		expectedRefreshToken string
	}{
		{
			configPath:     "test-data/no_auth_config.yaml",
			expectedErrMsg: "No OIDC auth provider section for user cluster2-access",
		},
		{
			configPath:     "test-data/wrong_clientid_config.yaml",
			expectedErrMsg: "Wrong ClientID for user cluster2-access",
		},
		{
			configPath:     "test-data/wrong_clientsecret_config.yaml",
			expectedErrMsg: "Wrong ClientSecret for user cluster2-access",
		},
		{
			configPath:     "test-data/wrong_scopes_config.yaml",
			expectedErrMsg: "Extra scopes does not match for user cluster2-access",
		},
		{
			configPath:     "test-data/wrong_idp_config.yaml",
			expectedErrMsg: "Wrong Issuer Identity Provider for user cluster2-access",
		},
		{
			configPath:     "test-data/diff_refreshtoken_config.yaml",
			expectedErrMsg: "Different RefreshTokens among users, found on user ",
		},
		{
			configPath:     "test-data/not_all_users_config.yaml",
			expectedErrMsg: "Failed to find all of the users. Found 1, need 2",
		},
		{
			configPath:           "test-data/ok_config.yaml",
			expectedRefreshToken: "refresh_token1",
		},
	} {
		test(c.configPath, c.expectedErrMsg, c.expectedRefreshToken)
	}
}

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

func TestK8sCache_SaveToken(t *testing.T) {
	loginCfg := login.OIDCConfig{
		ClientID:     "ID1",
		ClientSecret: "secret1",
		Scopes: []string{
			oidc.ScopeOpenID,
			oidc.ScopeEmail,
			oidc.ScopeProfile,
			oidc.ScopeOfflineAccess,
			"groups",
		},
		Provider: testProvider,
	}

	cache := NewCache(
		"",
		loginCfg,
		"cluster1-access",
		"cluster2-access",
	)

	// Test that all token can be applied to all types of existing configuration.
	// It also makes sure that not relevant users are not overridden.
	test := func(inputCfgPath string) {
		t.Logf("Testing %s", inputCfgPath)
		cache.kubeConfigPath = "test-data/tmp-" + rand128Bits()

		err := copyFileContents(inputCfgPath, cache.kubeConfigPath)
		require.NoError(t, err)

		defer os.Remove(cache.kubeConfigPath)
		token := &oidc.Token{
			AccessToken:  "new-token",
			RefreshToken: "new-refresh-token",
			IDToken:      "new-id-token",
		}

		err = cache.SaveToken(token)
		require.NoError(t, err)

		file, err := ioutil.ReadFile(cache.kubeConfigPath)
		require.NoError(t, err)

		expected, err := ioutil.ReadFile("test-data/expected_config.yaml")
		require.NoError(t, err)

		assert.Equal(t, string(expected), string(file))
	}

	for _, inputCfgPath := range []string{
		"test-data/no_auth_config.yaml",
		"test-data/wrong_clientid_config.yaml",
		"test-data/wrong_clientsecret_config.yaml",
		"test-data/wrong_scopes_config.yaml",
		"test-data/wrong_idp_config.yaml",
		"test-data/diff_refreshtoken_config.yaml",
		"test-data/not_all_users_config.yaml",
		"test-data/ok_config.yaml",
	} {
		test(inputCfgPath)
	}
}

func rand128Bits() string {
	buff := make([]byte, 16) // 128 bit random ID.
	if _, err := io.ReadFull(rand.Reader, buff); err != nil {
		panic(err)
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(buff), "=")
}

func TestK8sCache_NewCacheFromUser(t *testing.T) {
	expectedConfig := login.OIDCConfig{
		ClientID:     "ID1",
		ClientSecret: "secret1",
		Scopes: []string{
			oidc.ScopeOpenID,
			oidc.ScopeEmail,
			oidc.ScopeProfile,
			oidc.ScopeOfflineAccess,
			"groups",
		},
		Provider: testProvider,
	}

	cache, err := NewCacheFromUser("test-data/expected_config.yaml", "cluster1-access")
	require.NoError(t, err)

	assert.Equal(t, expectedConfig, cache.Config())
}
