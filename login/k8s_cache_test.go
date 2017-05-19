package login

import (
	"testing"

	"github.com/Bplotka/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testProvider = "https://example.org"
)

func TestK8sCache_Token_Config(t *testing.T) {
	loginCfg := Config{
		ClientID:     "ID1",
		ClientSecret: "secret1",
		NonceCheck:   true,
		Scopes: []string{
			oidc.ScopeOpenID,
			oidc.ScopeProfile,
			oidc.ScopeEmail,
			"groups",
			oidc.ScopeOfflineAccess,
		},
		Provider: testProvider,
	}

	cache := NewK8sConfigCache(
		loginCfg,
		"cluster1-access",
		"cluster2-access",
	)

	test := func(configPath string, expectedErr string, expectedRefreshToken string) {
		cache.kubeConfigPath = configPath
		token, err := cache.Token()
		if expectedErr != "" {
			require.Error(t, err)
			assert.Equal(t, expectedErr, err.Error())
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
			expectedErrMsg: "Different RefreshTokens among users, found on user cluster2-access",
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
