package authorize_test

import (
	"testing"

	"github.com/Bplotka/oidc/authorize"
	"github.com/Bplotka/oidc/testing"
	"github.com/stretchr/testify/require"
)

func TestIsAuthorized(t *testing.T) {
	p := &oidc_testing.Provider{}
	p.Setup(t)
	p.MockDiscoveryCall()

	testConfig := authorize.Config{
		Provider:      p.IssuerURL,
		ClientID:      "clientID",
		PermCondition: authorize.Contains("secret-permission"),
		PermsClaim:    "perms",
	}
	a, err := authorize.New(p.Context(), testConfig)
	require.NoError(t, err)

	// No perms.
	notAuthorizedToken, keys := p.NewIDToken(testConfig.ClientID, "sub1", "")
	p.MockPubKeysCall(keys)
	require.Error(t, a.IsAuthorized(p.Context(), notAuthorizedToken), "token is missing perms - expected to be not authorized.")

	// Perms in wrong claim.
	notAuthorizedToken, keys = p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms2": []string{"secret-permission"},
	})
	p.MockPubKeysCall(keys)
	require.Error(t, a.IsAuthorized(p.Context(), notAuthorizedToken), "token has wrong perms - expected to be not authorized.")

	// Perms claim ok, but type is wrong.
	notAuthorizedToken, keys = p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": "secret-permission",
	})
	p.MockPubKeysCall(keys)
	require.Error(t, a.IsAuthorized(p.Context(), notAuthorizedToken), "token claim has wrong type - expected to be not authorized.")

	// Perms claim ok, but does not have required one.
	notAuthorizedToken, keys = p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": []string{"secret-permission2", "s"},
	})
	p.MockPubKeysCall(keys)
	require.Error(t, a.IsAuthorized(p.Context(), notAuthorizedToken), "token has wrong perms - expected to be not authorized.")

	// Perms totally ok.
	authorizedToken, keys := p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": []string{"secret-permission2", "secret-permission"},
	})
	p.MockPubKeysCall(keys)
	require.NoError(t, a.IsAuthorized(p.Context(), authorizedToken), "token ok - expected to be authorized.")
}
