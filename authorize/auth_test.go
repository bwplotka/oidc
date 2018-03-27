package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/Bplotka/oidc"
	"github.com/Bplotka/oidc/testing"
	"github.com/stretchr/testify/require"
)

func TestIsAuthorized(t *testing.T) {
	oldKeySetExpiration := oidc.DefaultKeySetExpiration
	oidc.DefaultKeySetExpiration = 0 * time.Second
	defer func() {
		oidc.DefaultKeySetExpiration = oldKeySetExpiration
	}()

	p := &oidc_testing.Provider{}
	p.Setup(t)
	p.MockDiscoveryCall()

	testConfig := Config{
		Provider:      p.IssuerTestSrv.URL,
		ClientID:      "clientID",
		PermCondition: Contains("secret-permission"),
		PermsClaim:    "perms",
	}
	a, err := New(context.Background(), testConfig)
	require.NoError(t, err)

	// No perms.
	notAuthorizedToken, keys := p.NewIDToken(testConfig.ClientID, "sub1", "")
	p.MockPubKeysCall(keys)
	require.Error(t, a.IsAuthorized(context.Background(), notAuthorizedToken), "token is missing perms - expected to be not authorized.")

	// Perms in wrong claim.
	notAuthorizedToken, keys = p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms2": []string{"secret-permission"},
	})
	p.MockPubKeysCall(keys)
	err = a.IsAuthorized(context.Background(), notAuthorizedToken)
	require.Error(t, err, "token has wrong perms - expected to be not authorized.")

	// Perms claim ok, but type is wrong.
	notAuthorizedToken, keys = p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": "secret-permission",
	})
	p.MockPubKeysCall(keys)
	require.Error(t, a.IsAuthorized(context.Background(), notAuthorizedToken), "token claim has wrong type - expected to be not authorized.")

	// Perms claim ok, but does not have required one.
	notAuthorizedToken, keys = p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": []string{"secret-permission2", "s"},
	})
	p.MockPubKeysCall(keys)
	require.Error(t, a.IsAuthorized(context.Background(), notAuthorizedToken), "token has wrong perms - expected to be not authorized.")

	// Perms totally ok.
	authorizedToken, keys := p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": []string{"secret-permission2", "secret-permission"},
	})
	p.MockPubKeysCall(keys)
	require.NoError(t, a.IsAuthorized(context.Background(), authorizedToken), "token ok - expected to be authorized.")
	require.Len(t, p.ExpectedRequests, 0)
}
func TestIsAuthorizedError(t *testing.T) {
	oldKeySetExpiration := oidc.DefaultKeySetExpiration
	oidc.DefaultKeySetExpiration = 0 * time.Second
	defer func() {
		oidc.DefaultKeySetExpiration = oldKeySetExpiration
	}()

	p := &oidc_testing.Provider{}
	p.Setup(t)
	p.MockDiscoveryCall()

	testConfig := Config{
		Provider:      p.IssuerTestSrv.URL,
		ClientID:      "clientID",
		PermCondition: OR(AND(Contains("perm1"), Contains("perm2")), AND(Contains("perm1"), Contains("perm3"))),
		PermsClaim:    "perms",
	}
	a, err := New(context.Background(), testConfig)
	require.NoError(t, err)

	// perm1 is not enough.
	authorizedToken, keys := p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": []string{"perm1"},
	})
	p.MockPubKeysCall(keys)
	require.EqualError(t, a.IsAuthorized(context.Background(), authorizedToken),
		`Unauthorized. Permissions [perm1] of user "sub1" do not match ((perm1 && perm2) || (perm1 && perm3)).`)
	require.Len(t, p.ExpectedRequests, 0)

	// perm1 and perm3 is ok.
	authorizedToken, keys = p.NewIDToken(testConfig.ClientID, "sub1", "", map[string]interface{}{
		"perms": []string{"perm1", "perm3"},
	})
	p.MockPubKeysCall(keys)
	require.NoError(t, a.IsAuthorized(context.Background(), authorizedToken))
	require.Len(t, p.ExpectedRequests, 0)
}
