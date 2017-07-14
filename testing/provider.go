package oidc_testing

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bplotka/go-httpt"
	"github.com/Bplotka/go-httpt/rt"
	"github.com/Bplotka/go-jwt"
	"github.com/Bplotka/oidc"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

// Defaults
var (
	TestIssuerURL = "https://issuer.org"
)

func TestDiscovery(testIssuerURL string) oidc.DiscoveryJSON {
	return oidc.DiscoveryJSON{
		Issuer:   testIssuerURL,
		AuthURL:  testIssuerURL + "/auth1",
		TokenURL: testIssuerURL + "/token1",
		JWKSURL:  testIssuerURL + "/jwks1",
	}
}

type Provider struct {
	IssuerURL string
	// Used for initial discovery.
	Discovery oidc.DiscoveryJSON

	t       *testing.T
	srv     *httpt.Server
	testCtx context.Context
}

func (p *Provider) Setup(t *testing.T) {
	p.t = t
	if p.IssuerURL == "" {
		p.IssuerURL = TestIssuerURL
	}

	var empty oidc.DiscoveryJSON
	if p.Discovery == empty {
		p.Discovery = TestDiscovery(p.IssuerURL)
	}

	p.srv = httpt.NewServer(t)
	p.testCtx = context.WithValue(context.TODO(), oidc.HTTPClientCtxKey, p.srv.HTTPClient())
}

// Context that should be used to propagate mocked HTTP client.
func (p *Provider) Context() context.Context {
	return p.testCtx
}

// Mock allows to mock provider response on certain requests.
func (p *Provider) Mock() *httpt.Server {
	return p.srv
}

func (p *Provider) MockDiscoveryCall() {
	jsonDiscovery, err := json.Marshal(p.Discovery)
	require.NoError(p.t, err)

	p.srv.On("GET", p.IssuerURL+oidc.DiscoveryEndpoint).
		Push(rt.JSONResponseFunc(http.StatusOK, jsonDiscovery))
}

func (p *Provider) MockPubKeysCall(jwkSetJSON []byte) {
	p.srv.On("GET", p.Discovery.JWKSURL).
		Push(rt.JSONResponseFunc(http.StatusOK, jwkSetJSON))
}

// NewIDToken creates new token. Feel free to override basic claims in customClaim for various tests.
// NOTE: It is important that on every call we
func (p *Provider) NewIDToken(clientID string, subject string, nonce string, customClaims ...interface{}) (idToken string, jwkSetJSON []byte) {
	builder, err := jwt.NewDefaultBuilder()
	require.NoError(p.t, err)

	issuedAt := time.Now()
	jwsBasic := builder.JWS().Claims(&oidc.IDToken{
		Issuer:   p.IssuerURL,
		Nonce:    nonce,
		Expiry:   oidc.NewNumericDate(issuedAt.Add(1 * time.Hour)),
		IssuedAt: oidc.NewNumericDate(issuedAt),
		Subject:  subject,
		Audience: []string{clientID},
	})

	for _, claims := range customClaims {
		jwsBasic = jwsBasic.Claims(claims)
	}
	token, err := jwsBasic.CompactSerialize()
	require.NoError(p.t, err)

	set := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{builder.PublicJWK()},
	}

	jwkSetJSON, err = json.Marshal(&set)
	require.NoError(p.t, err)
	return token, jwkSetJSON
}
