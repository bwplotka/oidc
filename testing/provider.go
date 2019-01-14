package oidc_testing

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bwplotka/go-jwt"
	"github.com/bwplotka/oidc"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

type Request struct {
	Method  string
	URL     string
	Handler func(http.ResponseWriter)
}

type Provider struct {
	IssuerTestSrv    *httptest.Server
	ExpectedRequests []Request

	t *testing.T
}

func (p *Provider) Setup(t *testing.T) {
	p.t = t

	p.IssuerTestSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.t.Logf("Mock issuer HTTP server received %s %s\n", r.Method, r.URL.EscapedPath())
		if len(p.ExpectedRequests) == 0 {
			p.t.Fatal("Expected received request queue is empty.")
		}
		// Take first expected request, match it with actual request and execute handler.
		expected := p.ExpectedRequests[0]
		p.ExpectedRequests = p.ExpectedRequests[1:]
		if r.Method != expected.Method || r.URL.EscapedPath() != expected.URL {
			p.t.Fatalf("Request does not match expectation %s %s", expected.Method, expected.URL)
		}
		expected.Handler(w)
	}))
}

func (p *Provider) MockDiscoveryCall() {
	p.ExpectedRequests = append(p.ExpectedRequests, Request{
		Method: "GET",
		URL:    oidc.DiscoveryEndpoint,
		Handler: func(w http.ResponseWriter) {
			jsonDiscovery, err := json.Marshal(oidc.DiscoveryJSON{
				Issuer:   p.IssuerTestSrv.URL,
				AuthURL:  p.IssuerTestSrv.URL + "/auth1",
				TokenURL: p.IssuerTestSrv.URL + "/token1",
				JWKSURL:  p.IssuerTestSrv.URL + "/jwks1",
			})
			require.NoError(p.t, err)
			fmt.Fprintln(w, string(jsonDiscovery))
		},
	})
}

func (p *Provider) MockPubKeysCall(jwkSetJSON []byte) {
	p.ExpectedRequests = append(p.ExpectedRequests, Request{
		Method: "GET",
		URL:    "/jwks1",
		Handler: func(w http.ResponseWriter) {
			fmt.Fprintln(w, string(jwkSetJSON))
		},
	})
}

func (p *Provider) MockTokenCall(statusCode int, token string) {
	p.ExpectedRequests = append(p.ExpectedRequests, Request{
		Method: "POST",
		URL:    "/token1",
		Handler: func(w http.ResponseWriter) {
			w.Header().Add("content-type", "application/json")
			w.WriteHeader(statusCode)
			fmt.Fprintln(w, token)
		},
	})
}

// NewIDToken creates new token. Feel free to override basic claims in customClaim for various tests.
// NOTE: It is important that on every call we
func (p *Provider) NewIDToken(clientID string, subject string, nonce string, customClaims ...interface{}) (idToken string, jwkSetJSON []byte) {
	builder, err := jwt.NewDefaultBuilder()
	require.NoError(p.t, err)

	issuedAt := time.Now()
	jwsBasic := builder.JWS().Claims(&oidc.IDToken{
		Issuer:   p.IssuerTestSrv.URL,
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
