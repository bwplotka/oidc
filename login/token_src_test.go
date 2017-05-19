package login

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"testing"

	"github.com/Bplotka/go-httpt"
	"github.com/Bplotka/go-httpt/rt"
	"github.com/Bplotka/oidc"
	"github.com/Bplotka/oidc/login/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
)

const (
	testIssuer       = "https://issuer.org"
	testBindAddress  = "http://127.0.0.1:8393/something"
	testClientID     = "clientID1"
	testClientSecret = "secret1"
)

type TokenSourceTestSuite struct {
	suite.Suite

	testDiscovery oidc.DiscoveryJSON
	testCfg       Config

	s      *httpt.Server
	source oidc.TokenSource

	cache *mocks.TokenCache

	testCtx context.Context
}

func (s *TokenSourceTestSuite) SetupSuite() {
	s.testDiscovery = oidc.DiscoveryJSON{
		Issuer:   testIssuer,
		AuthURL:  testIssuer + "/auth1",
		TokenURL: testIssuer + "/token1",
		JWKSURL:  testIssuer + "/jwks1",
	}

	jsonDiscovery, err := json.Marshal(s.testDiscovery)
	s.NoError(err)

	s.s = httpt.NewServer(s.T())
	s.testCtx = context.WithValue(context.TODO(), oidc.HTTPClientCtxKey, s.s.HTTPClient())

	s.s.On("GET", testIssuer+oidc.DiscoveryEndpoint).
		Push(rt.JSONResponseFunc(http.StatusOK, jsonDiscovery))

	s.testCfg = Config{
		Provider:    testIssuer,
		BindAddress: testBindAddress,

		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail},

		NonceCheck: true,
	}

	s.cache = new(mocks.TokenCache)
	s.source, err = NewOIDCTokenSource(
		s.testCtx,
		log.New(ioutil.Discard, "", 0),
		s.testCfg,
		s.cache)
	s.NoError(err)

}

func (s *TokenSourceTestSuite) SetupTest() {
	s.s.Reset()

	s.source.(*OIDCTokenSource).openBrowser = func(string) error {
		s.T().Errorf("Not mocked")
		return nil
	}
}

func TestTokenSourceTestSuite(t *testing.T) {
	suite.Run(t, &TokenSourceTestSuite{})
}

func (s *TokenSourceTestSuite) Test_CacheEmpty_ObtainNewToken() {
	s.cache.On("Token").Return(nil, nil)


	token, err := s.source.OIDCToken()
	s.NoError(err)

	s.True(token.Valid(s.testCtx, s.source.Verifier()))
}

func TestCallbackURL(t *testing.T) {
	bindURL, err := url.Parse(testBindAddress)
	require.NoError(t, err)
	assert.Equal( t, "127.0.0.1:8393", bindURL.Host)
	assert.Equal(t, "/something/callback", callbackURL(bindURL))
}
