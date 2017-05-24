package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bplotka/go-httpt"
	"github.com/Bplotka/go-httpt/rt"
	"github.com/Bplotka/go-jwt"
	"github.com/Bplotka/oidc"
	"github.com/Bplotka/oidc/login/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v2"
)

const (
	testIssuer       = "https://issuer.org"
	testBindAddress  = "http://127.0.0.1:0/something"
	testClientID     = "clientID1"
	testClientSecret = "secret1"
	testNonce        = "nonce1"
)

var (
	testToken = oidc.Token{
		AccessToken:  "access1",
		RefreshToken: "refresh1",
		IDToken:      "idtoken1",
	}
)

type TokenSourceTestSuite struct {
	suite.Suite

	testDiscovery oidc.DiscoveryJSON
	testCfg       Config

	s *httpt.Server

	cache      *mocks.TokenCache
	oidcSource *OIDCTokenSource

	testCtx context.Context
}

func (s *TokenSourceTestSuite) validIDToken(nonce string) (idToken string, jwkSetJSON []byte) {
	builder, err := jwt.NewDefaultBuilder()
	s.Require().NoError(err)

	issuedAt := time.Now()
	token, err := builder.JWS().Claims(&oidc.IDToken{
		Issuer:   testIssuer,
		Nonce:    nonce,
		Expiry:   oidc.NewNumericDate(issuedAt.Add(1 * time.Hour)),
		IssuedAt: oidc.NewNumericDate(issuedAt),
		Subject:  "subject1",
		Audience: []string{testClientID},
	}).CompactSerialize()
	s.Require().NoError(err)

	set := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{builder.PublicJWK()},
	}

	jwkSetJSON, err = json.Marshal(&set)
	s.Require().NoError(err)
	return token, jwkSetJSON
}

func (s *TokenSourceTestSuite) SetupSuite() {
	s.testDiscovery = oidc.DiscoveryJSON{
		Issuer:   testIssuer,
		AuthURL:  testIssuer + "/auth1",
		TokenURL: testIssuer + "/token1",
		JWKSURL:  testIssuer + "/jwks1",
	}

	jsonDiscovery, err := json.Marshal(s.testDiscovery)
	s.Require().NoError(err)

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
	bindURL, err := url.Parse(s.testCfg.BindAddress)
	s.Require().NoError(err)

	oidcClient, err := oidc.NewClient(s.testCtx, s.testCfg.Provider)
	s.Require().NoError(err)

	s.oidcSource = &OIDCTokenSource{
		ctx:    s.testCtx,
		logger: log.New(os.Stdout, "", 0),

		oidcClient:  oidcClient,
		tokenCache:  s.cache,
		cfg:         s.testCfg,
		bindURL:     bindURL,
		openBrowser: openBrowser,

		nonce: testNonce,
	}
}

func (s *TokenSourceTestSuite) SetupTest() {
	s.s.Reset()

	s.oidcSource.openBrowser = func(string) error {
		s.T().Errorf("OpenBrowser Not mocked")
		s.T().FailNow()
		return nil
	}
	s.oidcSource.genRandToken = func() string {
		s.T().Errorf("GenState Not mocked")
		s.T().FailNow()
		return ""
	}

	s.cache = new(mocks.TokenCache)
	s.oidcSource.tokenCache = s.cache
}

func TestTokenSourceTestSuite(t *testing.T) {
	suite.Run(t, &TokenSourceTestSuite{})
}

func TestCallbackURL(t *testing.T) {
	bindURL, err := url.Parse(testBindAddress)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:0", bindURL.Host)
	assert.Equal(t, "/something/callback", callbackURL(bindURL))
}

// Below tests invokes local server - can be flaky due to timing issues. (Server did not have time to be closed).

func (s *TokenSourceTestSuite) Test_CacheOK() {
	idToken, jwkSetJSON := s.validIDToken(s.oidcSource.nonce)
	expectedToken := testToken
	expectedToken.IDToken = idToken
	s.cache.On("Token").Return(&expectedToken, nil)

	s.s.Push(rt.JSONResponseFunc(http.StatusOK, jwkSetJSON))

	token, err := s.oidcSource.OIDCToken()
	s.Require().NoError(err)

	s.Equal(expectedToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Equal(0, s.s.Len())
}

func stripRedirectURL(urlToStrip string) (string, error) {
	// Strip out redirectURL from URL.
	var redirectURL string
	splittedURL := strings.Split(urlToStrip, "&")
	for _, arg := range splittedURL {
		if !strings.HasPrefix(arg, "redirect_uri=") {
			continue
		}
		redirectArg := strings.Split(arg, "=")
		if len(redirectArg) != 2 {
			return "", errors.New("More or less than two args after splitting by `=`")
		}
		var err error
		redirectURL, err = url.QueryUnescape(redirectArg[1])
		if err != nil {
			return "", err
		}
	}
	if redirectURL == "" {
		return "", errors.New("RedirectURL not found in given URL.")
	}
	return redirectURL, nil
}

func (s *TokenSourceTestSuite) callSuccessfulCallback(expectedWord string) func(string) error {
	return func(urlToGet string) error {
		redirectURL, err := stripRedirectURL(urlToGet)
		s.Require().NoError(err)

		s.Equal(fmt.Sprintf(
			"https://issuer.org/auth1?client_id=%s&nonce=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
			testClientID,
			expectedWord,
			url.QueryEscape(redirectURL),
			strings.Join(s.testCfg.Scopes, "+"),
			expectedWord,
		), urlToGet)

		t := oidc.TokenResponse{
			AccessToken:  testToken.AccessToken,
			RefreshToken: testToken.RefreshToken,
			IDToken:      testToken.IDToken,
			TokenType:    "Bearer",
		}
		tokenJSON, err := json.Marshal(t)
		s.Require().NoError(err)

		s.s.Push(rt.JSONResponseFunc(http.StatusOK, tokenJSON))

		req, err := http.NewRequest("GET", fmt.Sprintf(
			"%s?code=%s&state=%s",
			redirectURL,
			"code1",
			expectedWord,
		), nil)
		s.Require().NoError(err)

		u, err := url.Parse(redirectURL)
		s.Require().NoError(err)
		for i := 0; i <= 5; i++ {
			_, err = net.Dial("tcp", u.Host)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		s.Require().NoError(err, "Server should be able to start and listen on provided address.")

		res, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)

		s.Equal(http.StatusOK, res.StatusCode)
		return nil
	}
}

func (s *TokenSourceTestSuite) Test_CacheErr_NewToken_OKCallback() {
	s.cache.On("Token").Return(nil, errors.New("test_err"))
	s.cache.On("SetToken", &testToken).Return(nil)

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}

	s.oidcSource.openBrowser = s.callSuccessfulCallback(expectedWord)
	token, err := s.oidcSource.OIDCToken()
	s.Require().NoError(err)

	s.Equal(testToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Equal(0, s.s.Len())
}

func (s *TokenSourceTestSuite) Test_CacheEmpty_NewToken_OKCallback() {
	s.cache.On("Token").Return(nil, nil)
	s.cache.On("SetToken", &testToken).Return(nil)

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}

	s.oidcSource.openBrowser = s.callSuccessfulCallback(expectedWord)
	token, err := s.oidcSource.OIDCToken()
	s.Require().NoError(err)

	s.Equal(testToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Equal(0, s.s.Len())
}

func (s *TokenSourceTestSuite) Test_IDTokenWrongNonce_RefreshToken_OK() {
	idToken, jwkSetJSON := s.validIDToken("wrongNonce")
	invalidToken := testToken
	invalidToken.IDToken = idToken
	s.cache.On("Token").Return(&invalidToken, nil)

	idTokenOkNonce, jwkSetJSON2 := s.validIDToken(s.oidcSource.nonce)
	expectedToken := invalidToken
	expectedToken.IDToken = idTokenOkNonce
	s.cache.On("SetToken", &expectedToken).Return(nil)

	// For first verification inside OIDC TokenSource.
	s.s.Push(rt.JSONResponseFunc(http.StatusOK, jwkSetJSON))

	// OK Refresh response.
	t := oidc.TokenResponse{
		AccessToken:  expectedToken.AccessToken,
		RefreshToken: expectedToken.RefreshToken,
		IDToken:      expectedToken.IDToken,
		TokenType:    "Bearer",
	}
	tokenJSON, err := json.Marshal(t)
	s.Require().NoError(err)

	s.s.Push(rt.JSONResponseFunc(http.StatusOK, tokenJSON))

	// For 2th verification inside reuse TokenSource.
	s.s.Push(rt.JSONResponseFunc(http.StatusOK, jwkSetJSON2))

	token, err := s.oidcSource.OIDCToken()
	s.Require().NoError(err)

	s.Equal(expectedToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Equal(0, s.s.Len())
}

func (s *TokenSourceTestSuite) Test_IDTokenWrongNonce_RefreshTokenErr_NewToken_OK() {
	idToken, jwkSetJSON := s.validIDToken("wrongNonce")
	invalidToken := testToken
	invalidToken.IDToken = idToken
	s.cache.On("Token").Return(&invalidToken, nil)
	s.cache.On("SetToken", &testToken).Return(nil)

	// For first verification inside OIDC TokenSource.
	s.s.Push(rt.JSONResponseFunc(http.StatusOK, jwkSetJSON))

	s.s.Push(rt.JSONResponseFunc(http.StatusBadRequest, []byte(`{"error": "bad_request"}`)))

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}
	s.oidcSource.openBrowser = s.callSuccessfulCallback(expectedWord)

	token, err := s.oidcSource.OIDCToken()
	s.Require().NoError(err)

	s.Equal(testToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Equal(0, s.s.Len())
}

func (s *TokenSourceTestSuite) Test_CacheEmpty_NewToken_ErrCallback() {
	s.cache.On("Token").Return(nil, nil)

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}

	s.oidcSource.openBrowser = func(urlToGet string) error {
		redirectURL, err := stripRedirectURL(urlToGet)
		s.Require().NoError(err)

		s.Equal(fmt.Sprintf(
			"https://issuer.org/auth1?client_id=%s&nonce=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
			testClientID,
			expectedWord,
			url.QueryEscape(redirectURL),
			strings.Join(s.testCfg.Scopes, "+"),
			expectedWord,
		), urlToGet)

		s.s.Push(rt.JSONResponseFunc(http.StatusGatewayTimeout, []byte(`{"error": "temporary unavailable"}`)))

		req, err := http.NewRequest("GET", fmt.Sprintf(
			"%s?code=%s&state=%s",
			redirectURL,
			"code1",
			expectedWord,
		), nil)
		s.Require().NoError(err)
		
		u, err := url.Parse(redirectURL)
		s.Require().NoError(err)
		for i := 0; i <= 5; i++ {
			_, err = net.Dial("tcp", u.Host)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		s.Require().NoError(err)

		res, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)

		// Still it should be ok.
		s.Equal(http.StatusOK, res.StatusCode)
		return nil
	}

	_, err := s.oidcSource.OIDCToken()
	s.Require().Error(err)
	s.Equal("Failed to obtain new token. Err: oidc: Callback error: oauth2: cannot fetch token: \nResponse: {\"error\": \"temporary unavailable\"}", err.Error())

	s.cache.AssertExpectations(s.T())
	s.Equal(0, s.s.Len())
}
