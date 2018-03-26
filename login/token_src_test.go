package login

import (
	"context"
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

	"github.com/Bplotka/oidc"
	"github.com/Bplotka/oidc/testing"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testBindAddress  = "http://127.0.0.1:0/something/callback"
	testSubject      = "subject1"
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

	testOIDCCfg OIDCConfig

	cache      *MockCache
	oidcSource *OIDCTokenSource

	provider *oidc_testing.Provider

	closeSrv func()
}

func (s *TokenSourceTestSuite) SetupSuite() {
	s.provider = &oidc_testing.Provider{}
	s.provider.Setup(s.T())
	s.provider.MockDiscoveryCall()

	s.testOIDCCfg = OIDCConfig{
		Provider: s.provider.IssuerURL,

		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail},
	}

	callbackSrv, closeSrv, err := NewServer(testBindAddress)
	s.Require().NoError(err)

	s.closeSrv = closeSrv

	oldKeySetExpiration := oidc.DefaultKeySetExpiration
	oidc.DefaultKeySetExpiration = 0 * time.Second
	defer func() {
		oidc.DefaultKeySetExpiration = oldKeySetExpiration
	}()
	oidcClient, err := oidc.NewClient(context.Background(), s.testOIDCCfg.Provider)
	s.Require().NoError(err)

	s.oidcSource = &OIDCTokenSource{
		logger: log.New(os.Stdout, "", 0),
		cfg:    Config{NonceCheck: true},

		oidcClient:  oidcClient,
		openBrowser: openBrowser,
		callbackSrv: callbackSrv,
		nonce:       testNonce,
	}
}

func (s *TokenSourceTestSuite) TearDownSuite() {
	s.closeSrv()
}

func (s *TokenSourceTestSuite) SetupTest() {
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

	s.cache = new(MockCache)
	s.cache.On("Config").Return(s.testOIDCCfg)
	s.oidcSource.cache = s.cache
}

func TestTokenSourceTestSuite(t *testing.T) {
	suite.Run(t, &TokenSourceTestSuite{})
}

func (s *TokenSourceTestSuite) Test_CacheOK() {
	idToken, jwkSetJSON := s.provider.NewIDToken(testClientID, testSubject, s.oidcSource.nonce)
	expectedToken := testToken
	expectedToken.IDToken = idToken
	s.cache.On("Token").Return(&expectedToken, nil)

	s.provider.MockPubKeysCall(jwkSetJSON)

	token, err := s.oidcSource.OIDCToken(context.Background())
	s.Require().NoError(err)

	s.Equal(expectedToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Len(s.provider.ExpectedRequests, 0)
}

// stripArgFromURL strips out arg value from URL.
func stripArgFromURL(arg string, urlToStrip string) (string, error) {
	var argValue string
	splittedURL := strings.Split(urlToStrip, "&")
	for _, a := range splittedURL {
		if !strings.HasPrefix(a, arg+"=") {
			continue
		}
		splittedArg := strings.Split(a, "=")
		if len(splittedArg) != 2 {
			return "", errors.New("More or less than two args after splitting by `=`")
		}
		var err error
		argValue, err = url.QueryUnescape(splittedArg[1])
		if err != nil {
			return "", err
		}
	}
	if argValue == "" {
		return "", fmt.Errorf("%s not found in given URL.", arg)
	}
	return argValue, nil
}

func (s *TokenSourceTestSuite) callSuccessfulCallback(expectedWord string) func(string) error {
	s.provider.ExpectedRequests = append(s.provider.ExpectedRequests, oidc_testing.Request{
		Method: "POST",
		URL:    "/token1",
		Handler: func(w http.ResponseWriter) {
			b, err := json.Marshal(testToken)
			require.NoError(s.T(), err)
			w.Header().Add("content-type", "application/json")
			fmt.Fprintln(w, string(b))
		},
	})
	return func(urlToGet string) error {
		redirectURL, err := stripArgFromURL("redirect_uri", urlToGet)
		s.Require().NoError(err)

		s.Equal(fmt.Sprintf(
			"%s/auth1?client_id=%s&nonce=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
			s.provider.IssuerTestSrv.URL,
			testClientID,
			expectedWord,
			url.QueryEscape(redirectURL),
			strings.Join(s.testOIDCCfg.Scopes, "+"),
			expectedWord,
		), urlToGet)

		go func() {
			// Perform actual request in go routine.
			fmt.Printf("Making request to: %v\n", redirectURL)
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
		}()
		return nil
	}
}

func (s *TokenSourceTestSuite) Test_CacheErr_NewToken_OKCallback() {
	s.cache.On("Token").Return(nil, errors.New("test_err"))
	s.cache.On("SaveToken", &testToken).Return(nil)

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}

	s.oidcSource.openBrowser = s.callSuccessfulCallback(expectedWord)
	token, err := s.oidcSource.OIDCToken(context.Background())
	s.Require().NoError(err)

	s.Equal(testToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Len(s.provider.ExpectedRequests, 0)
}

func (s *TokenSourceTestSuite) Test_CacheEmpty_NewToken_OKCallback() {
	s.cache.On("Token").Return(nil, nil)
	s.cache.On("SaveToken", &testToken).Return(nil)

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}

	s.oidcSource.openBrowser = s.callSuccessfulCallback(expectedWord)
	token, err := s.oidcSource.OIDCToken(context.Background())
	s.Require().NoError(err)

	s.Equal(testToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Len(s.provider.ExpectedRequests, 0)
}

func (s *TokenSourceTestSuite) Test_IDTokenWrongNonce_RefreshToken_OK() {
	idToken, jwkSetJSON := s.provider.NewIDToken(testClientID, testSubject, "wrongNonce")
	invalidToken := testToken
	invalidToken.IDToken = idToken
	s.cache.On("Token").Return(&invalidToken, nil)

	idTokenOkNonce, jwkSetJSON2 := s.provider.NewIDToken(testClientID, testSubject, s.oidcSource.nonce)
	expectedToken := invalidToken
	expectedToken.IDToken = idTokenOkNonce
	s.cache.On("SaveToken", &expectedToken).Return(nil)

	// For first verification inside OIDC TokenSource.
	s.provider.MockPubKeysCall(jwkSetJSON)

	// OK Refresh response.
	t := oidc.TokenResponse{
		AccessToken:  expectedToken.AccessToken,
		RefreshToken: expectedToken.RefreshToken,
		IDToken:      expectedToken.IDToken,
		TokenType:    "Bearer",
	}
	tokenJSON, err := json.Marshal(t)
	s.Require().NoError(err)

	s.provider.ExpectedRequests = append(s.provider.ExpectedRequests, oidc_testing.Request{
		Method: "POST",
		URL:    "/token1",
		Handler: func(w http.ResponseWriter) {
			b, err := json.Marshal(tokenJSON)
			require.NoError(s.T(), err)
			fmt.Fprintln(w, string(b))
		},
	})

	// For 2th verification inside reuse TokenSource.
	s.provider.MockPubKeysCall(jwkSetJSON2)

	token, err := s.oidcSource.OIDCToken(context.Background())
	s.Require().NoError(err)

	s.Equal(expectedToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Len(s.provider.ExpectedRequests, 0)
}

func (s *TokenSourceTestSuite) Test_IDTokenWrongNonce_RefreshTokenErr_NewToken_OK() {
	idToken, jwkSetJSON := s.provider.NewIDToken(testClientID, testSubject, "wrongNonce")
	invalidToken := testToken
	invalidToken.IDToken = idToken
	s.cache.On("Token").Return(&invalidToken, nil)
	s.cache.On("SaveToken", &testToken).Return(nil)

	// For first verification inside OIDC TokenSource.
	s.provider.MockPubKeysCall(jwkSetJSON)
	s.provider.ExpectedRequests = append(s.provider.ExpectedRequests, oidc_testing.Request{
		Method: "POST",
		URL:    "/token1",
		Handler: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, `{"error": "bad_request"}`)
		},
	})

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}
	s.oidcSource.openBrowser = s.callSuccessfulCallback(expectedWord)

	token, err := s.oidcSource.OIDCToken(context.Background())
	s.Require().NoError(err)

	s.Equal(testToken, *token)

	s.cache.AssertExpectations(s.T())
	s.Len(s.provider.ExpectedRequests, 0)
}

func (s *TokenSourceTestSuite) Test_CacheEmpty_NewToken_ErrCallback() {
	s.cache.On("Token").Return(nil, nil)
	s.provider.ExpectedRequests = append(s.provider.ExpectedRequests, oidc_testing.Request{
		Method: "POST",
		URL:    "/token1",
		Handler: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	})

	const expectedWord = "secret_token"
	s.oidcSource.genRandToken = func() string {
		return expectedWord
	}

	s.oidcSource.openBrowser = func(urlToGet string) error {
		redirectURL, err := stripArgFromURL("redirect_uri", urlToGet)
		s.Require().NoError(err)

		s.Equal(fmt.Sprintf(
			"%s/auth1?client_id=%s&nonce=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
			s.provider.IssuerTestSrv.URL,
			testClientID,
			expectedWord,
			url.QueryEscape(redirectURL),
			strings.Join(s.testOIDCCfg.Scopes, "+"),
			expectedWord,
		), urlToGet)

		go func() {
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
		}()

		return nil
	}

	_, err := s.oidcSource.OIDCToken(context.Background())
	s.Require().Error(err)
	s.Equal("Failed to obtain new token. Err: oidc: Callback error: oauth2: cannot fetch token: 503 Service Unavailable\nResponse: ", err.Error())

	s.cache.AssertExpectations(s.T())
	s.Len(s.provider.ExpectedRequests, 0)
}

func (s *TokenSourceTestSuite) Test_ClearIDToken_ClearOnlyIDToken() {
	token := oidc.Token{
		AccessToken:  "accessToken",
		IDToken:      "idToken",
		RefreshToken: "refreshToken",
	}
	// Just to satisfy mock.
	s.cache.Config()

	s.cache.On("Token").Return(&token, nil)
	s.cache.On("SaveToken", mock.Anything).Run(func(a mock.Arguments) {
		t, ok := a.Get(0).(*oidc.Token)
		s.Require().True(ok)

		s.Assert().Equal(token.AccessToken, t.AccessToken)
		s.Assert().Empty(t.IDToken)
		s.Assert().Equal(token.RefreshToken, t.RefreshToken)
	}).Return(nil)

	resetDone := true
	clear := s.oidcSource.clearIDToken(func() { resetDone = true })
	s.Require().NoError(clear())

	s.cache.AssertExpectations(s.T())
}
