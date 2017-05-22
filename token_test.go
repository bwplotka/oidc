package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/Bplotka/go-httpt/rt"
	"github.com/Bplotka/go-jwt"
	"gopkg.in/square/go-jose.v2"
)

func (s *ClientTestSuite) validIDToken() (idToken string, jwkSetJSON []byte) {
	builder, err := jwt.NewDefaultBuilder()
	s.NoError(err)

	issuedAt := time.Now()
	token, err := builder.JWS().Claims(&IDToken{
		Issuer:   exampleIssuer,
		Nonce:    "nonce1",
		Expiry:   jwt.NewNumericDate(issuedAt.Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(issuedAt),
		Subject:  "subject1",
		Audience: Audience([]string{"client1"}),
	}).CompactSerialize()
	s.NoError(err)

	set := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{builder.PublicJWK()},
	}

	jwkSetJSON, err = json.Marshal(&set)
	s.NoError(err)
	return token, jwkSetJSON
}

func (s *ClientTestSuite) TestToken_ClaimsWithVerify() {
	idToken, jwkSetJSON := s.validIDToken()

	token := Token{
		AccessToken:       "access1",
		RefreshToken:      "refresh1",
		IDToken:           idToken,
		AccessTokenExpiry: time.Now().Add(1 * time.Hour),
	}

	s.s.Push(rt.JSONResponseFunc(http.StatusOK, jwkSetJSON))
	claims := map[string]interface{}{}
	err := token.Claims(
		s.testCtx,
		s.client.Verifier(VerificationConfig{
			ClientID: "client1",
		}),
		&claims)
	s.NoError(err)

	s.Equal(exampleIssuer, claims["iss"])
	s.Equal("nonce1", claims["nonce"])
	s.Equal("subject1", claims["sub"])

	s.Equal(0, s.s.Len())
}

func (s *ClientTestSuite) TestToken_Valid() {
	idToken, jwkSetJSON := s.validIDToken()

	token := Token{
		AccessToken:       "access1",
		RefreshToken:      "refresh1",
		IDToken:           idToken,
		AccessTokenExpiry: time.Now().Add(1 * time.Hour),
	}

	s.s.Push(rt.JSONResponseFunc(http.StatusOK, jwkSetJSON))
	ok := token.Valid(
		s.testCtx,
		s.client.Verifier(VerificationConfig{
			ClientID: "client1",
		}))
	s.True(ok)

	s.Equal(0, s.s.Len())
}

func (s *ClientTestSuite) TestToken_SetAuthHeader() {
	token := Token{
		AccessToken: "access1",
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1/something", nil)
	token.SetAuthHeader(r)
	s.Equal("Bearer access1", r.Header.Get("Authorization"))
}
