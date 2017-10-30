package oidc

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bplotka/go-httpt"
	"github.com/Bplotka/go-httpt/rt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
)

const (
	exampleIssuer = "https://issuer.org"
	zeroTime = 0 * time.Second
)

var testDiscovery = DiscoveryJSON{
	Issuer:        exampleIssuer,
	AuthURL:       exampleIssuer + "/auth1",
	TokenURL:      exampleIssuer + "/token1",
	JWKSURL:       exampleIssuer + "/jwks1",
	UserInfoURL:   exampleIssuer + "/info1",
	RevocationURL: exampleIssuer + "/rev1",
}

type ClientTestSuite struct {
	suite.Suite
	testCtx context.Context

	s      *httpt.Server
	client *Client
}

func (s *ClientTestSuite) SetupSuite() {
	jsonDiscovery, err := json.Marshal(testDiscovery)
	s.NoError(err)

	s.s = httpt.NewServer(s.T())
	s.s.On("GET", exampleIssuer+DiscoveryEndpoint).
		Push(rt.JSONResponseFunc(http.StatusOK, jsonDiscovery))
	s.testCtx = context.WithValue(context.TODO(), HTTPClientCtxKey, s.s.HTTPClient())

	// For test purposes we don't want public keys cache.

	oldKeySetExpiration := DefaultKeySetExpiration
	DefaultKeySetExpiration = zeroTime
	defer func() {
		DefaultKeySetExpiration = oldKeySetExpiration
	}()
	s.client, err = NewClient(context.WithValue(context.TODO(), HTTPClientCtxKey, s.s.HTTPClient()), exampleIssuer)
	s.NoError(err)
}

func (s *ClientTestSuite) SetupTest() {
	s.s.Reset()
}

func TestClientTestSuite(t *testing.T) {
	suite.Run(t, &ClientTestSuite{})
}

func TestTokenResponseExpiry(t *testing.T) {
	expiresIn := 10

	currTime := time.Now()
	tr := TokenResponse{
		ExpiresIn: expirationTime(expiresIn),
	}
	tr.timeNow = func() time.Time {
		return currTime
	}

	assert.Equal(t, currTime.Add(time.Duration(expiresIn)*time.Second), tr.expiry())
}

func TestTokenResponseSetExpiry(t *testing.T) {
	expiresIn := 10
	currTime := time.Now()
	expiry := currTime.Add(time.Duration(expiresIn) * time.Second)

	tr := TokenResponse{}
	tr.timeNow = func() time.Time {
		return currTime
	}
	tr.SetExpiry(expiry)

	assert.Equal(t, expiresIn, int(tr.ExpiresIn))
	assert.Equal(t, expiry, tr.expiry())
}
