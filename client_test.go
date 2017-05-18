package oidc

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bplotka/go-httpt"
	"github.com/Bplotka/go-httpt/rt"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
)

const exampleIssuer = "https://issuer.org"

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

	s      *httpt.Server
	client *Client
}

func (s *ClientTestSuite) SetupSuite() {
	jsonDiscovery, err := json.Marshal(testDiscovery)
	s.NoError(err)

	s.s = httpt.NewServer(s.T())
	s.s.On("GET", exampleIssuer+DiscoveryEndpoint).
		Push(rt.JSONResponseFunc(http.StatusOK, jsonDiscovery))

	s.client, err = NewClient(context.WithValue(context.TODO(), HTTPClientCtxKey, s.s.HTTPClient()), exampleIssuer)
	s.NoError(err)
}

func (s *ClientTestSuite) SetupTest() {
	s.s.Reset()
}

func TestClientTestSuite(t *testing.T) {
	suite.Run(t, &ClientTestSuite{})
}

func (s *ClientTestSuite) Test() {
	// TODO
}