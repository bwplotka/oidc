package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

const (
	// ScopeOpenID is the mandatory scope for all OpenID Connect OAuth2 requests.
	ScopeOpenID        = "openid"
	ScopeOfflineAccess = "offline_access"
	ScopeEmail         = "email"
	ScopeProfile       = "profile"

	GrantTypeAuthCode     = "authorization_code"
	GrantTypeRefreshToken = "refresh_token"

	ResponseTypeCode    = "code"     // Authorization Code flow
	ResponseTypeToken   = "token"    // Implicit flow for frontend apps.
	ResponseTypeIDToken = "id_token" // ID Token in url fragment

	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

var HTTPClientCtxKey struct{}

// doRequest performs HTTP request using Default client or client given by context like this:
//
//     context.WithValue(ctx, oidc.HTTPClientCtxKey, client)
//
func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(HTTPClientCtxKey).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Client represents an OpenID Connect server's configuration.
type Client struct {
	issuer string

	// Raw claims returned by the server on discovery endpoint.
	rawDiscoveryClaims []byte
	discovery          DiscoveryJSON

	remoteKeySet *remoteKeySet

	cfg Config
}

type cachedKeys struct {
	keys   []jose.JSONWebKey
	expiry time.Time
}

type DiscoveryJSON struct {
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
	UserInfoURL   string `json:"userinfo_endpoint"`
	RevocationURL string `json:"revocation_endpoint"`
}

// NewClient uses the OpenID Connect discovery mechanism to construct a Client.
func NewClient(ctx context.Context, issuer string) (*Client, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + DiscoveryEndpoint
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}
	defer resp.Body.Close()
	var p DiscoveryJSON
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}
	if p.Issuer != issuer {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer, p.Issuer)
	}
	return &Client{
		issuer:             p.Issuer,
		discovery:          p,
		rawDiscoveryClaims: body,
		remoteKeySet:       newRemoteKeySet(ctx, p.JWKSURL, time.Now),
	}, nil
}

func (c *Client) Discovery() DiscoveryJSON {
	return c.discovery
}

// Claims unmarshals raw fields returned by the server during discovery.
//
//    var claims struct {
//        ScopesSupported []string `json:"scopes_supported"`
//        ClaimsSupported []string `json:"claims_supported"`
//    }
//
//    if err := provider.Claims(&claims); err != nil {
//        // handle unmarshaling error
//    }
//
// For a list of fields defined by the OpenID Connect spec see:
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (c *Client) Claims(v interface{}) error {
	if c.rawDiscoveryClaims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(c.rawDiscoveryClaims, v)
}

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	claims []byte
}

// Claims unmarshals the raw JSON object claims into the provided object.
func (u *UserInfo) Claims(v interface{}) error {
	if u.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(u.claims, v)
}

// UserInfo uses the token source to query the provider's user info endpoint.
func (c *Client) UserInfo(ctx context.Context, tokenSource TokenSource) (*UserInfo, error) {
	if c.discovery.UserInfoURL == "" {
		return nil, errors.New("oidc: user info endpoint is not supported by this provider")
	}

	req, err := http.NewRequest("GET", c.discovery.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: create GET request: %v", err)
	}

	token, err := tokenSource.OIDCToken()
	if err != nil {
		return nil, fmt.Errorf("oidc: get access token: %v", err)
	}
	token.SetAuthHeader(req)

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	userInfo.claims = body
	return &userInfo, nil
}

// Verifier returns an IDTokenVerifier that uses the provider's key set to verify JWTs.
//
// The returned IDTokenVerifier is tied to the Client's context and its behavior is
// undefined once the Client's context is canceled.
func (c *Client) Verifier(cfg VerificationConfig) *IDTokenVerifier {
	return newVerifier(c.remoteKeySet, cfg, c.issuer)
}

func (c *Client) Revoke(ctx context.Context, cfg Config, token string) error {
	v := url.Values{}
	v.Set("token", token)

	req, err := http.NewRequest("POST", c.discovery.RevocationURL, strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)

	r, err := doRequest(ctx, req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("oidc: cannot revoke token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return fmt.Errorf("oidc: cannot revoke token: %v\nResponse: %s", r.Status, body)
	}
	return nil
}

// AuthCodeURL returns a URL to OIDC provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-zero string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest for more info.
func (c *Client) AuthCodeURL(cfg Config, state string, extra ...url.Values) string {
	var buf bytes.Buffer
	buf.WriteString(c.discovery.AuthURL)
	v := url.Values{
		"response_type": {ResponseTypeCode},
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURL},
	}

	if state != "" {
		v.Set("state", state)
	}

	if len(cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	for _, e := range extra {
		for key := range e {
			v.Set(key, e.Get(key))
		}
	}

	if strings.Contains(c.discovery.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

// Exchange converts an authorization code into a token.
//
// It is used after a resource provider redirects the user back
// to the Redirect URI (the URL obtained from AuthCodeURL).
//
// The HTTP client to use is derived from the context.
// If a client is not provided via the context, http.DefaultClient is used.
//
// The code will be in the *http.Request.FormValue("code"). Before
// calling Exchange, be sure to validate FormValue("state").
func (c *Client) Exchange(ctx context.Context, cfg Config, code string, extra ...url.Values) (*Token, error) {
	v := url.Values{
		"grant_type":   {GrantTypeAuthCode},
		"code":         {code},
		"redirect_uri": {cfg.RedirectURL},
	}

	for _, e := range extra {
		for key := range e {
			v.Set(key, e.Get(key))
		}
	}

	return c.token(ctx, cfg.ClientID, cfg.ClientSecret, v)
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context.
func (c *Client) TokenSource(ctx context.Context, cfg Config, vcfg VerificationConfig, t *Token) TokenSource {
	tkr := &tokenRefresher{
		ctx: ctx,

		client: c,
		cfg:    cfg,
		vCfg:   vcfg,
	}
	if t != nil {
		tkr.refreshToken = t.RefreshToken
	}
	return NewReuseTokenSource(t, tkr)
}

func (c *Client) token(ctx context.Context, clientID string, clientSecret string, v url.Values) (*Token, error) {
	req, err := http.NewRequest("POST", c.discovery.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	r, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	var token *Token
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if content != "application/json" {
		return nil, fmt.Errorf("Wrong response content-type. Expected application/json, got %s", content)
	}

	var tr TokenResponse
	if err = json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}

	var br brokenTokenResponse
	if err = json.Unmarshal(body, &br); err != nil {
		return nil, err
	}

	token = &Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
	}

	token.AccessTokenExpiry = tr.expiry()
	if token.AccessTokenExpiry.IsZero() {
		token.AccessTokenExpiry = br.expiry()
	}

	if token.RefreshToken == "" {
		token.RefreshToken = v.Get("refresh_token")
	}
	return token, nil
}

// TokenResponse is the struct representing the HTTP response from OIDC
// providers returning a token in JSON form.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`

	ExpiresIn    expirationTime `json:"expires_in,omitempty"` // at least PayPal returns string, while most return number
	RefreshToken string         `json:"refresh_token,omitempty"`
	Scope        string         `json:"scope,omitempty"`
}

func (r *TokenResponse) SetExpiry(expiry time.Time) {
	r.ExpiresIn = expirationTime(time.Now().Sub(expiry).Seconds())
}

func (r *TokenResponse) expiry() time.Time {
	if v := r.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return time.Time{}
}

type brokenTokenResponse struct {
	Expires expirationTime `json:"expires"` // broken Facebook spelling of expires_in
}

func (r *brokenTokenResponse) expiry() time.Time {
	if v := r.Expires; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return time.Time{}
}

type expirationTime int32

func (e *expirationTime) MarshalJSON() ([]byte, error) {
	n := json.Number(*e)
	return json.Marshal(n)
}

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	*e = expirationTime(i)
	return nil
}