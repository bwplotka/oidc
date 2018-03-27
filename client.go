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
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// ScopeOpenID is the mandatory scope for all OpenID Connect OAuth2 requests.
	ScopeOpenID        = "openid"
	ScopeOfflineAccess = "offline_access"
	ScopeEmail         = "email"
	ScopeProfile       = "profile"

	GrantTypeAuthCode     = "authorization_code"
	GrantTypeRefreshToken = "refresh_token"
	// GrantTypeServiceAccount is a custom ServiceAccount to support exchanging SA for ID token.
	GrantTypeServiceAccount = "service_account"

	ResponseTypeCode    = "code"     // Authorization Code flow
	ResponseTypeToken   = "token"    // Implicit flow for frontend apps.
	ResponseTypeIDToken = "id_token" // ID Token in url fragment

	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

// HTTPClientCtxKey is Context key which is used to fetch custom HTTP.Client.
// Used to pass special HTTP client (e.g with non-default timeout) or for tests.
var HTTPClientCtxKey struct{}

// doRequest performs HTTP request using our default client or client given by context like this:
//
//     context.WithValue(ctx, oidc.HTTPClientCtxKey, client)
//
func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Create new transport before using it with exactly the same params as default one. Don't use it directly, because
	// we don't want to depend on the default one.
	newTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport: newTransport,
	}
	if c, ok := ctx.Value(HTTPClientCtxKey).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

// Config is client configuration that contains all required client details to communicate with OIDC server.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Client represents an OpenID Connect client.
type Client struct {
	issuer string

	// Raw claims returned by the server on discovery endpoint.
	rawDiscoveryClaims []byte
	discovery          DiscoveryJSON

	keySet keySet

	cfg Config
}

// DiscoveryJSON is structure expected by Discovery endpoint.
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
		keySet:             newCachedKeySet(newRemoteKeySet(p.JWKSURL), DefaultKeySetExpiration, time.Now),
	}, nil
}

// Discovery returns standard discovery fields held by OIDC provider we point to.
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
//    if err := client.Claims(&claims); err != nil {
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

	token, err := tokenSource.OIDCToken(ctx)
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
	return newVerifier(c.keySet, cfg, c.issuer)
}

// Revoke revokes provided token. It can be access token or refresh token. In most, revoking access token will
// revoke refresh token which can be convenient. (IsValid e.g for Google OIDC).
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

// Exchange converts an google service account JSON into a token.
// This is custom Corp Auth additional grant and is not in standard OpenID Connect flow.
func (c *Client) ExchangeServiceAccount(ctx context.Context, cfg Config, googleServiceAccountJSON string, extra ...url.Values) (*Token, error) {
	v := url.Values{
		"grant_type":      {GrantTypeServiceAccount},
		"service_account": {googleServiceAccountJSON},
		"redirect_uri":    {cfg.RedirectURL},
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
func (c *Client) TokenSource(cfg Config, t *Token) TokenSource {
	tkr := &TokenRefresher{
		client: c,
		cfg:    cfg,
	}
	if t != nil {
		tkr.refreshToken = t.RefreshToken
	}
	src, _ := NewReuseTokenSource(t, tkr)
	return src
}

// token fetches token from OIDC token endpoint with provided URL values.
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

	timeNow func() time.Time
}

// SetExpiry sets expiry in form of time in future.
func (r *TokenResponse) SetExpiry(expiry time.Time) {
	if r.timeNow == nil {
		r.timeNow = time.Now
	}
	r.ExpiresIn = expirationTime(expiry.Sub(r.timeNow()).Seconds())
}

func (r *TokenResponse) expiry() time.Time {
	if r.timeNow == nil {
		r.timeNow = time.Now
	}

	if v := r.ExpiresIn; v != 0 {
		return r.timeNow().Add(time.Duration(v) * time.Second)
	}
	return time.Time{}
}

// brokenTokenResponse represents response that is not compliant with OIDC.
type brokenTokenResponse struct {
	Expires expirationTime `json:"expires"` // broken Facebook spelling of expires_in
}

func (r *brokenTokenResponse) expiry() time.Time {
	if v := r.Expires; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return time.Time{}
}

// expirationTime represents Oauth2 valid expires_in field in seconds.
type expirationTime int32

// MarshalJSON unmarshals expiration time from JSON.
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
