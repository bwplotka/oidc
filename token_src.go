package oidc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
)

//go:generate mockery -name TokenSource -case underscore

// TokenSource is anything that can return an oidc token and verifier for token verification.
type TokenSource interface {
	// OIDCToken must be safe for concurrent use by multiple goroutines.
	// The returned Token must not be modified.
	OIDCToken() (*Token, error)
	Verifier() Verifier
}

// ReuseTokenSource is a oidc TokenSource that holds a single token in memory
// and validates its expiry before each call to retrieve it with
// Token. If it's expired, it will be auto-refreshed using the
// new TokenSource.
type ReuseTokenSource struct {
	ctx context.Context // ctx for HTTP requests.

	new TokenSource // called when t is expired.
	mu  sync.Mutex  // guards t
	t   *Token
}

// ReuseTokenSource returns a TokenSource which repeatedly returns the
// same token as long as it's valid, starting with t.
// When its cached token is invalid, a new token is obtained from source.
func NewReuseTokenSource(ctx context.Context, t *Token, src TokenSource) TokenSource {
	return &ReuseTokenSource{
		ctx: ctx,
		t:   t,
		new: src,
	}
}

// OIDCToken returns the current token if it's still valid, else will
// refresh the current token (using r.Context for HTTP client
// information) and return the new one.
func (s *ReuseTokenSource) OIDCToken() (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t != nil && s.t.Valid(s.ctx, s.Verifier()) {
		return s.t, nil
	}
	t, err := s.new.OIDCToken()
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, nil
}

func (s *ReuseTokenSource) Verifier() Verifier {
	return s.new.Verifier()
}

// TokenRefresher is a TokenSource that makes "grant_type"=="refresh_token"
// HTTP requests to renew a token using a RefreshToken.
type TokenRefresher struct {
	ctx context.Context // used to get HTTP requests

	refreshToken string
	client       *Client

	cfg Config
}

func NewTokenRefresher(ctx context.Context, client *Client, cfg Config, refreshToken string) TokenSource {
	return &TokenRefresher{
		ctx:          ctx,
		refreshToken: refreshToken,
		client:       client,
		cfg:          cfg,
	}
}

// WARNING: Token is not safe for concurrent access, as it
// updates the tokenRefresher's refreshToken field.
// It is meant to be used with ReuseTokenSource which
// synchronizes calls to this method with its own mutex.
func (tf *TokenRefresher) OIDCToken() (*Token, error) {
	if tf.refreshToken == "" {
		return nil, errors.New("oauth2: token expired and refresh token is not set")
	}

	v := url.Values{
		"grant_type":    {GrantTypeRefreshToken},
		"refresh_token": {tf.refreshToken},
	}

	if len(tf.cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(tf.cfg.Scopes, " "))
	}

	tk, err := tf.client.token(tf.ctx, tf.cfg.ClientID, tf.cfg.ClientSecret, v)
	if err != nil {
		return nil, err
	}

	if tf.refreshToken != tk.RefreshToken {
		tf.refreshToken = tk.RefreshToken
	}

	return tk, err
}

func (tf *TokenRefresher) Verifier() Verifier {
	return tf.client.Verifier(VerificationConfig{ClientID: tf.cfg.ClientID})
}

// StaticTokenSource returns a TokenSource that always returns the same token.
// Because the provided token t is never refreshed, StaticTokenSource is only
// useful for tokens that never expire.
func StaticTokenSource(t *Token) TokenSource {
	return staticTokenSource{t}
}

// staticTokenSource is a TokenSource that always returns the same Token.
type staticTokenSource struct {
	t *Token
}

func (s staticTokenSource) OIDCToken() (*Token, error) {
	return s.t, nil
}

func (s staticTokenSource) Verifier() Verifier {
	return nil
}
