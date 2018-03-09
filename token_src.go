package oidc

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"net/url"
	"strings"
	"sync"
)

//go:generate mockery -name TokenSource -case underscore
//go:generate mockery -name TokenSourceCtx -case underscore

// TokenSource is anything that can return an oidc token and verifier for token verification.
// Deprecated: use TokenSourceCtx and OIDCTokenCtx method instead.
type TokenSource interface {
	Verifier() Verifier

	// OIDCToken is the same as OIDCTokenCtx, except it uses context from itself.
	// Deprecated: use OIDCTokenCtx method instead.
	OIDCToken() (*Token, error)
}

// TokenSource is anything that can return an oidc token and verifier for token verification.
type TokenSourceCtx interface {
	// OIDCTokenCtx must be safe for concurrent use by multiple goroutines.
	// The returned Token must not be modified.
	OIDCTokenCtx(context.Context) (*Token, error)
	Verifier() Verifier

	// OIDCToken is the same as OIDCTokenCtx, except it uses context from itself.
	// Deprecated: use OIDCTokenCtx method instead.
	OIDCToken() (*Token, error)
}

// ReuseTokenSource is a oidc TokenSource that holds a single token in memory
// and validates its expiry before each call to retrieve it with
// Token. If it's expired, it will be auto-refreshed using the
// new TokenSource.
type ReuseTokenSource struct {
	ctx context.Context // ctx for HTTP requests.

	new TokenSourceCtx // called when t is expired.
	mu  sync.Mutex     // guards t
	t   *Token

	// Optional std logger for debug log. The only case which will be logged is why OIDC token was invalid.
	debugLogger *log.Logger
}

// NewReuseTokenSource returns a TokenSourceCtx which repeatedly returns the
// same token as long as it's valid, starting with t.
// As a second argument it returns reset function that enables to reset h
// When its cached token is invalid, a new token is obtained from source.
// Warning: do not use per request timeouts in ctx. Also use OIDCTokenCtx instead.
func NewReuseTokenSource(ctx context.Context, t *Token, src TokenSourceCtx) (ret *ReuseTokenSource, clearIDToken func()) {
	s := &ReuseTokenSource{
		ctx:         ctx,
		t:           t,
		new:         src,
		debugLogger: log.New(ioutil.Discard, "", 0),
	}
	return s, s.reset
}

// NewReuseTokenSourceWithDebugLogger is the same as NewReuseTokenSource but with logger.
// Warning: do not use per request timeouts in ctx. Also use OIDCTokenCtx instead.
func NewReuseTokenSourceWithDebugLogger(ctx context.Context, debugLogger *log.Logger, t *Token, src TokenSourceCtx) (ret *ReuseTokenSource, clearIDToken func()) {
	s := &ReuseTokenSource{
		ctx:         ctx,
		t:           t,
		new:         src,
		debugLogger: debugLogger,
	}
	return s, s.reset
}

// OIDCToken is the same as OIDCTokenCtx, except it uses context from itself.
// Deprecated: use OIDCTokenCtx method instead.
func (s *ReuseTokenSource) OIDCToken() (*Token, error) {
	return s.OIDCTokenCtx(s.ctx)
}

// OIDCTokenCtx returns the current token if it's still valid, else will
// refresh the current token (using r.Context for HTTP client
// information) and return the new one.
func (s *ReuseTokenSource) OIDCTokenCtx(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t != nil {
		err := s.t.IsValid(ctx, s.Verifier())
		if err == nil {
			return s.t, nil
		}
		s.debugLogger.Printf("reuseTokenSource: Token not valid. Obtaining new one. Cause: %v\n", err)
	} else {
		s.debugLogger.Println("reuseTokenSource: No token to reuse. Obtaining new one")
	}
	t, err := s.new.OIDCTokenCtx(ctx)
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, nil
}

// Verifier returns verifier from underlying token source.
func (s *ReuseTokenSource) Verifier() Verifier {
	return s.new.Verifier()
}

func (s *ReuseTokenSource) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.t = nil
}

// TokenRefresher is a TokenSourceCtx that makes "grant_type"=="refresh_token"
// HTTP requests to renew a token using a RefreshToken.
type TokenRefresher struct {
	ctx context.Context // used to get HTTP requests

	refreshToken string
	client       *Client

	cfg Config
}

// NewTokenRefresher constructs token refresher.
func NewTokenRefresher(ctx context.Context, client *Client, cfg Config, refreshToken string) *TokenRefresher {
	return &TokenRefresher{
		ctx:          ctx,
		refreshToken: refreshToken,
		client:       client,
		cfg:          cfg,
	}
}

// OIDCToken is the same as OIDCTokenCtx, except it uses context from itself.
// Deprecated: use OIDCTokenCtx method instead.
func (tf *TokenRefresher) OIDCToken() (*Token, error) {
	return tf.OIDCTokenCtx(tf.ctx)
}

// OIDCTokenCtx is not safe for concurrent access, as it
// updates the tokenRefresher's refreshToken field.
// It is meant to be used with ReuseTokenSource which
// synchronizes calls to this method with its own mutex.
// NOTE: Returned token is not verified.
func (tf *TokenRefresher) OIDCTokenCtx(ctx context.Context) (*Token, error) {
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

	tk, err := tf.client.token(ctx, tf.cfg.ClientID, tf.cfg.ClientSecret, v)
	if err != nil {
		return nil, err
	}

	if tf.refreshToken != tk.RefreshToken {
		tf.refreshToken = tk.RefreshToken
	}

	return tk, err
}

// Verifier returns verifier for ID Token.
func (tf *TokenRefresher) Verifier() Verifier {
	return tf.client.Verifier(VerificationConfig{ClientID: tf.cfg.ClientID})
}

// StaticTokenSource returns a TokenSourceCtx that always returns the same token.
// Because the provided token t is never refreshed, StaticTokenSource is only
// useful for tokens that never expire.
func StaticTokenSource(t *Token) staticTokenSource {
	return staticTokenSource{t}
}

// staticTokenSource is a TokenSourceCtx that always returns the same Token.
type staticTokenSource struct {
	t *Token
}

// OIDCToken returns saved pointer to token.
func (s staticTokenSource) OIDCToken() (*Token, error) {
	return s.OIDCTokenCtx(nil)
}

// OIDCTokenCtx returns saved pointer to token.
func (s staticTokenSource) OIDCTokenCtx(_ context.Context) (*Token, error) {
	return s.t, nil
}

// Verifier returns nil, since it is static.
func (s staticTokenSource) Verifier() Verifier {
	return nil
}
