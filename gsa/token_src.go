package gsa

import (
	"context"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Bplotka/oidc"
	"github.com/pkg/errors"
)

const (
	exchangeServiceAccountTimeout = 10 * time.Second
)

type OIDCConfig struct {
	Provider     string   `json:"provider"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"secret"`
	Scopes       []string `json:"scopes"`
}

// OIDCTokenSource implements `oidc.TokenSource` interface to perform oidc-browser-dance. Strictly for Google Service Accounts.
type OIDCTokenSource struct {
	logger *log.Logger

	googleServiceAccountJSON []byte
	oidcClient               *oidc.Client
	oidcConfig               oidc.Config

	// These two are guarded by mutex.
	nonce        string
	openBrowser  func(string) error
	genRandToken func() string

	mu sync.Mutex
}

// NewOIDCTokenSource constructs OIDCTokenSource.
// Only JSON files are supported as ServiceAccount files.
// We are making request to Google in constructor (with context ctx) to make sure oidc works.
func NewOIDCTokenSource(ctx context.Context, logger *log.Logger, googleServiceAccountJSON []byte, provider string, cfg OIDCConfig) (src oidc.TokenSource, clearIDToken func() error, err error) {
	oidcClient, err := oidc.NewClient(ctx, provider)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to initialize OIDC client")
	}

	s := &OIDCTokenSource{
		logger: logger,
		googleServiceAccountJSON: googleServiceAccountJSON,
		oidcClient:               oidcClient,
		oidcConfig: oidc.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
		},
	}

	reuseTokenSource, reset := oidc.NewReuseTokenSourceWithDebugLogger(logger, nil, s)

	// Our clear ID token function needs to only reset reuse token.
	return reuseTokenSource, func() error { reset(); return nil }, nil
}

// OIDCToken is used to obtain new OIDC Token (which includes e.g access token and id token).
// No refresh token will be returned, because this is token source is only service Accounts and we don't need login for that anyway.
// No caching is in place. We base for reuse token source to cache valid tokens in memory.
func (s *OIDCTokenSource) OIDCToken(ctx context.Context) (*oidc.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Our request for access token was denied, either we had no RefreshToken, it was invalid or expired.
	newToken, err := s.newToken(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain new token.")
	}

	return newToken, nil
}

// Verifier returns verifier for tokens.
func (s *OIDCTokenSource) Verifier() oidc.Verifier {
	return s.oidcClient.Verifier(oidc.VerificationConfig{
		ClientID:   s.oidcConfig.ClientID,
		ClaimNonce: s.nonce,
	})
}

// newToken calls URL to Provider token endpoint with special grant_type "service_account" to exchange Google SA for ID token.
func (s *OIDCTokenSource) newToken(ctx context.Context) (*oidc.Token, error) {
	s.logger.Print("Debug: Exchanging SA JWT for IDToken")

	ctx, cancel := context.WithTimeout(ctx, exchangeServiceAccountTimeout)
	defer cancel()

	var extra []url.Values
	if len(s.oidcConfig.Scopes) > 0 {
		extra = append(extra, url.Values{
			"scope": {strings.Join(s.oidcConfig.Scopes, " ")},
		})
	}
	return s.oidcClient.ExchangeServiceAccount(ctx, s.oidcConfig, string(s.googleServiceAccountJSON), extra...)
}
