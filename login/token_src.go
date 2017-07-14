package login

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/Bplotka/oidc"
)

const callbackPath = "/callback"

//go:generate mockery -name Cache -case underscore -inpkg

// Cache is a Open ID Connect Token caching structure for token and configuration.
// (These are usually stored in the same place.)
type Cache interface {
	SaveToken(token *oidc.Token) error
	Token() (*oidc.Token, error)
	Config() OIDCConfig
}

// OIDCTokenSource implements `oidc.TokenSource` interface to perform oidc-browser-dance.
// It caches fetched tokens in provided TokenCache e.g on disk or in k8s config.
// No mutex is implemented, since it is made to be used with oidc.ReuseTokenSource which already guards it.
type OIDCTokenSource struct {
	ctx    context.Context
	logger *log.Logger
	cfg    Config

	oidcClient *oidc.Client

	// These two are guarded by mutex.
	cache Cache
	nonce string

	bindURL *url.URL

	openBrowser  func(string) error
	genRandToken func() string
}

// NewOIDCTokenSource constructs OIDCTokenSource.
// Note that OIDC configuration can be passed only from cache. This is due the fact that configuration can be stored in cache as well.
func NewOIDCTokenSource(ctx context.Context, logger *log.Logger, cfg Config, cache Cache) (oidc.TokenSource, error) {
	bindURL, err := url.Parse(cfg.BindAddress)
	if err != nil {
		return nil, fmt.Errorf("BindAddress or Issuer are not in a form of URL. Err: %v", err)
	}

	oidcClient, err := oidc.NewClient(ctx, cache.Config().Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC client. Err: %v", err)
	}

	s := &OIDCTokenSource{
		ctx:    ctx,
		logger: logger,
		cfg:    cfg,

		oidcClient: oidcClient,

		cache:        cache,
		bindURL:      bindURL,
		openBrowser:  openBrowser,
		genRandToken: rand128Bits,
	}

	if cfg.NonceCheck {
		s.nonce = rand128Bits()
	}

	return oidc.NewReuseTokenSource(ctx, nil, s), nil
}

func (s *OIDCTokenSource) getOIDCConfig() oidc.Config {
	cfg := s.cache.Config()
	oidcConfig := oidc.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
	}
	return oidcConfig
}

func (s *OIDCTokenSource) getOIDCConfigWithRedirectURL(redirectURL string) oidc.Config {
	cfg := s.cache.Config()
	oidcConfig := oidc.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		RedirectURL:  redirectURL,
	}
	return oidcConfig
}

// OIDCToken is used to obtain new OIDC Token (which include e.g access token, refresh token and id token). It does that by
// using a Refresh Token to obtain new Tokens. If the cached one is still valid it returns it immediately.
func (s *OIDCTokenSource) OIDCToken() (*oidc.Token, error) {
	cachedToken, err := s.cache.Token()
	if err != nil {
		s.logger.Printf("Warn: Failed to get cached token or token is invalid. Err: %v", err)
	} else if cachedToken != nil {
		if cachedToken.Valid(s.ctx, s.Verifier()) {
			// Successfully retrieved a non-expired cached token and only if we have ID token as well.
			return cachedToken, nil
		}

		if cachedToken.RefreshToken != "" {
			// Only if we have refresh token, we can refresh NewIDToken.
			oidcToken, err := s.refreshToken(cachedToken.RefreshToken)
			if err == nil {
				return oidcToken, nil
			}

			// Our refresh token expired.
			s.logger.Printf("Warn: Refresh token expired. Err: %v", err)
		}
	}

	if s.cfg.DisableLogin {
		return nil, errors.New("Failed to obtain new token. Refresh token expired or not specified.")
	}

	// Our request for access token was denied, either we had no RefreshToken, it was invalid or expired.
	newToken, err := s.newToken()
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain new token. Err: %v", err)
	}

	return newToken, nil
}

// Verifier returns verifier for tokens.
func (s *OIDCTokenSource) Verifier() oidc.Verifier {
	return s.oidcClient.Verifier(oidc.VerificationConfig{
		ClientID:   s.cache.Config().ClientID,
		ClaimNonce: s.nonce,
	})
}

func (s *OIDCTokenSource) refreshToken(refreshToken string) (*oidc.Token, error) {
	s.logger.Printf("Debug: Cached token has none or expired ID token or access token. " +
		"Try to refresh access token using refresh token.")

	token, err := oidc.NewTokenRefresher(
		s.ctx,
		s.oidcClient,
		s.getOIDCConfig(),
		refreshToken,
	).OIDCToken()
	if err != nil {
		return nil, err
	}

	_, err = s.Verifier().Verify(s.ctx, token.IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify idToken from provider. Err: %v", err)
	}

	if token.AccessToken == "" {
		return nil, fmt.Errorf("no access token found in token from provider")
	}

	if token.IsAccessTokenExpired() {
		return nil, fmt.Errorf("got expired access token in token from provider")
	}

	err = s.cache.SaveToken(token)
	if err != nil {
		s.logger.Printf("Warn: Cannot cache token. Err: %v", err)
	}

	return token, nil
}

func (s *OIDCTokenSource) prefixPath() string {
	if s.bindURL.Path != "" {
		return s.bindURL.Path
	}
	return "/"
}

func callbackURL(u *url.URL) string {
	return u.Path + callbackPath
}

// newToken starts short-living server that exposes callback handler and opens browser to call Provider auth endpoint
// with response type set to `code`.
// NOTE: this flow will fail on any random request that will fly to callback request. Currently there is no way to differentiate
// it with proper redirect call from Provider.
func (s *OIDCTokenSource) newToken() (*oidc.Token, error) {
	s.logger.Print("Debug: Perfoming auth Code flow to obtain entirely new OIDC token.")

	callbackChan := make(chan *callbackMsg, 1)
	srvClosed := make(chan struct{}, 1)

	state := s.genRandToken()
	nonce := ""
	extra := url.Values{}
	if s.cfg.NonceCheck {
		nonce = s.genRandToken()
		extra.Set("nonce", nonce)
	}

	ctx, cancel := context.WithTimeout(s.ctx, 1*time.Minute)
	defer cancel()

	// TODO(bplotka): Consider having server up for a whole life of tokenSource.
	listener, err := net.Listen("tcp", s.bindURL.Host)
	if err != nil {
		return nil, fmt.Errorf("Failed to Listen for tcp on: %s. Err: %v", s.bindURL.Host, err)
	}

	redirectURL := fmt.Sprintf("http://%s%s", listener.Addr().String(), callbackURL(s.bindURL))

	handler := http.NewServeMux()
	handler.HandleFunc(callbackURL(s.bindURL), callbackHandler(
		ctx,
		s.oidcClient,
		s.getOIDCConfigWithRedirectURL(redirectURL),
		state,
		callbackChan,
	))

	go func() {
		http.Serve(listener, handler)
		srvClosed <- struct{}{}
		cancel()
	}()
	defer func() {
		// Move to shutdown.
		listener.Close()
		close(callbackChan)
	}()

	authURL := s.oidcClient.AuthCodeURL(s.getOIDCConfigWithRedirectURL(redirectURL), state, extra)
	s.logger.Printf("Info: Opening browser to access URL: %s", authURL)
	err = s.openBrowser(authURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: Failed to open browser. Please open this URL in browser: %s Err: %v", authURL, err)
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		cancel()
	}()

	select {
	// TODO(bplotka): What if someone will scan our callback endpoint?
	case msg := <-callbackChan:
		// Give some time for server to finish request.
		time.Sleep(200 * time.Millisecond)
		if msg.err != nil {
			return nil, fmt.Errorf("oidc: Callback error: %v", msg.err)
		}

		s.nonce = nonce
		err = s.cache.SaveToken(msg.token)
		if err != nil {
			s.logger.Printf("Warn: Cannot cache token. Err: %v", err)
		}
		return msg.token, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("oidc Deadline Exceeded: Timed out waiting for token. Please retry the command and open the URL printed above in a browser if it doesn't open automatically")
	}
}
