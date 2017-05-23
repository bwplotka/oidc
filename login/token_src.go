package login

import (
	"context"
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

func callbackURL(u *url.URL) string {
	return u.Path + callbackPath
}

//go:generate mockery -name TokenCache -case underscore

// TokenCache is a Open ID Connect Token caching structure.
type TokenCache interface {
	SetToken(token *oidc.Token) error
	Token() (*oidc.Token, error)
}

// OIDCTokenSource implements `oidc.TokenSource` interface to perform oidc-browser-dance.
// It caches fetched tokens in provided TokenCache e.g on disk or in k8s config.
// No mutex is implemented, since it is made to be used with oidc.ReuseTokenSource which already guards it.
type OIDCTokenSource struct {
	ctx    context.Context
	logger *log.Logger

	oidcClient *oidc.Client
	oidcConfig oidc.Config

	// These two are guarded by mutex.
	tokenCache TokenCache
	nonce      string

	bindURL *url.URL
	cfg     Config

	openBrowser  func(string) error
	genRandToken func() string
}

// NewOIDCTokenSource constructs OIDCTokenSource.
func NewOIDCTokenSource(ctx context.Context, logger *log.Logger, cfg Config, tokenCache TokenCache) (oidc.TokenSource, error) {
	bindURL, err := url.Parse(cfg.BindAddress)
	if err != nil {
		return nil, fmt.Errorf("BindAddress or Issuer are not in a form of URL. Err: %v", err)
	}

	oidcConfig := oidc.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  bindURL.String() + callbackPath,
		Scopes:       cfg.Scopes,
	}

	oidcClient, err := oidc.NewClient(ctx, cfg.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC client. Err: %v", err)
	}

	s := &OIDCTokenSource{
		ctx:    ctx,
		logger: logger,

		oidcClient: oidcClient,
		oidcConfig: oidcConfig,

		tokenCache:   tokenCache,
		cfg:          cfg,
		bindURL:      bindURL,
		openBrowser:  openBrowser,
		genRandToken: rand128Bits,
	}

	if cfg.NonceCheck {
		s.nonce = rand128Bits()
	}

	return oidc.NewReuseTokenSource(ctx, nil, s), nil
}

// OIDCToken is used to obtain new OIDC Token (which include e.g access token, refresh token and id token). It does that by
// using a Refresh Token to obtain new Tokens. If the cached one is still valid it returns it immediately.
func (s *OIDCTokenSource) OIDCToken() (*oidc.Token, error) {
	cachedToken, err := s.tokenCache.Token()
	if err != nil {
		s.logger.Printf("Error: Failed to get cached token. Caching might be broken. Err: %v", err)
	} else if cachedToken != nil {
		if cachedToken.Valid(s.ctx, s.Verifier()) {
			// Successfully retrieved a non-expired cached token and only if we have ID token as well.
			return cachedToken, nil
		}

		if cachedToken.RefreshToken != "" {
			// Only if we have refresh token, we can refresh IDToken.
			oidcToken, err := s.refreshToken(cachedToken.RefreshToken)
			if err == nil {
				return oidcToken, nil
			}

			// Our refresh token expired.
			s.logger.Printf("Warn: Refresh token expired. Err: %v", err)
		}
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
		ClientID:   s.oidcConfig.ClientID,
		ClaimNonce: s.nonce,
	})
}

func (s *OIDCTokenSource) refreshToken(refreshToken string) (*oidc.Token, error) {
	s.logger.Printf("Debug: Cached token has none or expired ID token or access token. " +
		"Try to refresh access token using refresh token.")

	token, err := oidc.NewTokenRefresher(
		s.ctx,
		s.oidcClient,
		s.oidcConfig,
		refreshToken,
	).OIDCToken()
	if err != nil {
		return nil, err
	}

	if !token.Valid(s.ctx, s.Verifier()) {
		return nil, fmt.Errorf("got invalid idToken from provider")
	}

	err = s.tokenCache.SetToken(token)
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
	handler := http.NewServeMux()
	handler.HandleFunc(callbackURL(s.bindURL), callbackHandler(
		ctx,
		s.oidcClient,
		s.oidcConfig,
		state,
		callbackChan,
	))

	listener, err := net.Listen("tcp", s.bindURL.Host)
	if err != nil {
		return nil, fmt.Errorf("Failed to Listen for tcp on: %s. Err: %v", s.bindURL.Host, err)
	}
	go func() {
		err := http.Serve(listener, handler)
		if err != nil {
			s.logger.Printf("Warn: Callback server fail: %v", err)
		}
		srvClosed <- struct{}{}
		cancel()
	}()
	defer func() {
		listener.Close()
		close(callbackChan)
	}()

	authURL := s.oidcClient.AuthCodeURL(s.oidcConfig, state, extra)
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
		err = s.tokenCache.SetToken(msg.token)
		if err != nil {
			s.logger.Printf("Warn: Cannot cache token. Err: %v", err)
		}
		return msg.token, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("oidc Deadline Exceeded: Timed out waiting for token. Please retry the command and open the URL printed above in a browser if it doesn't open automatically")
	}
}
