package login

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/Bplotka/oidc"
)

const callbackPath = "/oidc-callback"

// CachedOIDCTokenSource implements `oidc.TokenSource` interface to perform oidc-browser-dance.
// It caches fetched tokens in provided TokenCache e.g on disk.
type OIDCTokenSource struct {
	sync.Mutex

	ctx    context.Context
	logger *log.Logger

	oidcClient *oidc.Client
	oidcConfig oidc.Config

	// These two are guarded by mutex.
	tokenCache TokenCache
	nonce      string

	cfg Config
}

func NewOIDCTokenSource(ctx context.Context, logger *log.Logger, cfg Config, tokenCache TokenCache) (oidc.TokenSource, error) {
	oidcConfig := oidc.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  "todo",
		Scopes:       cfg.Scopes,
	}

	oidcClient, err := oidc.NewClient(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC client. Err: %v", err)
	}

	s := &OIDCTokenSource{
		ctx:    ctx,
		logger: logger,

		oidcClient: oidcClient,
		oidcConfig: oidcConfig,

		tokenCache: tokenCache,
		cfg:        cfg,
	}

	return oidc.NewReuseTokenSource(nil, s), nil
}

// OIDCToken is used to obtain new OIDC Token (which include e.g access token, refresh token and id token). It does that by
// using a Refresh Token to obtain new Tokens. If the cached one is still valid it returns it immediately.
func (s *OIDCTokenSource) OIDCToken() (*oidc.Token, error) {
	s.Lock()
	defer s.Unlock()

	cachedToken, err := s.tokenCache.Token()
	if err != nil {
		s.logger.Printf("Error: Failed to get cached token. Caching might be broken. Err: %v", err)

	} else if cachedToken != nil {
		if cachedToken.Valid(s.ctx, s.oidcClient.Verifier(
			oidc.VerificationConfig{
				ClientID:   s.cfg.ClientID,
				ClaimNonce: s.nonce,
			},
		)) {
			// Successfully retrieved a non-expired cached token and only if we have ID token as well.
			return cachedToken, nil
		}

		if cachedToken.RefreshToken != "" {
			// Only if we have refresh token, we can refresh IDToken.
			oidcToken, err := s.refreshToken(cachedToken)
			if err == nil {
				return oidcToken, nil
			}

			// Our refresh token expired.
			s.logger.Print("Warn: Refresh token expired.")
		}
	}

	// Our request for access token was denied, either we had no RefreshToken, it was invalid or expired.
	newToken, err := s.updateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain new refresh token. Err: %v", err)
	}

	return newToken, nil
}

func (s *OIDCTokenSource) Verifier() oidc.Verifier {
	return s.oidcClient.Verifier(oidc.VerificationConfig{
		ClientID: s.oidcConfig.ClientID,
	})
}

func (s *OIDCTokenSource) refreshToken(invalidToken *oidc.Token) (*oidc.Token, error) {
	ctx := oidcContextWithTimeout(s.ctx)

	s.logger.Printf("Debug: Cached token has none or expired ID token or access token. " +
		"Try to refresh access token using refresh token.")
	token, err := s.oidcClient.TokenSource(
		ctx,
		s.oidcConfig,
		invalidToken,
	).OIDCToken()
	if err != nil {
		return nil, err
	}

	if !token.Valid(s.ctx, s.oidcClient.Verifier(oidc.VerificationConfig{ClientID: s.cfg.ClientID})) {
		return nil, fmt.Errorf("got invalid idToken from provider.")
	}

	s.Lock()
	defer s.Unlock()
	err = s.tokenCache.SetToken(token)
	if err != nil {
		s.logger.Printf("Warn: Cannot cache token. Err: %v", err)
	}

	return token, nil
}

func oidcContextWithTimeout(ctx context.Context) context.Context {
	if existing := ctx.Value(oidc.HTTPClientCtxKey); existing != nil {
		return ctx
	}
	timeout := 10 * time.Second
	if deadline, exists := ctx.Deadline(); exists {
		timeout = deadline.Sub(time.Now())
	}
	return context.WithValue(ctx, oidc.HTTPClientCtxKey, http.Client{
		Timeout: timeout,
	})
}

func (s *OIDCTokenSource) updateRefreshToken() (*oidc.Token, error) {
	s.logger.Print("Debug: Perfoming auth Code flow to obtain new refresh token and other tokens.")

	callbackChan := make(chan *callbackMsg, 100)

	state := rand128Bits()
	nonce := ""
	extra := url.Values{}
	if s.cfg.NonceCheck {
		nonce = rand128Bits()
		extra.Set("nonce", nonce)
	}

	ctx, cancel := context.WithTimeout(s.ctx, 1*time.Minute)
	defer cancel()

	handler := http.NewServeMux()
	handler.HandleFunc(callbackPath, CallbackHandler(
		s.oidcClient,
		s.oidcConfig,
		state,
		callbackChan,
	))

	server := &http.Server{Addr: s.cfg.BindAddress, Handler: handler}
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			s.logger.Printf("Warn: Callback server fail: %v", err)
		}
		cancel()
	}()
	defer func() {
		server.Close()
		close(callbackChan)
	}()

	authURL := s.oidcClient.AuthCodeURL(s.oidcConfig, state, extra)
	err := openBrowser(authURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: Failed to open browser. Err: %v", err)
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
		if msg.err != nil {
			return nil, fmt.Errorf("oidc: Callback error: %v", msg.err)
		}

		s.Lock()
		defer s.Unlock()
		s.nonce = nonce
		err = s.tokenCache.SetToken(msg.token)
		if err != nil {
			s.logger.Printf("Warn: Cannot cache token. Err: %v", err)
		}

		return msg.token, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("oidc Deadline Exceeded: Timed out waiting for token. Please retry the command and open the URL printed above in a browser if it doesn't open automatically.")
	}
}
