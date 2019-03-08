package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/bwplotka/oidc"
)

const (
	codeParam  = "code"
	stateParam = "state"

	errParam     = "error"
	errDescParam = "error_description"
)

func rand128Bits() string {
	buff := make([]byte, 16) // 128 bit random ID.
	if _, err := io.ReadFull(rand.Reader, buff); err != nil {
		panic(err)
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(buff), "=")
}

// open opens the specified URL in the default browser of the user.
func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
		// If we don't escape &, cmd will ignore everything after the first &.
		url = strings.Replace(url, "&", "^&", -1)
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

// callbackResponse contains return message from callback server including token or error.
type callbackResponse struct {
	token *oidc.Token
	err   error
}

// callbackRequest specifies values that are needed for expected callback handling.
type callbackRequest struct {
	ctx           context.Context
	expectedState string

	cfg    oidc.Config
	client *oidc.Client
}

// CallbackServer carries a callback handler for OIDC auth code flow.
// NOTE: This is not thread-safe in terms of multiple logins in the same time.
type CallbackServer struct {
	redirectURL string
	callbackCh  chan *callbackResponse

	// CallbackReq is written in separate thread so guard that.
	callbackReqMu sync.Mutex
	// If empty, nothing is expected, so callback should immediately return err.
	callbackReq *callbackRequest
}

// NewServer creates HTTP server with OIDC callback on the bindAddress an argument. BindAddress is the ultimately a redirectURL that all clients MUST register
// first on the OIDC server. It can (and is recommended) to point to localhost. Bind Address must include port. You can specify 0 if your
// OIDC provider support wildcard on port (almost all server does NOT).
func NewServer(bindAddress string) (srv *CallbackServer, closeSrv func(), err error) {
	bindURL, err := url.Parse(bindAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("BindAddress is not in a form of URL. Err: %v", err)
	}

	listener, err := net.Listen("tcp", bindURL.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to Listen for tcp on: %s. Err: %v", bindURL.Host, err)
	}

	s := &CallbackServer{
		redirectURL: fmt.Sprintf("http://%s%s", listener.Addr().String(), bindURL.Path),
		callbackCh:  make(chan *callbackResponse),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(bindURL.Path, s.callbackHandler)

	go func() {
		http.Serve(listener, mux)
	}()

	return s, func() {
		listener.Close()
		close(s.callbackCh)
	}, nil
}

// NewReuseServer creates HTTP server with OIDC callback registered on given HTTP mux. Server constructed in such way
// is not responsible for serving the callback. This is responsibility of the caller.
func NewReuseServer(pattern string, listenAddress string, mux *http.ServeMux) *CallbackServer {
	s := &CallbackServer{
		redirectURL: fmt.Sprintf("http://%s%s", listenAddress, pattern),
		callbackCh:  make(chan *callbackResponse),
	}
	mux.HandleFunc(pattern, s.callbackHandler)
	return s
}

// callbackHandler handles redirect from OIDC provider with either code or error parameters.
// If none callback is expected it will return error.
// In case of valid code with corresponded state it will perform token exchange with OIDC provider.
// Any message is propagated via Go channel if the callback was expected.
// NOTE: This is not thread-safe in terms of multiple logins in the same time.
func (s *CallbackServer) callbackHandler(w http.ResponseWriter, r *http.Request) {
	s.callbackReqMu.Lock()
	if s.callbackReq == nil {
		w.WriteHeader(http.StatusPreconditionFailed)
		w.Write([]byte("Did not expect OIDC callback"))
		return
	}
	defer func() {
		s.callbackReq = nil
		s.callbackReqMu.Unlock()
	}()

	err := r.ParseForm()
	if err != nil {
		err := fmt.Errorf("Failed to parse request form. Err: %v", err)
		s.errRespond(w, r, err)
		return
	}

	code, state, err := parseCallbackRequest(r.Form)
	if err != nil {
		s.errRespond(w, r, err)
		return
	}

	if state != s.callbackReq.expectedState {
		err := fmt.Errorf("Invalid state parameter. Got %s, expected: %s", state, s.callbackReq.expectedState)
		s.errRespond(w, r, err)
		return
	}

	ctx := mergeContexts(r.Context(), s.callbackReq.ctx)
	oidcToken, err := s.callbackReq.client.Exchange(ctx, s.callbackReq.cfg, code)
	if err != nil {
		s.errRespond(w, r, err)
		return
	}

	callbackResponse := &callbackResponse{
		token: oidcToken,
	}
	OKCallbackResponse(w, r)
	select {
	case <-s.callbackReq.ctx.Done():
	case s.callbackCh <- callbackResponse:
	}
	return
}

func parseCallbackRequest(form url.Values) (code string, state string, err error) {
	state = form.Get(stateParam)
	if state == "" {
		return "", "", errors.New("User session error. No state parameter.")
	}

	if errorCode := form.Get(errParam); errorCode != "" {
		// Got error from provider. Passing through.
		return "", "", fmt.Errorf("Got error from provider: %s Desc: %s", errorCode, form.Get(errDescParam))
	}

	code = form.Get(codeParam)
	if code == "" {
		return "", "", errors.New("Missing code token.")
	}

	return code, state, nil
}

// OKCallbackResponse is package wide function variable that returns HTTP response on successful OIDC `code` flow.
var OKCallbackResponse = func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OIDC authentication flow is completed. You can close browser tab."))
}

// ErrCallbackResponse is package wide function variable that returns HTTP response on failed OIDC `code` flow.
// Note that, by default we don't want user to see anything wrong on browser side. All errors are propagated to command.
// If it is required otherwise, override this function.
var ErrCallbackResponse = func(w http.ResponseWriter, _ *http.Request, _ error) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OIDC authentication flow is completed. You can close browser tab."))
}

func (s *CallbackServer) errRespond(w http.ResponseWriter, r *http.Request, err error) {
	callbackResponse := &callbackResponse{
		err: err,
	}
	ErrCallbackResponse(w, r, err)

	select {
	case <-s.callbackReq.ctx.Done():
	case s.callbackCh <- callbackResponse:
	}
	return
}

func mergeContexts(originalCtx context.Context, oidcCtx context.Context) context.Context {
	if customClient := originalCtx.Value(oidc.HTTPClientCtxKey); customClient != nil {
		return originalCtx
	}
	return context.WithValue(originalCtx, oidc.HTTPClientCtxKey, oidcCtx.Value(oidc.HTTPClientCtxKey))
}

func (s *CallbackServer) ExpectCallback(callbackReq *callbackRequest) {
	s.callbackReqMu.Lock()
	defer s.callbackReqMu.Unlock()
	s.callbackReq = callbackReq
}

func (s *CallbackServer) Callback() <-chan *callbackResponse {
	return s.callbackCh
}

func (s *CallbackServer) RedirectURL() string {
	return s.redirectURL
}
