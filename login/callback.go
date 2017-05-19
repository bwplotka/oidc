package login

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	"github.com/Bplotka/oidc"
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
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

type callbackMsg struct {
	token *oidc.Token
	err   error
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

var OKCallbackResponse = func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OIDC authentication flow is completed. You can close browser tab."))
}
var ErrCallbackResponse = func(w http.ResponseWriter, _ *http.Request, _ error) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OIDC authentication flow is completed. You can close browser tab."))
}

func errRespond(w http.ResponseWriter, r *http.Request, err error, callbackChan chan<- *callbackMsg) {
	callbackResponse := &callbackMsg{
		err: err,
	}
	callbackChan <- callbackResponse
	ErrCallbackResponse(w, r, err)
	return
}

func CallbackHandler(
	oidcClient *oidc.Client,
	oidcConfig oidc.Config,
	expectedState string,
	callbackChan chan<- *callbackMsg,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			err := fmt.Errorf("Failed to parse request form. Err: %v", err)
			errRespond(w, r, err, callbackChan)
			return
		}

		code, state, err := parseCallbackRequest(r.Form)
		if err != nil {
			errRespond(w, r, err, callbackChan)
			return
		}

		if state != expectedState {
			err := fmt.Errorf("Invalid state parameter. Got %s, expected: %s", state, expectedState)
			errRespond(w, r, err, callbackChan)
			return
		}

		oidcToken, err := oidcClient.Exchange(r.Context(), oidcConfig, code)
		if err != nil {
			errRespond(w, r, err, callbackChan)
			return
		}

		callbackResponse := &callbackMsg{
			token: oidcToken,
		}
		callbackChan <- callbackResponse
		OKCallbackResponse(w, r)
		return
	}
}
