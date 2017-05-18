package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

// Token is an Open ID Connect token's response described here:
// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse. Token is always Bearer type.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests. It can be used for API access or token revocation.
	AccessToken string `json:"access_token"`

	// AccessTokenExpiry is time when access token will be invalid.
	AccessTokenExpiry time.Time `json:"expiry"`

	// RefreshToken is used to refresh the access token and ID token if they expire.
	RefreshToken string `json:"refresh_token,omitempty"`

	// IDToken is a security token that contains Claims about the Authentication of an End-User by an Authorization
	// Server when using a Client, and potentially other requested Claims that helps in authorization itself.
	// The ID Token is always represented as a JWT.
	IDToken string `json:"id_token"`
}

// Claims unmarshals the raw JSON payload of the IDToken into a provided struct.
//
//		var claims struct {
//			Email         string `json:"email"`
//			EmailVerified bool   `json:"email_verified"`
//		}
//		if err := oidc.Token{IDToken: "<id token>"}.Claims(idTokenVerifier, &claims); err != nil {
//			// handle error
//		}
//
func (t Token) Claims(ctx context.Context, verifier Verifier, v interface{}) error {
	idToken, err := verifier.Verify(ctx, t.IDToken)
	if err != nil {
		return fmt.Errorf("cannot get claims. Failed to verify and parse IDToken. Err: %v.", err)
	}

	return idToken.Claims(v)
}

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+t.AccessToken)
}

func (t *Token) accessTokenExpired() bool {
	if t.AccessTokenExpiry.IsZero() {
		return false
	}
	return t.AccessTokenExpiry.Add(-expiryDelta).Before(time.Now())
}

// Valid validates oidc token by validating AccessToken and ID Token.
func (t *Token) Valid(ctx context.Context, verifier Verifier) bool {
	idToken, err := verifier.Verify(ctx, t.IDToken)
	if err != nil {
		return false
	}

	return t != nil && t.AccessToken != "" && !t.accessTokenExpired() && idToken.Expiry.Add(-expiryDelta).After(time.Now())
}

// IDToken is an OpenID Connect extension that provides a predictable representation
// of an authorization event.
//
// The ID Token only holds fields OpenID Connect requires. To access additional
// claims returned by the server, use the Claims method.
type IDToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// A unique string which identifies the end user.
	Subject string

	// Expiry of the token. Ths package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time

	// When the token was issued by the provider.
	IssuedAt time.Time

	// Initial nonce provided during the authentication redirect.
	//
	// If present, this package ensures this is a valid nonce.
	Nonce string

	// Raw payload of the id_token.
	claims []byte
}

// Claims unmarshals the raw JSON payload of the ID Token into a provided struct.
//
//		idToken, err := idTokenVerifier.Verify(rawIDToken)
//		if err != nil {
//			// handle error
//		}
//		var claims struct {
//			Email         string `json:"email"`
//			EmailVerified bool   `json:"email_verified"`
//		}
//		if err := idToken.Claims(&claims); err != nil {
//			// handle error
//		}
//
func (i *IDToken) Claims(v interface{}) error {
	if i.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(i.claims, v)
}

type idToken struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	Expiry   jsonTime `json:"exp"`
	IssuedAt jsonTime `json:"iat"`
	Nonce    string   `json:"nonce"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = audience(auds)
	return nil
}

func (a audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}

func (j jsonTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(j).Unix())
}
