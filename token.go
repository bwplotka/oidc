package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

// Token is an Open ID Connect token's response described here:
// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse. Token is always Bearer type.
// See TokenResponse for full oauth2-compatible response.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests. It can be used for API access or token revocation.
	AccessToken string `json:"access_token"`

	// AccessTokenExpiry is time when access token will be invalid.
	AccessTokenExpiry time.Time `json:"expiry"`

	// RefreshToken is used to refresh the access token and ID token if they expire.
	RefreshToken string `json:"refresh_token,omitempty"`

	// NewIDToken is a security token that contains Claims about the Authentication of an End-User by an Authorization
	// Server when using a Client, and potentially other requested Claims that helps in authorization itself.
	// The ID Token is always represented as a JWT.
	IDToken string `json:"id_token"`
}

// Claims unmarshals the raw JSON payload of the NewIDToken into a provided struct.
//
//		var claims struct {
//			Email         string `json:"email"`
//			EmailVerified bool   `json:"email_verified"`
//		}
//		if err := oidc.Token{NewIDToken: "<id token>"}.Claims(idTokenVerifier, &claims); err != nil {
//			// handle error
//		}
//
func (t Token) Claims(ctx context.Context, verifier Verifier, v interface{}) error {
	idToken, err := verifier.Verify(ctx, t.IDToken)
	if err != nil {
		return fmt.Errorf("cannot get claims. Failed to verify and parse NewIDToken. Err: %v", err)
	}

	return idToken.Claims(v)
}

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+t.AccessToken)
}

// IsAccessTokenExpired returns true if access token expired.
func (t *Token) IsAccessTokenExpired() bool {
	if t.AccessTokenExpiry.IsZero() {
		return false
	}
	return t.AccessTokenExpiry.Add(-expiryDelta).Before(time.Now())
}

// IsValid validates oidc token by validating AccessToken and ID Token.
// If error is nil, the token is valid.
func (t *Token) IsValid(ctx context.Context, verifier Verifier) error {
	_, err := verifier.Verify(ctx, t.IDToken)
	if err != nil {
		return fmt.Errorf("token: IDToken is not valid. Err: %v", err)
	}

	if t.AccessToken == "" {
		return errors.New("token: No AccessToken.")
	}

	if t.IsAccessTokenExpired() {
		return errors.New("token: AccessToken expired.")
	}
	return nil
}

// NewIDToken is an OpenID Connect extension that provides a predictable representation
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
	Issuer string `json:"iss"`

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	Audience Audience `json:"aud"`

	// A unique string which identifies the end user.
	Subject string `json:"sub"`

	// Expiry of the token.
	Expiry NumericDate `json:"exp"`

	// When the token was issued by the provider.
	IssuedAt NumericDate `json:"iat"`

	// Initial nonce provided during the authentication redirect.
	//
	// If present, this package ensures this is a valid nonce.
	Nonce string `json:"nonce"`

	// Raw payload of the id_token.
	claims []byte
}

type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var audience []string
	err := json.Unmarshal(b, &audience)
	if err == nil {
		*a = Audience(audience)
		return nil
	}

	var audienceString string
	err = json.Unmarshal(b, &audienceString)
	if err != nil {
		return err
	}

	*a = Audience([]string{audienceString})
	return nil
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

// NumericDate represents date and time as the number of seconds since the
// epoch, including leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
type NumericDate int64

// NewNumericDate constructs NumericDate from time.Time value.
func NewNumericDate(t time.Time) NumericDate {
	if t.IsZero() {
		return NumericDate(0)
	}

	// While RFC 7519 technically states that NumericDate values may be
	// non-integer values, we don't bother serializing timestamps in
	// claims with sub-second accuracy and just round to the nearest
	// second instead.
	return NumericDate(t.Unix())
}

// MarshalJSON serializes the given NumericDate into its JSON representation.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(n), 10)), nil
}

// UnmarshalJSON reads a date from its JSON representation.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	s := string(b)

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("Failed to unmarshall NumericDate. Err: %v", err)
	}

	*n = NumericDate(f)
	return nil
}

// Time returns time.Time representation of NumericDate.
func (n NumericDate) Time() time.Time {
	return time.Unix(int64(n), 0)
}
