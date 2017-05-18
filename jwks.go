package oidc

// This file was heavily inspired by github.com/coreos/go-oidc/jwks.go with some custom simplification
// (0 cache expiration logic).

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

func newRemoteKeySet(ctx context.Context, jwksURL string, now func() time.Time) *remoteKeySet {
	if now == nil {
		now = time.Now
	}
	return &remoteKeySet{jwksURL: jwksURL, ctx: ctx, timeNow: now}
}

type remoteKeySet struct {
	jwksURL string
	ctx     context.Context
	timeNow func() time.Time

	// guard all other fields
	mutex sync.Mutex

	// inflightCtx suppresses parallel execution of getKeys and allows
	// multiple goroutines to wait for its result.
	// Its Err() method returns any errors encountered during getKeys.
	//
	// If nil, there is no inflight getKeys request.
	inflightCtx *inflight

	keys []jose.JSONWebKey
}

// inflight is used to wait on some in-flight request from multiple goroutines
type inflight struct {
	done chan struct{}
	err  error
}

// Done returns a channel that is closed when the inflight request finishes.
func (i *inflight) Done() <-chan struct{} {
	return i.done
}

// Err returns any error encountered during request execution. May be nil.
func (i *inflight) Err() error {
	return i.err
}

// Cancel signals completion of the inflight request with error err.
// Must be called only once for particular inflight instance.
func (i *inflight) Cancel(err error) {
	i.err = err
	close(i.done)
}

func (r *remoteKeySet) keysWithID(ctx context.Context, keyIDs []string) ([]jose.JSONWebKey, error) {
	var inflightCtx *inflight
	func() {
		r.mutex.Lock()
		defer r.mutex.Unlock()

		// If there's not a current inflight request, create one.
		if r.inflightCtx == nil {
			inflightCtx := &inflight{make(chan struct{}), nil}
			r.inflightCtx = inflightCtx

			go func() {
				inflightCtx.Cancel(r.updateKeys(r.ctx))

				r.mutex.Lock()
				defer r.mutex.Unlock()
				r.inflightCtx = nil
			}()
		}

		inflightCtx = r.inflightCtx
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-inflightCtx.Done():
		if err := inflightCtx.Err(); err != nil {
			return nil, err
		}
	}

	return r.keys, nil
}

func (r *remoteKeySet) updateKeys(ctx context.Context) error {
	req, err := http.NewRequest("GET", r.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("oidc: can't create request: %v", err)
	}

	resp, err := doRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("oidc: get keys failed %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("oidc: read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: get keys failed: %s %s", resp.Status, body)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return fmt.Errorf("oidc: failed to decode keys: %v %s", err, body)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.keys = keySet.Keys

	return nil
}
