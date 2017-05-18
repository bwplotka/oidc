package login

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"github.com/Bplotka/oidc"
)

//go:generate mockery -name TokenCache -case underscore

// TokenCache is a Open ID Connect Token caching structure.
type TokenCache interface {
	SetToken(token *oidc.Token) error
	Token() (*oidc.Token, error)
}

const DefaultTokenCache = "~/.oidc_keys"

// OnDiskTokenCache is a OAuth Token caching structure that stores it on disk.
type OnDiskTokenCache struct {
	storePath string
	clientID  string
}

func NewDiskTokenCache(clientID string, path string) *OnDiskTokenCache {
	return &OnDiskTokenCache{storePath: path, clientID: clientID}
}

func (c *OnDiskTokenCache) getOrCreateStoreDir() (string, error) {
	err := os.MkdirAll(c.storePath, os.ModeDir|0700)
	return c.storePath, err
}

func (c *OnDiskTokenCache) tokenCacheFileName() string {
	cliToolName := filepath.Base(os.Args[0])
	return fmt.Sprintf("oauth2_token_%s_%s", cliToolName, c.clientID)
}

func (c *OnDiskTokenCache) Token() (*oidc.Token, error) {
	storeDir, err := c.getOrCreateStoreDir()
	if err != nil {
		return nil, fmt.Errorf("Failed to create store dir. Err: %v", err)
	}

	bytes, err := ioutil.ReadFile(filepath.Join(storeDir, c.tokenCacheFileName()))
	if os.IsNotExist(err) {
		// Probably a no such file err.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to get cached token code. Err: %v", err)
	}
	token := &oidc.Token{}
	if err := json.Unmarshal(bytes, token); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal token JSON. Err: %v", err)
	}

	return token, nil
}

func (c *OnDiskTokenCache) SetToken(token *oidc.Token) error {
	storeDir, err := c.getOrCreateStoreDir()
	if err != nil {
		return err
	}

	marshaledToken, err := json.Marshal(token)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(storeDir, c.tokenCacheFileName()), marshaledToken, 0600)
	if err != nil {
		return fmt.Errorf("Failed caching access token. Err: %v", err)
	}

	return nil
}
