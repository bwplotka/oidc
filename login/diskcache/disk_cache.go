package disk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/bwplotka/oidc"
	"github.com/bwplotka/oidc/login"
)

// DefaultCachePath is default path for OIDC tokens.
const DefaultCachePath = "$HOME/.oidc_keys"

// Cache is a oidc caching structure that stores all tokens on disk.
// Tokens cache files are named after clientID and arg[0].
// NOTE: There is no logic for cleaning cache in case of change in clientID.
// NOTE: There is no logic for caching configuration as well.
type Cache struct {
	cfg       login.OIDCConfig
	storePath string
}

// NewTokenCache constructs disk cache.
func NewCache(path string, cfg login.OIDCConfig) *Cache {
	return &Cache{cfg: cfg, storePath: os.ExpandEnv(path)}
}

func (c *Cache) getOrCreateStoreDir() (string, error) {
	err := os.MkdirAll(c.storePath, os.ModeDir|0700)
	return c.storePath, err
}

func (c *Cache) tokenCacheFileName() string {
	cliToolName := filepath.Base(os.Args[0])
	return fmt.Sprintf("token_%s_%s", cliToolName, c.cfg.ClientID)
}

// Token retrieves token from file.
func (c *Cache) Token() (*oidc.Token, error) {
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

// SaveToken saves token in file.
func (c *Cache) SaveToken(token *oidc.Token) error {
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

// Config returns OIDC configuration.
func (c *Cache) Config() login.OIDCConfig {
	return c.cfg
}
