# Login

Login package provides tokenSource that is able to cache, reuse and obtain OIDC token.

## Usage:
```go
package main

import (
    "context"
    "log"
    "os"
    
    "github.com/Bplotka/oidc/login"
    "github.com/Bplotka/oidc/login/diskcache"
)

func main() {
    oidcConfig := login.Config{
        ClientID: "client1",
        ClientSecret: "secret1",
        Provider: "https://issuer-oidc.org",
        BindAddress: "http://127.0.0.1:8883",
        // Make sure you ask for offline_access if you want to use refresh tokens!
        Scopes: []string{"openid", "email", "profile", "offline_access"},
        NonceCheck: true,
    }

    cache := disk.NewTokenCache(oidcConfig.ClientID, "~/.super_cache") // see also other caches e.g k8s.NewConfigCache.

	source, err := login.NewOIDCTokenSource(context.Background(), log.New(os.Stdout, "", 0), oidcConfig, cache)
	if err != nil {
		// handle err...
	}

	token, err := source.OIDCToken()
	if err != nil {
	 // handle err...
	}
	
	// Use your token!
	token.AccessToken
	token.IDToken,
	token.RefreshToken
	
}
```

`OIDCToken` method will make sure you retrieve valid token. If token is in cache but expired it will try to refresh it using
refresh token (if present). If cache is empty, or refresh token is wrong it will perform full OIDC login to obtain token.

NOTE: For login purposes and since it implements `code` OIDC flow, it requires browser to be available - it will not work on headless systems.