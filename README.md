# oidc
[![Build Status](https://travis-ci.org/bwplotka/oidc.svg?branch=master)](https://travis-ci.org/bwplotka/oidc)
[![Go Report Card](https://goreportcard.com/badge/github.com/bwplotka/oidc)](https://goreportcard.com/report/github.com/bwplotka/oidc)


Golang Open ID Connect (OIDC) client library.

This library provides OIDC client that mimics standard [oauth2](https://github.com/golang/oauth2) library and gives functionality 
for communicating with any [OIDC](http://openid.net/specs/openid-connect-core-1_0.html)-compliant provider.
 
This package was also inspired by [go-oidc](https://github.com/coreos/go-oidc) package by CoreOS.

## Usage:

### Directly oidc package:

```go
package main

import (
    "context"
    
    "github.com/bwplotka/oidc"
)

func main() {
    // Performs call discovery endpoint to get all the details about provider.
    client, err := oidc.NewClient(context.Background(), "https://issuer-oidc.org")
    if err != nil {
        // handle err
    }
    
    extraDiscoveryStuff := map[string]interface{}{}
    err = client.Claims(&extraDiscoveryStuff)
    if err != nil {
        // handler err
    }
    
    // For exchanging code into token...
    client.Exchange(...)
    // For revoking tokens...
    client.Revoke(...)
    // For OIDC UserInfo...
    client.UserInfo(...)
    // For IDToken verification...
    client.Verifier(...)
    // For ID token refreshing...
    client.TokenSource(...).OIDCToken(context.Background())
}
```

### Using login package for full oidc-browser-dance: 

See [login](./login/README.md)

## Deps:

Vendoring using submodules. See [.gitmodules](.gitmodules)
 

## Wishlist:

* [x] Support 0 port (not pin into exact port)
* [ ] Consider moving to structure logger with levels e.g logrus or just drop logging. (I don't like passing std logger in constructor)
   
## Copyright 
Copyright 2017 Bartłomiej Płotka. All Rights Reserved.
See LICENSE for licensing terms.
