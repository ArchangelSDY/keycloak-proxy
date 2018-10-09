/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OAuth2GrantType int

const (
	GrantTypeAuthCode OAuth2GrantType = iota
	GrantTypeRefreshToken
)

// getOAuthConfig returns a oauth2 config
func (r *oauthProxy) getOAuthConfig(redirectionURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     r.config.ClientID,
		ClientSecret: r.config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  r.idp.AuthEndpoint.String(),
			TokenURL: r.idp.TokenEndpoint.String(),
		},
		// AuthMethod:  oauth2.AuthMethodClientSecretBasic,
		RedirectURL: redirectionURL,
		Scopes:      append(r.config.Scopes, oidc.DefaultScope...),
	}
}

// verifyToken verify that the token in the user context is valid
func verifyToken(provider *oidc.Provider, rawToken string) (*oidc.IDToken, error) {
	if token, err := provider.Verify(rawToken); err == nil {
		return token, nil
	} else {
		if strings.Contains(err.Error(), "token is expired") {
			return nil, ErrAccessTokenExpired
		}
		return nil, err
	}
}

// getRefreshedToken attempts to refresh the access token, returning the parsed token and the time it expires or a error
func getRefreshedToken(client *oidc.Client, ctx context.Context, t string) (jose.JWT, time.Time, error) {
	cl, err := client.OAuthClient()
	if err != nil {
		return jose.JWT{}, time.Time{}, err
	}
	response, err := getToken(cl, ctx, GrantTypeRefreshToken, t)
	if err != nil {
		if strings.Contains(err.Error(), "token expired") {
			return jose.JWT{}, time.Time{}, ErrRefreshTokenExpired
		}
		return jose.JWT{}, time.Time{}, err
	}

	token, identity, err := parseToken(response.AccessToken)
	if err != nil {
		return jose.JWT{}, time.Time{}, err
	}

	return token, identity.ExpiresAt, nil
}

// exchangeAuthenticationCode exchanges the authentication code with the oauth server for a access token
func exchangeAuthenticationCode(cfg *oauth2.Config, ctx context.Context, code string) (oauth2.Token, error) {
	return getToken(cft, ctx, GrantTypeAuthCode, code)
}

// getUserinfo is responsible for getting the userinfo from the IDPD
func getUserinfo(client *oauth2.Client, endpoint string, token string) (jose.Claims, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(authorizationHeader, fmt.Sprintf("Bearer %s", token))

	resp, err := client.HttpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("token not validate by userinfo endpoint")
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var claims jose.Claims
	if err := json.Unmarshal(content, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// getToken retrieves a code from the provider, extracts and verified the token
func getToken(cfg *oauth2.Config, ctx context.Context, grantType, code string) (oauth2.Token, error) {
	start := time.Now()
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return token, err
	}
	taken := time.Since(start).Seconds()
	switch grantType {
	case GrantTypeAuthCode:
		oauthTokensMetric.WithLabelValues("exchange").Inc()
		oauthLatencyMetric.WithLabelValues("exchange").Observe(taken)
	case GrantTypeRefreshToken:
		oauthTokensMetric.WithLabelValues("renew").Inc()
		oauthLatencyMetric.WithLabelValues("renew").Observe(taken)
	}

	return token, err
}

// parseToken retrieve the user identity from the token
func parseToken(t string) (jose.JWT, *oidc.Identity, error) {
	token, err := jose.ParseJWT(t)
	if err != nil {
		return jose.JWT{}, nil, err
	}
	claims, err := token.Claims()
	if err != nil {
		return jose.JWT{}, nil, err
	}
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return jose.JWT{}, nil, err
	}

	return token, identity, nil
}
