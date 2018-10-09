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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
)

// extractIdentity parse the jwt token and extracts the various elements is order to construct
func extractIdentity(token *oidc.IDToken) (*userContext, error) {
	var claims map[string]json.RawMessage
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	var email string
	if val, ok := claims[claimEmail]; ok {
		json.Unmarshal(val, &email)
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	var preferredName string
	if val, ok := claims[claimPreferredName]; ok {
		if err := json.Unmarshal(val, &preferredName); err != nil {
			preferredName = email
		}
	}

	// @step: extract the realm roles
	var roleList []string
	if val, ok := claims[claimRealmAccess]; ok {
		var realmRoles map[string][]string
		if err := json.Unmarshal(val, &realmRoles); err == nil {
			if roles, ok := realmRoles[claimRealmAccess]; ok {
				roleList = append(roleList, roles...)
			}
		}
	}

	// @step: extract the client roles from the access token
	if val, ok := claims[claimResourceAccess]; ok {
		var accesses map[string]map[string][]string
		if err := json.Unmarshal(val, &accesses); err == nil {
			for name, scopes := range accesses {
				if roles, found := scopes[claimResourceRoles]; found {
					for _, r := range roles {
						roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
					}
				}
			}
		}
	}

	// @step: extract any group information from the tokens
	var groups []string
	if val, ok := claims[claimGroups]; ok {
		json.Unmarshal(val, &groups)
	}

	return &userContext{
		audiences:     token.Audience,
		claims:        claims,
		email:         email,
		expiresAt:     token.Expiry,
		groups:        groups,
		subject:       token.Subject,
		name:          preferredName,
		preferredName: preferredName,
		roles:         roleList,
	}, nil
}

// backported from https://github.com/gambol99/go-oidc/blob/master/oidc/verification.go#L28-L37
// I'll raise another PR to make it public in the go-oidc package so we can just use `oidc.ContainsString()`
func containsString(needle string, haystack []string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// isAudience checks the audience
func (r *userContext) isAudience(aud string) bool {
	return containsString(aud, r.audiences)
}

// getRoles returns a list of roles
func (r *userContext) getRoles() string {
	return strings.Join(r.roles, ",")
}

// isExpired checks if the token has expired
func (r *userContext) isExpired() bool {
	return r.expiresAt.Before(time.Now())
}

// isBearer checks if the token
func (r *userContext) isBearer() bool {
	return r.bearerToken
}

// isCookie checks if it's by a cookie
func (r *userContext) isCookie() bool {
	return !r.isBearer()
}

// String returns a string representation of the user context
func (r *userContext) String() string {
	return fmt.Sprintf("user: %s, expires: %s, roles: %s", r.preferredName, r.expiresAt.String(), strings.Join(r.roles, ","))
}
