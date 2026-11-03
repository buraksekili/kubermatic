/*
Copyright 2026 The Kubermatic Kubernetes Platform contributors.

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

package tokenwebhook

import (
	"errors"
	"regexp"
	"strings"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
)

var (
	// ErrMalformedToken covers everything that is not a well-formed
	// kkp_<cluster-id>_<token-id>:<secret> token.
	ErrMalformedToken = errors.New("malformed token")
	// ErrWrongCluster means the token carries another cluster ID.
	ErrWrongCluster = errors.New("token was issued for another cluster")
	// ErrInvalidTokenID means the token ID part fails the token ID format.
	ErrInvalidTokenID = errors.New("invalid token ID")
)

// tokenIDRegexp matches the token ID: the same pattern the CRDs enforce on
// the object name.
var tokenIDRegexp = regexp.MustCompile(`^[a-z0-9]{8,32}$`)

// ClusterIDRegexp matches a cluster name (DNS label), which is also the
// cluster ID part of a token.
var ClusterIDRegexp = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ParsedToken is a token split into its parts. The secret is kept in memory
// only as long as the authentication of one request needs it and is never
// logged.
type ParsedToken struct {
	ClusterID string
	TokenID   string
	Secret    string
}

// ParseToken splits a token of the form kkp_<cluster-id>_<token-id>:<secret>
// and checks the cluster part and the token ID format. A token that does not
// pass this check is rejected without any store lookup. The secret is only
// checked for being non-empty and colon-free; its value is verified later by
// its hash.
func ParseToken(token, clusterID string) (ParsedToken, error) {
	if !strings.HasPrefix(token, kubermaticv1.UserClusterTokenPrefix) {
		return ParsedToken{}, ErrMalformedToken
	}

	// cluster IDs are DNS labels, so exactly one underscore follows the prefix
	rest := strings.TrimPrefix(token, kubermaticv1.UserClusterTokenPrefix)
	parts := strings.Split(rest, "_")
	if len(parts) != 2 {
		return ParsedToken{}, ErrMalformedToken
	}

	if parts[0] != clusterID {
		return ParsedToken{}, ErrWrongCluster
	}

	tokenID, secret, found := strings.Cut(parts[1], ":")
	if !found || tokenID == "" || secret == "" || strings.Contains(secret, ":") {
		return ParsedToken{}, ErrMalformedToken
	}

	if !tokenIDRegexp.MatchString(tokenID) {
		return ParsedToken{}, ErrInvalidTokenID
	}

	return ParsedToken{ClusterID: parts[0], TokenID: tokenID, Secret: secret}, nil
}
