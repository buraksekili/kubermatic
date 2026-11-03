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
	"testing"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
)

func TestParseToken(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		clusterID  string
		wantParsed ParsedToken
		wantErr    error
	}{
		{
			name:      "valid token",
			token:     "kkp_abc123_7f3e9c2a:Zt8kQ2",
			clusterID: "abc123",
			wantParsed: ParsedToken{
				ClusterID: "abc123",
				TokenID:   "7f3e9c2a",
				Secret:    "Zt8kQ2",
			},
		},
		{
			name:      "wrong prefix",
			token:     "kube_abc123_7f3e9c2a:Zt8kQ2",
			clusterID: "abc123",
			wantErr:   ErrMalformedToken,
		},
		{
			name:      "wrong cluster",
			token:     "kkp_abc123_7f3e9c2a:Zt8kQ2",
			clusterID: "xyz789",
			wantErr:   ErrWrongCluster,
		},
		{
			name:      "id too short",
			token:     "kkp_abc123_7f3e9c:Zt8kQ2",
			clusterID: "abc123",
			wantErr:   ErrInvalidTokenID,
		},
		{
			name:      "id too long",
			token:     "kkp_abc123_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7" + ":Zt8kQ2",
			clusterID: "abc123",
			wantErr:   ErrInvalidTokenID,
		},
		{
			name:      "id with invalid character",
			token:     "kkp_abc123_7f3e9c-A:Zt8kQ2",
			clusterID: "abc123",
			wantErr:   ErrInvalidTokenID,
		},
		{
			name:      "missing secret",
			token:     "kkp_abc123_7f3e9c2a:",
			clusterID: "abc123",
			wantErr:   ErrMalformedToken,
		},
		{
			name:      "missing colon",
			token:     "kkp_abc123_7f3e9c2a",
			clusterID: "abc123",
			wantErr:   ErrMalformedToken,
		},
		{
			name:      "empty id",
			token:     "kkp_abc123_:Zt8kQ2",
			clusterID: "abc123",
			wantErr:   ErrMalformedToken,
		},
		{
			name:      "secret containing a colon",
			token:     "kkp_abc123_7f3e9c2a:foo:bar",
			clusterID: "abc123",
			wantErr:   ErrMalformedToken,
		},
		{
			name:      "two underscores",
			token:     "kkp_abc_123_7f3e9c2a:Zt8kQ2",
			clusterID: "abc_123",
			wantErr:   ErrMalformedToken,
		},
		{
			name:      "empty token",
			token:     "",
			clusterID: "abc123",
			wantErr:   ErrMalformedToken,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := ParseToken(test.token, test.clusterID)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("got error %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed != test.wantParsed {
				t.Errorf("got %+v, want %+v", parsed, test.wantParsed)
			}
		})
	}
}

// The prefix used by ParseToken must stay in sync with the SDK constant.
func TestTokenPrefixMatchesSDK(t *testing.T) {
	if want := kubermaticv1.UserClusterTokenPrefix; want != "kkp_" {
		t.Fatalf("SDK token prefix changed to %q, ParseToken must follow", want)
	}
}

func TestClusterIDRegexp(t *testing.T) {
	valid := []string{"abc123", "a", "a-b-c", "0x9y8"}
	invalid := []string{"", "Abc123", "-abc", "abc-", "a_b", "a.b", "abc--def-"}

	for _, id := range valid {
		if !ClusterIDRegexp.MatchString(id) {
			t.Errorf("cluster ID %q should match", id)
		}
	}
	for _, id := range invalid {
		if ClusterIDRegexp.MatchString(id) {
			t.Errorf("cluster ID %q should not match", id)
		}
	}
}
