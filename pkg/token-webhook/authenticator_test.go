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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testNamespace   = "cluster-ca"
	testClusterID   = "ca"
	testClusterUID  = "ca-uid-1"
	testTokenID     = "abcdef123456"
	testSecret      = "Zt8kQ2vXnB4m"
	testUserID      = "user-1a2b3c"
	testGroupPrefix = "oidc:"
)

var testNow = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func testTokenValue() string {
	return fmt.Sprintf("kkp_%s_%s:%s", testClusterID, testTokenID, testSecret)
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func testToken() *kubermaticv1.UserClusterToken {
	return &kubermaticv1.UserClusterToken{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testTokenID,
			Namespace:  testNamespace,
			Generation: 1,
		},
		Spec: kubermaticv1.UserClusterTokenSpec{
			TokenHash:      hashSecret(testSecret),
			UserID:         testUserID,
			ClusterID:      testClusterID,
			ClusterUID:     testClusterUID,
			SeedName:       "europe-west3-c",
			IssueTime:      metav1.Time{Time: testNow.Add(-10 * time.Minute)},
			ExpirationTime: metav1.Time{Time: testNow.Add(1 * time.Hour)},
		},
		Status: kubermaticv1.UserClusterTokenStatus{
			ObservedGeneration: 1,
			State:              kubermaticv1.UserClusterTokenActive,
		},
	}
}

func testAttribute() *kubermaticv1.UserClusterAttribute {
	return &kubermaticv1.UserClusterAttribute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testUserID,
			Namespace:  testNamespace,
			Generation: 1,
		},
		Spec: kubermaticv1.UserClusterAttributeSpec{UserID: testUserID},
		Status: kubermaticv1.UserClusterAttributeStatus{
			ObservedGeneration: 1,
			State:              kubermaticv1.UserClusterTokenActive,
			Username:           "alice@example.com",
			Groups:             []string{"team-payments", "kkp-users"},
		},
	}
}

// fakeStore implements tokenSource entirely in memory.
type fakeStore struct {
	mu           sync.Mutex
	tokens       map[string]*kubermaticv1.UserClusterToken
	attributes   map[string]*kubermaticv1.UserClusterAttribute
	synced       bool
	lastContact  time.Time
	tokenLookups int
	getErr       error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		tokens:      map[string]*kubermaticv1.UserClusterToken{testTokenID: testToken()},
		attributes:  map[string]*kubermaticv1.UserClusterAttribute{testUserID: testAttribute()},
		synced:      true,
		lastContact: testNow,
	}
}

func (s *fakeStore) GetToken(_ context.Context, id string) (*kubermaticv1.UserClusterToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokenLookups++
	if s.getErr != nil {
		return nil, s.getErr
	}
	if token := s.tokens[id]; token != nil {
		return token.DeepCopy(), nil
	}
	return nil, nil
}

func (s *fakeStore) GetAttribute(_ context.Context, userID string) (*kubermaticv1.UserClusterAttribute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getErr != nil {
		return nil, s.getErr
	}
	if attribute := s.attributes[userID]; attribute != nil {
		return attribute.DeepCopy(), nil
	}
	return nil, nil
}

func (s *fakeStore) HasSynced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.synced
}

func (s *fakeStore) LastContact() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastContact
}

func (s *fakeStore) CacheSizes() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens), len(s.attributes)
}

func (s *fakeStore) mutate(fn func(*fakeStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

func (s *fakeStore) lookups() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenLookups
}

// fakeWriter records lastUsedTime writes.
type fakeWriter struct {
	mu     sync.Mutex
	writes []struct {
		tokenID string
		at      time.Time
	}
}

func (w *fakeWriter) WriteLastUsed(_ context.Context, _, tokenID string, t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, struct {
		tokenID string
		at      time.Time
	}{tokenID, t})
	return nil
}

func (w *fakeWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.writes)
}

func newTestAuthenticator(store *fakeStore, writer LastUsedWriter, now func() time.Time, mut func(*AuthenticatorConfig)) *Authenticator {
	cfg := AuthenticatorConfig{
		ClusterID:        testClusterID,
		ClusterUID:       testClusterUID,
		GroupPrefix:      testGroupPrefix,
		ClockSkew:        30 * time.Second,
		IdleTimeout:      24 * time.Hour,
		MaxStaleness:     2 * time.Minute,
		LastUsedInterval: 5 * time.Minute,
		Store:            store,
		Writer:           writer,
		Metrics:          NewMetrics(prometheus.NewRegistry()),
		Log:              zap.NewNop().Sugar(),
		Now:              now,
	}
	if mut != nil {
		mut(&cfg)
	}
	return NewAuthenticator(testNamespace, cfg)
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		prepare    func(store *fakeStore, cfg *AuthenticatorConfig)
		want       Decision
		wantReason string
		wantUser   *authenticationv1.UserInfo
	}{
		{
			name:  "valid token",
			token: testTokenValue(),
			want:  DecisionAllow,
			wantUser: &authenticationv1.UserInfo{
				Username: "alice@example.com",
				UID:      testUserID,
				Groups:   []string{"oidc:team-payments", "oidc:kkp-users", "system:authenticated"},
				Extra:    map[string]authenticationv1.ExtraValue{CredentialIDExtraKey: {testTokenID}},
			},
		},
		{
			name:       "no kkp prefix",
			token:      "abc123_" + testTokenID + ":" + testSecret,
			want:       DecisionReject,
			wantReason: "malformed token",
		},
		{
			name:       "wrong cluster part",
			token:      "kkp_cb_" + testTokenID + ":" + testSecret,
			want:       DecisionReject,
			wantReason: "another cluster",
		},
		{
			name:       "token ID too short",
			token:      "kkp_ca_abc123:" + testSecret,
			want:       DecisionReject,
			wantReason: "invalid token ID",
		},
		{
			name:       "token ID with uppercase",
			token:      "kkp_ca_ABCDEFGH1234:" + testSecret,
			want:       DecisionReject,
			wantReason: "invalid token ID",
		},
		{
			name:       "token ID too long",
			token:      "kkp_ca_" + strings.Repeat("a", 33) + ":" + testSecret,
			want:       DecisionReject,
			wantReason: "invalid token ID",
		},
		{
			name:       "missing secret",
			token:      "kkp_ca_" + testTokenID + ":",
			want:       DecisionReject,
			wantReason: "malformed token",
		},
		{
			name:       "missing colon",
			token:      "kkp_ca_" + testTokenID,
			want:       DecisionReject,
			wantReason: "malformed token",
		},
		{
			name:       "second underscore in cluster part",
			token:      "kkp_ca_x_" + testTokenID + ":" + testSecret,
			want:       DecisionReject,
			wantReason: "malformed token",
		},
		{
			name:       "random garbage",
			token:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig",
			want:       DecisionReject,
			wantReason: "malformed token",
		},
		{
			name:       "unknown token ID",
			token:      "kkp_ca_zzzzzzzzzzzz:" + testSecret,
			want:       DecisionReject,
			wantReason: "token not found",
		},
		{
			name: "token status not evaluated yet",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.tokens[testTokenID].Status.State = "" })
			},
			token:      testTokenValue(),
			want:       DecisionUnavailable,
			wantReason: "not been evaluated",
		},
		{
			name: "token observed generation lags",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.tokens[testTokenID].Status.ObservedGeneration = 2 })
			},
			token:      testTokenValue(),
			want:       DecisionUnavailable,
			wantReason: "not been evaluated",
		},
		{
			name: "token disabled",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) {
					s.tokens[testTokenID].Status.State = kubermaticv1.UserClusterTokenDisabled
					s.tokens[testTokenID].Status.Reason = kubermaticv1.UserClusterTokenExpired
				})
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "token is disabled (Expired)",
		},
		{
			name: "token expired, inside clock skew",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) {
					s.tokens[testTokenID].Spec.ExpirationTime = metav1.Time{Time: testNow.Add(-10 * time.Second)}
				})
			},
			token: testTokenValue(),
			want:  DecisionAllow,
			wantUser: &authenticationv1.UserInfo{
				Username: "alice@example.com",
				UID:      testUserID,
				Groups:   []string{"oidc:team-payments", "oidc:kkp-users", "system:authenticated"},
				Extra:    map[string]authenticationv1.ExtraValue{CredentialIDExtraKey: {testTokenID}},
			},
		},
		{
			name: "token expired, beyond clock skew",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) {
					s.tokens[testTokenID].Spec.ExpirationTime = metav1.Time{Time: testNow.Add(-31 * time.Second)}
				})
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "expired",
		},
		{
			name: "cluster UID mismatch (cluster recreated with same name)",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.tokens[testTokenID].Spec.ClusterUID = "ca-uid-2" })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "previous incarnation",
		},
		{
			name: "spec cluster ID mismatch",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.tokens[testTokenID].Spec.ClusterID = "cb" })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "another cluster",
		},
		{
			name:       "wrong secret",
			token:      "kkp_ca_" + testTokenID + ":wrong-secret",
			want:       DecisionReject,
			wantReason: "secret does not match",
		},
		{
			name: "idle timeout passed since last use",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) {
					last := testNow.Add(-25 * time.Hour)
					s.tokens[testTokenID].Status.LastUsedTime = &metav1.Time{Time: last}
				})
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "not been used recently enough",
		},
		{
			name: "idle timeout passed, never used (issue time old)",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) {
					s.tokens[testTokenID].Spec.IssueTime = metav1.Time{Time: testNow.Add(-25 * time.Hour)}
				})
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "not been used recently enough",
		},
		{
			name: "idle timeout disabled",
			prepare: func(store *fakeStore, cfg *AuthenticatorConfig) {
				cfg.IdleTimeout = 0
				store.mutate(func(s *fakeStore) {
					last := testNow.Add(-100 * 24 * time.Hour)
					s.tokens[testTokenID].Status.LastUsedTime = &metav1.Time{Time: last}
				})
			},
			token: testTokenValue(),
			want:  DecisionAllow,
			wantUser: &authenticationv1.UserInfo{
				Username: "alice@example.com",
				UID:      testUserID,
				Groups:   []string{"oidc:team-payments", "oidc:kkp-users", "system:authenticated"},
				Extra:    map[string]authenticationv1.ExtraValue{CredentialIDExtraKey: {testTokenID}},
			},
		},
		{
			name: "user attribute missing",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { delete(s.attributes, testUserID) })
			},
			token:      testTokenValue(),
			want:       DecisionUnavailable,
			wantReason: "attribute has not been created",
		},
		{
			name: "user attribute not evaluated yet",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.State = "" })
			},
			token:      testTokenValue(),
			want:       DecisionUnavailable,
			wantReason: "not been evaluated",
		},
		{
			name: "user attribute observed generation lags",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.ObservedGeneration = 2 })
			},
			token:      testTokenValue(),
			want:       DecisionUnavailable,
			wantReason: "not been evaluated",
		},
		{
			name: "user attribute disabled",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) {
					s.attributes[testUserID].Status.State = kubermaticv1.UserClusterTokenDisabled
					s.attributes[testUserID].Status.Reason = kubermaticv1.UserClusterAttributeNotProjectMember
				})
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "NotProjectMember",
		},
		{
			name: "username starts with system:",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Username = "system:admin" })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "username is reserved",
		},
		{
			name: "username empty",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Username = "" })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "no username",
		},
		{
			name: "group starts with system:",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Groups = []string{"system:masters"} })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "reserved",
		},
		{
			name: "group is a KKP internal owners group",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Groups = []string{"owners-c4wf2mgh"} })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "reserved",
		},
		{
			name: "group is a KKP internal editors group",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Groups = []string{"editors-c4wf2mgh"} })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "reserved",
		},
		{
			name: "group is a KKP internal viewers group",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Groups = []string{"viewers-c4wf2mgh"} })
			},
			token:      testTokenValue(),
			want:       DecisionReject,
			wantReason: "reserved",
		},
		{
			name: "group that merely starts with owners is fine",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Groups = []string{"ownership-team"} })
			},
			token: testTokenValue(),
			want:  DecisionAllow,
			wantUser: &authenticationv1.UserInfo{
				Username: "alice@example.com",
				UID:      testUserID,
				Groups:   []string{"oidc:ownership-team", "system:authenticated"},
				Extra:    map[string]authenticationv1.ExtraValue{CredentialIDExtraKey: {testTokenID}},
			},
		},
		{
			name: "no groups at all",
			prepare: func(store *fakeStore, _ *AuthenticatorConfig) {
				store.mutate(func(s *fakeStore) { s.attributes[testUserID].Status.Groups = nil })
			},
			token: testTokenValue(),
			want:  DecisionAllow,
			wantUser: &authenticationv1.UserInfo{
				Username: "alice@example.com",
				UID:      testUserID,
				Groups:   []string{"system:authenticated"},
				Extra:    map[string]authenticationv1.ExtraValue{CredentialIDExtraKey: {testTokenID}},
			},
		},
		{
			name: "custom group prefix",
			prepare: func(_ *fakeStore, cfg *AuthenticatorConfig) {
				cfg.GroupPrefix = "idp:"
			},
			token: testTokenValue(),
			want:  DecisionAllow,
			wantUser: &authenticationv1.UserInfo{
				Username: "alice@example.com",
				UID:      testUserID,
				Groups:   []string{"idp:team-payments", "idp:kkp-users", "system:authenticated"},
				Extra:    map[string]authenticationv1.ExtraValue{CredentialIDExtraKey: {testTokenID}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore()
			authenticator := newTestAuthenticator(store, nil, func() time.Time { return testNow }, func(cfg *AuthenticatorConfig) {
				if test.prepare != nil {
					test.prepare(store, cfg)
				}
			})

			result := authenticator.Authenticate(context.Background(), test.token)

			if result.Decision != test.want {
				t.Fatalf("got decision %d (%s), want %d", result.Decision, result.Reason, test.want)
			}
			if test.wantReason != "" && !strings.Contains(result.Reason, test.wantReason) {
				t.Errorf("got reason %q, want it to contain %q", result.Reason, test.wantReason)
			}
			if test.wantUser != nil {
				if result.User == nil {
					t.Fatal("got no user, want one")
				}
				if result.User.Username != test.wantUser.Username {
					t.Errorf("username: got %q, want %q", result.User.Username, test.wantUser.Username)
				}
				if result.User.UID != test.wantUser.UID {
					t.Errorf("uid: got %q, want %q", result.User.UID, test.wantUser.UID)
				}
				if strings.Join(result.User.Groups, ",") != strings.Join(test.wantUser.Groups, ",") {
					t.Errorf("groups: got %v, want %v", result.User.Groups, test.wantUser.Groups)
				}
				if !extraEqual(result.User.Extra, test.wantUser.Extra) {
					t.Errorf("extra: got %v, want %v", result.User.Extra, test.wantUser.Extra)
				}
			}
		})
	}
}

func extraEqual(got, want map[string]authenticationv1.ExtraValue) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		other, ok := got[k]
		if !ok || strings.Join(other, ",") != strings.Join(v, ",") {
			return false
		}
	}
	return true
}

// Rule 2: malformed tokens and tokens for other clusters are rejected
// without any store lookup, so a flood of random tokens costs no cache work.
func TestAuthenticateMalformedTokensDoNotHitTheStore(t *testing.T) {
	store := newFakeStore()
	store.mutate(func(s *fakeStore) { s.synced = false })

	authenticator := newTestAuthenticator(store, nil, func() time.Time { return testNow }, nil)

	badTokens := []string{
		"",
		"kkp",
		"kkp_",
		"kkp_ca",
		"kkp_ca_abc",
		"kkp_ca_" + testTokenID,
		"kkp_ca_" + testTokenID + ":",
		":secret",
		"kkp_ca_" + testTokenID + "::secret",
		"kkp_cb_" + testTokenID + ":" + testSecret,
		"Bearer " + testTokenValue(),
	}

	for _, token := range badTokens {
		result := authenticator.Authenticate(context.Background(), token)
		if result.Decision != DecisionReject {
			t.Errorf("token %q: got decision %d, want %d", token, result.Decision, DecisionReject)
		}
	}

	if lookups := store.lookups(); lookups != 0 {
		t.Errorf("got %d store lookups for malformed tokens, want 0", lookups)
	}
}

// Rule 4: while the cache has not synced, or when it is stale, the webhook
// must refuse to decide (503) instead of answering a cached rejection.
func TestAuthenticateUnavailableStates(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(store *fakeStore)
	}{
		{
			name: "cache not synced",
			prepare: func(store *fakeStore) {
				store.mutate(func(s *fakeStore) { s.synced = false })
			},
		},
		{
			name: "cache stale beyond max staleness",
			prepare: func(store *fakeStore) {
				store.mutate(func(s *fakeStore) { s.lastContact = testNow.Add(-3 * time.Minute) })
			},
		},
		{
			name: "cache never had contact",
			prepare: func(store *fakeStore) {
				store.mutate(func(s *fakeStore) { s.lastContact = time.Time{} })
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore()
			test.prepare(store)
			authenticator := newTestAuthenticator(store, nil, func() time.Time { return testNow }, nil)

			result := authenticator.Authenticate(context.Background(), testTokenValue())
			if result.Decision != DecisionUnavailable {
				t.Fatalf("got decision %d (%s), want %d", result.Decision, result.Reason, int(DecisionUnavailable))
			}
		})
	}
}

func TestAuthenticateStoreErrorsAreUnavailable(t *testing.T) {
	store := newFakeStore()
	store.mutate(func(s *fakeStore) { s.getErr = errors.New("informer exploded") })

	authenticator := newTestAuthenticator(store, nil, func() time.Time { return testNow }, nil)

	result := authenticator.Authenticate(context.Background(), testTokenValue())
	if result.Decision != DecisionUnavailable {
		t.Fatalf("got decision %d (%s), want %d", result.Decision, result.Reason, int(DecisionUnavailable))
	}
}

// Rule 10: lastUsedTime is written at most once per interval per token.
func TestAuthenticateLastUsedThrottle(t *testing.T) {
	store := newFakeStore()
	writer := &fakeWriter{}

	now := testNow
	authenticator := newTestAuthenticator(store, writer, func() time.Time { return now }, nil)

	for range 3 {
		if result := authenticator.Authenticate(context.Background(), testTokenValue()); result.Decision != DecisionAllow {
			t.Fatalf("got decision %d, want allow", result.Decision)
		}
	}
	waitForWrites(t, writer, 1)

	// still inside the interval
	now = now.Add(time.Minute)
	store.mutate(func(s *fakeStore) { s.lastContact = now })
	authenticator.Authenticate(context.Background(), testTokenValue())
	waitForWrites(t, writer, 1)

	// beyond the interval
	now = now.Add(5 * time.Minute)
	store.mutate(func(s *fakeStore) { s.lastContact = now })
	result := authenticator.Authenticate(context.Background(), testTokenValue())
	if result.Decision != DecisionAllow {
		t.Fatalf("got decision %d (%s), want allow", result.Decision, result.Reason)
	}
	waitForWrites(t, writer, 2)

	if got := writer.writes[len(writer.writes)-1].tokenID; got != testTokenID {
		t.Errorf("last write for token %q, want %q", got, testTokenID)
	}
}

func waitForWrites(t *testing.T, writer *fakeWriter, want int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for writer.count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("got %d writes, want %d", writer.count(), want)
		}
		time.Sleep(time.Millisecond)
	}
	if writer.count() != want {
		t.Fatalf("got %d writes, want %d", writer.count(), want)
	}
}

// Rejected tokens never trigger a lastUsedTime write.
func TestAuthenticateNoLastUsedOnReject(t *testing.T) {
	store := newFakeStore()
	writer := &fakeWriter{}

	authenticator := newTestAuthenticator(store, writer, func() time.Time { return testNow }, nil)

	for range 3 {
		authenticator.Authenticate(context.Background(), "kkp_ca_"+testTokenID+":wrong")
	}

	if writer.count() != 0 {
		t.Errorf("got %d lastUsedTime writes for a rejected token, want 0", writer.count())
	}
}

// Benchmark of the fast rejection path: malformed tokens must cost no store
// lookup. The store counts lookups; the benchmark fails if one happens.
func BenchmarkRejectMalformedTokens(b *testing.B) {
	store := newFakeStore()
	authenticator := newTestAuthenticator(store, nil, func() time.Time { return testNow }, nil)

	tokens := []string{
		"",
		"garbage",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig",
		"kkp_cb_" + testTokenID + ":" + testSecret,
		"kkp_ca_short:" + testSecret,
		"kkp_ca_" + strings.Repeat("x", 40) + ":" + testSecret,
		"kkp_ca_" + testTokenID,
	}

	b.ResetTimer()
	for i := range b.N {
		result := authenticator.Authenticate(context.Background(), tokens[i%len(tokens)])
		if result.Decision != DecisionReject {
			b.Fatalf("got decision %d, want reject", result.Decision)
		}
	}
	b.StopTimer()

	if lookups := store.lookups(); lookups != 0 {
		b.Fatalf("%d store lookups on the rejection path, want 0", lookups)
	}
}

func BenchmarkAuthenticateAllow(b *testing.B) {
	store := newFakeStore()
	authenticator := newTestAuthenticator(store, nil, func() time.Time { return testNow }, nil)

	b.ResetTimer()
	for range b.N {
		result := authenticator.Authenticate(context.Background(), testTokenValue())
		if result.Decision != DecisionAllow {
			b.Fatalf("got decision %d, want allow", result.Decision)
		}
	}
}
