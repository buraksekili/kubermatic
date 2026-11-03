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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	tokenwebhookresources "k8c.io/kubermatic/v2/pkg/resources/token-webhook"
	authenticationv1 "k8s.io/api/authentication/v1"
)

func newTestServer(t *testing.T, store *fakeStore) (*httptest.Server, *Metrics, *prometheus.Registry) {
	t.Helper()

	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	server := &Server{
		Authenticator: newTestAuthenticator(store, nil, func() time.Time { return testNow }, nil),
		Metrics:       metrics,
		Log:           zap.NewNop().Sugar(),
		Ready: func() bool {
			return store.HasSynced() && time.Since(store.LastContact()) <= 2*time.Minute
		},
	}

	mux := http.NewServeMux()
	server.RegisterTokenReview(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, metrics, registry
}

// postTokenReview posts a TokenReview and returns the status code and body.
// The response body is closed before returning.
func postTokenReview(t *testing.T, url, body string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	return resp.StatusCode, string(payload)
}

// doGet issues a GET and returns status code and body, with the body closed.
func doGet(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	return resp.StatusCode, string(payload)
}

// wantHandshakeFailure issues a GET and requires it to fail (TLS handshake).
func wantHandshakeFailure(t *testing.T, client *http.Client, url string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatalf("request succeeded with %d, want a TLS handshake failure", resp.StatusCode)
	}
}

func tokenReviewBody(apiVersion, kind, token string) string {
	return fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"spec":{"token":%q}}`, apiVersion, kind, token)
}

// Rules 1 and 7: only authentication.k8s.io/v1 TokenReview is accepted, and
// an accepted token is answered in the exact TokenReview shape the apiserver
// decodes, with the request TypeMeta echoed.
func TestTokenReviewEndpoint(t *testing.T) {
	store := newFakeStore()
	ts, _, _ := newTestServer(t, store)

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{
			name:       "v1 TokenReview",
			body:       tokenReviewBody("authentication.k8s.io/v1", "TokenReview", testTokenValue()),
			wantStatus: http.StatusOK,
		},
		{
			name:       "v1beta1 is rejected",
			body:       tokenReviewBody("authentication.k8s.io/v1beta1", "TokenReview", testTokenValue()),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong group",
			body:       tokenReviewBody("authorization.k8s.io/v1", "TokenReview", testTokenValue()),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong kind",
			body:       tokenReviewBody("authentication.k8s.io/v1", "SubjectAccessReview", testTokenValue()),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "not json",
			body:       "garbage",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown field",
			body:       `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"x","mystery":1}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing apiVersion",
			body:       `{"kind":"TokenReview","spec":{"token":"x"}}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			method := http.MethodPost
			if test.method != "" {
				method = test.method
			}

			req, err := http.NewRequestWithContext(t.Context(), method, ts.URL+TokenReviewPath, strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != test.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("got status %d (%s), want %d", resp.StatusCode, body, test.wantStatus)
			}
		})
	}
}

func TestTokenReviewGetIsNotAllowed(t *testing.T) {
	store := newFakeStore()
	ts, _, _ := newTestServer(t, store)

	code, _ := doGet(t, http.DefaultClient, ts.URL+TokenReviewPath)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want %d", code, http.StatusMethodNotAllowed)
	}
}

func TestTokenReviewOversizedBody(t *testing.T) {
	store := newFakeStore()
	ts, _, _ := newTestServer(t, store)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"` + strings.Repeat("a", 128*1024) + `"}}`
	code, _ := postTokenReview(t, ts.URL+TokenReviewPath, body)
	if code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", code, http.StatusBadRequest)
	}
}

func TestTokenReviewAllowResponseShape(t *testing.T) {
	store := newFakeStore()
	ts, _, _ := newTestServer(t, store)

	status, body := postTokenReview(t, ts.URL+TokenReviewPath, tokenReviewBody("authentication.k8s.io/v1", "TokenReview", testTokenValue()))
	if status != http.StatusOK {
		t.Fatalf("got status %d (%s), want 200", status, body)
	}

	review := authenticationv1.TokenReview{}
	if err := json.Unmarshal([]byte(body), &review); err != nil {
		t.Fatalf("response is not a TokenReview: %v\n%s", err, body)
	}

	// the apiserver decodes the reply with its own codec and needs the echo
	if review.APIVersion != "authentication.k8s.io/v1" || review.Kind != "TokenReview" {
		t.Errorf("TypeMeta not echoed: %s / %s", review.APIVersion, review.Kind)
	}
	if !review.Status.Authenticated {
		t.Errorf("status.authenticated is false")
	}
	if review.Status.User.Username != "alice@example.com" {
		t.Errorf("username: got %q", review.Status.User.Username)
	}
	if review.Status.User.UID != testUserID {
		t.Errorf("uid: got %q", review.Status.User.UID)
	}
	wantGroups := "oidc:team-payments,oidc:kkp-users,system:authenticated"
	if got := strings.Join(review.Status.User.Groups, ","); got != wantGroups {
		t.Errorf("groups: got %q, want %q", got, wantGroups)
	}
	if got := review.Status.User.Extra[CredentialIDExtraKey]; len(got) != 1 || got[0] != testTokenID {
		t.Errorf("extra[%s]: got %v, want [%s]", CredentialIDExtraKey, got, testTokenID)
	}
	if review.Status.Error != "" {
		t.Errorf("status.error set on allow: %q", review.Status.Error)
	}
}

func TestTokenReviewRejectResponseShape(t *testing.T) {
	store := newFakeStore()
	ts, _, _ := newTestServer(t, store)

	// a valid, well-formed token for this cluster with a wrong secret
	status, body := postTokenReview(t, ts.URL+TokenReviewPath,
		tokenReviewBody("authentication.k8s.io/v1", "TokenReview", "kkp_ca_"+testTokenID+":wrong-secret"))

	if status != http.StatusOK {
		t.Fatalf("got status %d (%s), want 200: a refused token is a successful call", status, body)
	}

	review := authenticationv1.TokenReview{}
	if err := json.Unmarshal([]byte(body), &review); err != nil {
		t.Fatalf("response is not a TokenReview: %v", err)
	}
	if review.Status.Authenticated {
		t.Error("status.authenticated is true")
	}
	if !strings.Contains(review.Status.Error, "secret does not match") {
		t.Errorf("status.error: got %q", review.Status.Error)
	}
	if review.Status.User.Username != "" || len(review.Status.User.Groups) > 0 {
		t.Errorf("user set on rejection: %+v", review.Status.User)
	}
}

func TestTokenReviewUnavailableIs503(t *testing.T) {
	store := newFakeStore()
	store.mutate(func(s *fakeStore) { s.synced = false })
	ts, _, _ := newTestServer(t, store)

	status, body := postTokenReview(t, ts.URL+TokenReviewPath,
		tokenReviewBody("authentication.k8s.io/v1", "TokenReview", testTokenValue()))

	if status != http.StatusServiceUnavailable {
		t.Fatalf("got status %d (%s), want 503", status, body)
	}
}

func TestHealthEndpoints(t *testing.T) {
	_, _, registry := newTestServer(t, newFakeStore())

	ready := false
	server := &Server{Ready: func() bool { return ready }}
	mux := http.NewServeMux()
	server.RegisterHealth(mux, registry)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	get := func(path string) int {
		code, _ := doGet(t, http.DefaultClient, ts.URL+path)
		return code
	}

	if code := get("/healthz"); code != http.StatusOK {
		t.Errorf("healthz not ready: got %d, want 200 (liveness only means the process is up)", code)
	}
	if code := get("/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readyz not ready: got %d, want 503", code)
	}

	ready = true

	if code := get("/healthz"); code != http.StatusOK {
		t.Errorf("healthz ready: got %d, want 200", code)
	}
	if code := get("/readyz"); code != http.StatusOK {
		t.Errorf("readyz ready: got %d, want 200", code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	store := newFakeStore()
	ts, metrics, registry := newTestServer(t, store)

	postTokenReview(t, ts.URL+TokenReviewPath, tokenReviewBody("authentication.k8s.io/v1", "TokenReview", testTokenValue()))
	postTokenReview(t, ts.URL+TokenReviewPath, tokenReviewBody("authentication.k8s.io/v1", "TokenReview", "kkp_ca_zzzzzzzzzzzz:x"))
	postTokenReview(t, ts.URL+TokenReviewPath, tokenReviewBody("authentication.k8s.io/v1beta1", "TokenReview", "x"))
	postTokenReview(t, ts.URL+TokenReviewPath, tokenReviewBody("authentication.k8s.io/v1", "TokenReview", "kkp_cb_"+testTokenID+":x"))

	server := &Server{Ready: func() bool { return true }}
	mux := http.NewServeMux()
	server.RegisterHealth(mux, registry)
	healthTS := httptest.NewServer(mux)
	t.Cleanup(healthTS.Close)

	code, exposition := doGet(t, http.DefaultClient, healthTS.URL+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("got status %d, want 200", code)
	}

	count, err := testutil.GatherAndCount(registry)
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	if count < 4 {
		t.Errorf("registry exposes %d metric families, want at least the 4 webhook metrics", count)
	}

	if got := testutil.ToFloat64(metrics.requests.WithLabelValues(ResultAllow)); got != 1 {
		t.Errorf("allow requests: got %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.requests.WithLabelValues(ResultReject)); got != 2 {
		t.Errorf("reject requests: got %v, want 2", got)
	}
	if got := testutil.ToFloat64(metrics.requests.WithLabelValues(ResultBadRequest)); got != 1 {
		t.Errorf("bad_request requests: got %v, want 1", got)
	}

	metrics.ObserveCacheSize("userclustertokens", 7)
	if got := testutil.ToFloat64(metrics.cacheSize.WithLabelValues("userclustertokens")); got != 7 {
		t.Errorf("cache size: got %v, want 7", got)
	}

	metrics.ObserveLastUsedPatch()
	metrics.ObserveLastUsedPatch()
	if got := testutil.ToFloat64(metrics.lastUsedWrites); got != 2 {
		t.Errorf("last used patches: got %v, want 2", got)
	}

	if !strings.Contains(exposition, "kkp_token_webhook_requests_total") {
		t.Error("metrics exposition does not contain kkp_token_webhook_requests_total")
	}
}

// The TokenReview path must stay identical to the URL WP3 writes into the
// kube-apiserver webhook kubeconfig.
func TestTokenReviewPathMatchesWP3Rendering(t *testing.T) {
	resources := tokenwebhookresources.URL("cluster-ca")
	if !strings.HasSuffix(resources, TokenReviewPath) {
		t.Errorf("kube-apiserver URL %q does not end in the served path %q", resources, TokenReviewPath)
	}
}
