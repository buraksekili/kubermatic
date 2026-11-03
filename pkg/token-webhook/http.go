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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
)

// TokenReviewPath must match the URL in the kube-apiserver webhook kubeconfig
// rendered by pkg/resources/token-webhook.
const TokenReviewPath = "/tokenreview"

// maxRequestSize caps the accepted TokenReview body. A real TokenReview is a
// few hundred bytes.
const maxRequestSize = 64 * 1024

// Server answers the TokenReview requests of kube-apiserver and serves the
// health and metrics endpoints.
type Server struct {
	Authenticator *Authenticator
	Metrics       *Metrics
	Log           *zap.SugaredLogger
	// Ready reports whether the server should receive TokenReview traffic
	// (informer caches synced and fresh).
	Ready func() bool
}

// RegisterTokenReview registers the TokenReview handler. It is served on the
// TLS listener with mandatory client certificates.
func (s *Server) RegisterTokenReview(mux *http.ServeMux) {
	mux.HandleFunc(TokenReviewPath, s.handleTokenReview)
}

// RegisterHealth registers /healthz, /readyz and /metrics on the plain HTTP
// listener. The metrics endpoint serves the given registry, which holds the
// webhook metrics and the Go and process collectors.
func (s *Server) RegisterHealth(mux *http.ServeMux, registry *prometheus.Registry) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.Ready == nil || !s.Ready() {
			http.Error(w, "informer caches are not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
}

func (s *Server) handleTokenReview(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		s.Metrics.ObserveRequest(ResultMethodDenied, time.Since(start))
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestSize))
	if err != nil {
		s.Metrics.ObserveRequest(ResultBadRequest, time.Since(start))
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}

	review, err := decodeTokenReview(body)
	if err != nil {
		s.Metrics.ObserveRequest(ResultBadRequest, time.Since(start))
		s.Log.Warnw("rejecting unreadable TokenReview", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := s.Authenticator.Authenticate(r.Context(), review.Spec.Token)

	// kube-apiserver only decodes a reply that repeats the TypeMeta of the
	// request, so the decoded review is echoed with its status filled in.
	switch result.Decision {
	case DecisionAllow:
		review.Status = authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User:          *result.User,
		}
	case DecisionReject:
		review.Status = authenticationv1.TokenReviewStatus{
			Authenticated: false,
			Error:         result.Reason,
		}
	case DecisionUnavailable:
		s.Metrics.ObserveRequest(ResultUnavailable, time.Since(start))
		// a 5xx is a failed webhook call for kube-apiserver: it does not
		// cache the answer, unlike an authenticated: false reply
		http.Error(w, result.Reason, http.StatusServiceUnavailable)
		return
	}

	s.Metrics.ObserveRequest(resultLabel(result.Decision), time.Since(start))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		s.Log.Errorw("failed to write TokenReview response", zap.Error(err))
	}
}

func resultLabel(d Decision) string {
	switch d {
	case DecisionAllow:
		return ResultAllow
	case DecisionUnavailable:
		return ResultUnavailable
	default:
		return ResultReject
	}
}

// decodeTokenReview decodes the request body strictly and accepts only
// authentication.k8s.io/v1 TokenReviews. v1beta1 and anything else answer 400:
// kube-apiserver would discard a mismatching response anyway.
func decodeTokenReview(body []byte) (*authenticationv1.TokenReview, error) {
	review := &authenticationv1.TokenReview{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(review); err != nil {
		return nil, fmt.Errorf("decoding TokenReview: %w", err)
	}

	if review.APIVersion != authenticationv1.SchemeGroupVersion.String() {
		return nil, fmt.Errorf("unsupported apiVersion %q, only %s is supported", review.APIVersion, authenticationv1.SchemeGroupVersion.String())
	}
	if review.Kind != "TokenReview" {
		return nil, fmt.Errorf("unsupported kind %q, only TokenReview is supported", review.Kind)
	}

	return review, nil
}
