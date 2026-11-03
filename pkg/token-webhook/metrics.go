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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Result label values for the request metrics.
const (
	ResultAllow        = "allow"
	ResultReject       = "reject"
	ResultUnavailable  = "unavailable"
	ResultBadRequest   = "bad_request"
	ResultMethodDenied = "method_not_allowed"
)

// Metrics holds the Prometheus metrics of the webhook. All of them are
// registered on a private registry handed to the health server.
type Metrics struct {
	requests       *prometheus.CounterVec
	requestDurs    *prometheus.HistogramVec
	cacheSize      *prometheus.GaugeVec
	lastUsedWrites prometheus.Counter
}

// NewMetrics returns the webhook metrics registered on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kkp_token_webhook_requests_total",
			Help: "Number of TokenReview requests by result.",
		}, []string{"result"}),
		requestDurs: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "kkp_token_webhook_request_duration_seconds",
			Help: "Time spent answering a TokenReview request, by result.",
		}, []string{"result"}),
		cacheSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kkp_token_webhook_cache_size",
			Help: "Number of objects held in the informer caches, by resource.",
		}, []string{"resource"}),
		lastUsedWrites: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "kkp_token_webhook_last_used_patches_total",
			Help: "Number of status.lastUsedTime patches sent to the seed API.",
		}),
	}

	reg.MustRegister(m.requests, m.requestDurs, m.cacheSize, m.lastUsedWrites)

	return m
}

// ObserveRequest records one TokenReview request.
func (m *Metrics) ObserveRequest(result string, duration time.Duration) {
	m.requests.WithLabelValues(result).Inc()
	m.requestDurs.WithLabelValues(result).Observe(duration.Seconds())
}

// ObserveCacheSize records the number of cached objects of one resource.
func (m *Metrics) ObserveCacheSize(resource string, size int) {
	m.cacheSize.WithLabelValues(resource).Set(float64(size))
}

// ObserveLastUsedPatch records one throttled lastUsedTime patch.
func (m *Metrics) ObserveLastUsedPatch() {
	m.lastUsedWrites.Inc()
}
