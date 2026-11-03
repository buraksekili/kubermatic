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

package main

import (
	"flag"
	"testing"
	"time"
)

// validOptions matches the flags WP3 renders for the Deployment.
func validOptions() options {
	opts := options{
		clusterID:        "abc123",
		clusterUID:       "0f4c0e2a-0000-0000-0000-000000000001",
		namespace:        "cluster-abc123",
		listenAddress:    ":8443",
		healthAddress:    ":8080",
		tlsCertFile:      "/certs/serving.crt",
		tlsKeyFile:       "/certs/serving.key",
		clientCAFile:     "/certs/ca.crt",
		clientCommonName: "kkp-token-webhook-client",
		groupPrefix:      "oidc:",
		clockSkew:        30 * time.Second,
		maxStaleness:     2 * time.Minute,
		idleTimeout:      24 * time.Hour,
		lastUsedInterval: 5 * time.Minute,
	}
	opts.log.Format = "JSON"
	return opts
}

func TestOptionsValidate(t *testing.T) {
	valid := validOptions()
	if err := valid.validate(); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*options)
	}{
		{"empty cluster ID", func(o *options) { o.clusterID = "" }},
		{"cluster ID not a DNS label", func(o *options) { o.clusterID = "ABC_123" }},
		{"empty cluster UID", func(o *options) { o.clusterUID = "" }},
		{"empty namespace", func(o *options) { o.namespace = "" }},
		{"no serving cert", func(o *options) { o.tlsCertFile = "" }},
		{"no serving key", func(o *options) { o.tlsKeyFile = "" }},
		{"no client CA", func(o *options) { o.clientCAFile = "" }},
		{"zero max staleness", func(o *options) { o.maxStaleness = 0 }},
		{"bad log format", func(o *options) { o.log.Format = "yaml" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := validOptions()
			test.mut(&opts)
			if err := opts.validate(); err == nil {
				t.Error("invalid options accepted")
			}
		})
	}
}

// Every flag WP3 renders must exist with the same name and default.
func TestFlagContract(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts := options{}
	opts.addFlags(fs)

	for _, name := range []string{
		"cluster-id", "cluster-uid", "namespace", "listen-address",
		"tls-cert-file", "tls-key-file", "client-ca-file", "client-common-name",
		"health-address", "max-staleness", "idle-timeout",
		"last-used-update-interval", "group-prefix", "clock-skew",
		"kubeconfig", "log-format", "log-debug",
	} {
		if f := fs.Lookup(name); f == nil {
			t.Errorf("flag -%s is missing", name)
		}
	}

	wantDefaults := map[string]string{
		"listen-address":            ":8443",
		"health-address":            ":8080",
		"client-common-name":        "kkp-token-webhook-client",
		"group-prefix":              "oidc:",
		"clock-skew":                "30s",
		"max-staleness":             "2m0s",
		"idle-timeout":              "24h0m0s",
		"last-used-update-interval": "5m0s",
	}
	for name, want := range wantDefaults {
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if got := f.DefValue; got != want {
			t.Errorf("flag -%s default: got %q, want %q", name, got, want)
		}
	}
}
