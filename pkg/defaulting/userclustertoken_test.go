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

package defaulting_test

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/defaulting"
)

func TestDefaultUserClusterTokens(t *testing.T) {
	config := &kubermaticv1.KubermaticConfiguration{}

	got, err := defaulting.DefaultConfiguration(config, zap.NewNop().Sugar())
	if err != nil {
		t.Fatalf("defaulting failed: %v", err)
	}

	tokens := got.Spec.UserClusterTokens
	if tokens.DefaultLifetime.Duration != 24*time.Hour {
		t.Errorf("defaultLifetime: got %v, want 24h", tokens.DefaultLifetime)
	}
	if tokens.MaxLifetime.Duration != 7*24*time.Hour {
		t.Errorf("maxLifetime: got %v, want 168h", tokens.MaxLifetime)
	}
	if tokens.IdleTimeout.Duration != 24*time.Hour {
		t.Errorf("idleTimeout: got %v, want 24h", tokens.IdleTimeout)
	}
	if tokens.WebhookCacheTTL.Duration != 60*time.Second {
		t.Errorf("webhookCacheTTL: got %v, want 60s", tokens.WebhookCacheTTL)
	}
	if tokens.MaxActivePerUserPerCluster != 10 {
		t.Errorf("maxActivePerUserPerCluster: got %d, want 10", tokens.MaxActivePerUserPerCluster)
	}
}

func TestDefaultUserClusterTokensKeepsUserValues(t *testing.T) {
	config := &kubermaticv1.KubermaticConfiguration{
		Spec: kubermaticv1.KubermaticConfigurationSpec{
			UserClusterTokens: kubermaticv1.KubermaticUserClusterTokensConfiguration{
				DefaultLifetime:            metav1Duration(time.Hour),
				MaxLifetime:                metav1Duration(48 * time.Hour),
				IdleTimeout:                metav1Duration(time.Hour),
				WebhookCacheTTL:            metav1Duration(30 * time.Second),
				MaxActivePerUserPerCluster: 3,
			},
		},
	}

	got, err := defaulting.DefaultConfiguration(config, zap.NewNop().Sugar())
	if err != nil {
		t.Fatalf("defaulting failed: %v", err)
	}

	tokens := got.Spec.UserClusterTokens
	if tokens.DefaultLifetime.Duration != time.Hour ||
		tokens.MaxLifetime.Duration != 48*time.Hour ||
		tokens.IdleTimeout.Duration != time.Hour ||
		tokens.WebhookCacheTTL.Duration != 30*time.Second ||
		tokens.MaxActivePerUserPerCluster != 3 {
		t.Fatalf("user-provided values were overwritten: %+v", tokens)
	}
}

func metav1Duration(d time.Duration) metav1.Duration {
	return metav1.Duration{Duration: d}
}
