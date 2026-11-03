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

package apiserver

import (
	"strings"
	"testing"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/resources"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTokenWebhookEnvData(gateEnabled bool) *resources.TemplateData {
	cluster := &kubermaticv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: "abc123"},
		Spec:       kubermaticv1.ClusterSpec{Cloud: kubermaticv1.CloudSpec{Fake: &kubermaticv1.FakeCloudSpec{}}},
		Status: kubermaticv1.ClusterStatus{
			NamespaceName: "cluster-abc123",
			Address: kubermaticv1.ClusterAddress{
				InternalName: "apiserver.cluster-abc123.svc.cluster.local.",
			},
		},
	}

	seed := &kubermaticv1.Seed{
		Spec: kubermaticv1.SeedSpec{
			ProxySettings: &kubermaticv1.ProxySettings{
				HTTPProxy: kubermaticv1.NewProxyValue("http://proxy.example.com:3128"),
			},
		},
	}

	return resources.NewTemplateDataBuilder().
		WithCluster(cluster).
		WithSeed(seed).
		WithUserClusterTokenWebhook(gateEnabled).
		Build()
}

func TestGetEnvVarsTokenWebhookNoProxy(t *testing.T) {
	vars, err := GetEnvVars(newTokenWebhookEnvData(true))
	if err != nil {
		t.Fatalf("failed to get env vars: %v", err)
	}

	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		found := false
		for _, v := range vars {
			if v.Name == name {
				found = true
				if !strings.Contains(v.Value, "kkp-token-webhook.cluster-abc123.svc.cluster.local") {
					t.Errorf("%s = %q, must contain the webhook service FQDN", name, v.Value)
				}
			}
		}
		if !found {
			t.Errorf("env var %s missing", name)
		}
	}
}

func TestGetEnvVarsTokenWebhookDisabledLeavesNoProxyUnchanged(t *testing.T) {
	disabled, err := GetEnvVars(newTokenWebhookEnvData(false))
	if err != nil {
		t.Fatalf("failed to get env vars: %v", err)
	}

	for _, v := range disabled {
		if v.Name != "NO_PROXY" && v.Name != "no_proxy" {
			continue
		}
		if strings.Contains(v.Value, "kkp-token-webhook") {
			t.Errorf("%s = %q, must not mention the webhook with the gate off", v.Name, v.Value)
		}
	}
}
