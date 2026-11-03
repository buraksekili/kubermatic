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

package tokenwebhook_test

import (
	"strings"
	"testing"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	kkpresources "k8c.io/kubermatic/v2/pkg/resources"
	tokenwebhook "k8c.io/kubermatic/v2/pkg/resources/token-webhook"
	"k8c.io/kubermatic/v2/pkg/version/kubermatic"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestData(idleTimeout string) *kkpresources.TemplateData {
	cluster := &kubermaticv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "abc123",
			UID:  "cluster-uid-1",
		},
		Spec: kubermaticv1.ClusterSpec{
			Cloud: kubermaticv1.CloudSpec{Fake: &kubermaticv1.FakeCloudSpec{}},
		},
		Status: kubermaticv1.ClusterStatus{
			NamespaceName: "cluster-abc123",
		},
	}

	config := &kubermaticv1.KubermaticConfiguration{}
	if idleTimeout != "" {
		config.Spec.UserClusterTokens.IdleTimeout.Duration = mustDuration(idleTimeout)
	}

	return kkpresources.NewTemplateDataBuilder().
		WithCluster(cluster).
		WithDatacenter(&kubermaticv1.Datacenter{Spec: kubermaticv1.DatacenterSpec{Fake: &kubermaticv1.DatacenterSpecFake{}}}).
		WithSeed(&kubermaticv1.Seed{}).
		WithKubermaticConfiguration(config).
		WithVersions(kubermatic.GetFakeVersions()).
		Build()
}

func mustDuration(s string) (d time.Duration) {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestDeploymentReconciler(t *testing.T) {
	name, reconciler := tokenwebhook.DeploymentReconciler(newTestData(""))()

	// replicate what the reconciling framework would normally do
	deployment := &appsv1.Deployment{}
	deployment.SetName(name)

	deployment, err := reconciler(deployment)
	if err != nil {
		t.Fatalf("failed to reconcile Deployment: %v", err)
	}

	if name != tokenwebhook.Name {
		t.Fatalf("deployment name = %q, want %q", name, tokenwebhook.Name)
	}

	if replicas := deployment.Spec.Replicas; replicas == nil || *replicas != 2 {
		t.Fatalf("replicas = %v, want 2", replicas)
	}

	strategy := deployment.Spec.Strategy.RollingUpdate
	if strategy == nil || strategy.MaxUnavailable.IntValue() != 0 || strategy.MaxSurge.IntValue() != 1 {
		t.Fatalf("rolling update = %+v, want maxUnavailable 0, maxSurge 1", strategy)
	}

	if deployment.Spec.Template.Spec.Affinity == nil || deployment.Spec.Template.Spec.Affinity.PodAntiAffinity == nil {
		t.Fatal("expected anti-affinity on the pod template")
	}

	container := deployment.Spec.Template.Spec.Containers[0]
	if container.Image != tokenwebhook.Image() {
		t.Fatalf("image = %q, want %q (unrewritten placeholder)", container.Image, tokenwebhook.Image())
	}

	wantArgs := []string{
		"-cluster-id=abc123",
		"-cluster-uid=cluster-uid-1",
		"-namespace=cluster-abc123",
		"-listen-address=:8443",
		"-client-common-name=" + tokenwebhook.ClientCommonName,
		"-max-staleness=2m0s",
		// default idle timeout from the KubermaticConfiguration defaulting
		"-idle-timeout=24h0m0s",
	}
	args := strings.Join(container.Args, " ")
	for _, want := range wantArgs {
		if !strings.Contains(args, want) {
			t.Errorf("args %q do not contain %q", args, want)
		}
	}

	if container.ReadinessProbe == nil || container.ReadinessProbe.HTTPGet == nil || container.ReadinessProbe.HTTPGet.Path != "/readyz" {
		t.Errorf("readiness probe = %#v, want HTTP /readyz", container.ReadinessProbe)
	}
	if container.LivenessProbe == nil || container.LivenessProbe.HTTPGet == nil || container.LivenessProbe.HTTPGet.Path != "/healthz" {
		t.Errorf("liveness probe = %#v, want HTTP /healthz", container.LivenessProbe)
	}

	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.Name == "client-ca" {
			for _, item := range volume.Secret.Items {
				if item.Key == "ca.key" {
					t.Error("the client CA key must not be mounted into the webhook pod")
				}
			}
		}
	}
}

func TestDeploymentIdleTimeoutFromConfiguration(t *testing.T) {
	_, reconciler := tokenwebhook.DeploymentReconciler(newTestData("30m"))()
	deployment, err := reconciler(&appsv1.Deployment{})
	if err != nil {
		t.Fatalf("failed to reconcile Deployment: %v", err)
	}

	args := strings.Join(deployment.Spec.Template.Spec.Containers[0].Args, " ")
	if !strings.Contains(args, "-idle-timeout=30m0s") {
		t.Fatalf("args %q do not contain the configured idle timeout", args)
	}
}

func TestAPIServerFlags(t *testing.T) {
	flags := tokenwebhook.APIServerFlags(newTestData("").KubermaticConfiguration())
	joined := strings.Join(flags, " ")

	for _, want := range []string{
		"--authentication-token-webhook-config-file /etc/kubernetes/kkp-token-webhook/webhook.kubeconfig",
		"--authentication-token-webhook-version v1",
		"--authentication-token-webhook-cache-ttl 1m0s",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("flags %q do not contain %q", joined, want)
		}
	}
}

func TestServiceAndPDBReconcilers(t *testing.T) {
	_, serviceReconciler := tokenwebhook.ServiceReconciler()()
	service, err := serviceReconciler(&corev1.Service{})
	if err != nil {
		t.Fatalf("failed to reconcile Service: %v", err)
	}
	if service.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Fatalf("service type = %q, want ClusterIP", service.Spec.Type)
	}
	if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != tokenwebhook.ServicePort || service.Spec.Ports[0].TargetPort.IntValue() != tokenwebhook.ListenPort {
		t.Fatalf("service ports = %#v", service.Spec.Ports)
	}

	_, pdbReconciler := tokenwebhook.PodDisruptionBudgetReconciler()()
	pdb, err := pdbReconciler(&policyv1.PodDisruptionBudget{})
	if err != nil {
		t.Fatalf("failed to reconcile PodDisruptionBudget: %v", err)
	}
	if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntValue() != 1 {
		t.Fatalf("PDB minAvailable = %#v, want 1", pdb.Spec.MinAvailable)
	}
}

func TestRoleReconciler(t *testing.T) {
	name, reconciler := tokenwebhook.RoleReconciler()
	role, err := reconciler(&rbacv1.Role{})
	if err != nil {
		t.Fatalf("failed to reconcile Role: %v", err)
	}

	if name != "kubermatic:kkp-token-webhook" {
		t.Fatalf("role name = %q, want kubermatic:kkp-token-webhook", name)
	}

	var readRule, statusRule bool
	for _, rule := range role.Rules {
		if strings.Contains(strings.Join(rule.Resources, ","), "userclustertokens/status") {
			statusRule = true
			if len(rule.Verbs) != 1 || rule.Verbs[0] != "patch" {
				t.Errorf("status rule verbs = %v, want [patch]", rule.Verbs)
			}
		} else {
			readRule = true
			resources := strings.Join(rule.Resources, ",")
			for _, want := range []string{"userclustertokens", "userclusterattributes"} {
				if !strings.Contains(resources, want) {
					t.Errorf("read rule resources %q do not contain %q", resources, want)
				}
			}
			for _, verb := range rule.Verbs {
				if verb != "get" && verb != "list" && verb != "watch" {
					t.Errorf("read rule has unexpected verb %q", verb)
				}
			}
		}
	}

	if !readRule || !statusRule {
		t.Fatalf("expected a read rule and a status patch rule, got %#v", role.Rules)
	}
}
