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
	"testing"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/resources"
	"k8c.io/kubermatic/v2/pkg/resources/certificates/triple"
	tokenwebhook "k8c.io/kubermatic/v2/pkg/resources/token-webhook"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
)

type fakeCertData struct {
	cluster *kubermaticv1.Cluster
	ca      *triple.KeyPair
}

func (d *fakeCertData) Cluster() *kubermaticv1.Cluster      { return d.cluster }
func (d *fakeCertData) GetRootCA() (*triple.KeyPair, error) { return d.ca, nil }

type fakeKubeconfigData struct {
	fakeCertData
	clientCA *triple.KeyPair
}

func (d *fakeKubeconfigData) GetClusterSignerCA(string) (*triple.KeyPair, error) {
	return d.clientCA, nil
}

func newFakeData(t *testing.T) *fakeKubeconfigData {
	t.Helper()

	rootCA, err := triple.NewCAWithConfig("root-ca.example", triple.KeyConfig{})
	if err != nil {
		t.Fatalf("failed to create root CA: %v", err)
	}

	clientCA, err := triple.NewCAWithConfig("kkp-token-webhook-client-ca", triple.KeyConfig{})
	if err != nil {
		t.Fatalf("failed to create client CA: %v", err)
	}

	return &fakeKubeconfigData{
		fakeCertData: fakeCertData{
			cluster: &kubermaticv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{Name: "abc123"},
				Status:     kubermaticv1.ClusterStatus{NamespaceName: "cluster-abc123"},
			},
			ca: rootCA,
		},
		clientCA: clientCA,
	}
}

func TestServingCertificateReconciler(t *testing.T) {
	data := newFakeData(t)

	_, reconciler := tokenwebhook.ServingCertificateReconciler(&data.fakeCertData)()
	secret, err := reconciler(&corev1.Secret{})
	if err != nil {
		t.Fatalf("failed to reconcile serving cert Secret: %v", err)
	}

	if len(secret.Data[resources.ServingCertSecretKey]) == 0 || len(secret.Data[resources.ServingCertKeySecretKey]) == 0 {
		t.Fatal("serving cert secret is missing cert or key")
	}

	certs, err := certutil.ParseCertsPEM(secret.Data[resources.ServingCertSecretKey])
	if err != nil {
		t.Fatalf("failed to parse generated serving cert: %v", err)
	}

	for _, dnsName := range []string{
		"kkp-token-webhook",
		"kkp-token-webhook.cluster-abc123",
		"kkp-token-webhook.cluster-abc123.svc",
		"kkp-token-webhook.cluster-abc123.svc.",
		"kkp-token-webhook.cluster-abc123.svc.cluster.local",
		"kkp-token-webhook.cluster-abc123.svc.cluster.local.",
	} {
		found := false
		for _, name := range certs[0].DNSNames {
			if name == dnsName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("serving cert is missing DNS name %q, has %v", dnsName, certs[0].DNSNames)
		}
	}

	// an unchanged secret must be reused, not regenerated (new key material would
	// fail validation because IsServerCertificateValidForAllOf rejects it)
	again, err := reconciler(secret)
	if err != nil {
		t.Fatalf("failed to re-reconcile serving cert Secret: %v", err)
	}
	if string(again.Data[resources.ServingCertKeySecretKey]) != string(secret.Data[resources.ServingCertKeySecretKey]) {
		t.Error("serving cert was regenerated although the existing one is valid")
	}
}

func TestClientCAReconcilerKeepsExistingCA(t *testing.T) {
	data := newFakeData(t)

	_, reconciler := tokenwebhook.ClientCAReconciler(&data.fakeCertData)()
	secret, err := reconciler(&corev1.Secret{})
	if err != nil {
		t.Fatalf("failed to reconcile client CA Secret: %v", err)
	}

	if len(secret.Data[resources.CACertSecretKey]) == 0 {
		t.Fatal("client CA secret is missing the certificate")
	}

	again, err := reconciler(secret)
	if err != nil {
		t.Fatalf("failed to re-reconcile client CA Secret: %v", err)
	}
	if string(again.Data[resources.CACertSecretKey]) != string(secret.Data[resources.CACertSecretKey]) {
		t.Error("client CA was replaced; an existing CA must never be rotated by the reconciler")
	}
}

func TestKubeconfigReconciler(t *testing.T) {
	data := newFakeData(t)

	_, reconciler := tokenwebhook.KubeconfigReconciler(data)()
	secret, err := reconciler(&corev1.Secret{})
	if err != nil {
		t.Fatalf("failed to reconcile kubeconfig Secret: %v", err)
	}

	config, err := clientcmd.Load(secret.Data[tokenwebhook.KubeconfigSecretKey])
	if err != nil {
		t.Fatalf("failed to load generated kubeconfig: %v", err)
	}

	if len(config.Clusters) != 1 {
		t.Fatalf("clusters = %#v, want exactly one", config.Clusters)
	}
	for _, cluster := range config.Clusters {
		if cluster.Server != "https://kkp-token-webhook.cluster-abc123.svc.cluster.local:443/tokenreview" {
			t.Errorf("server = %q", cluster.Server)
		}
		if len(cluster.CertificateAuthorityData) == 0 {
			t.Error("kubeconfig cluster has no certificate-authority-data")
		}
	}
	for _, authInfo := range config.AuthInfos {
		if len(authInfo.ClientCertificateData) == 0 || len(authInfo.ClientKeyData) == 0 {
			t.Error("kubeconfig auth info has no client certificate")
		}
	}

	// unchanged input must keep the secret stable
	again, err := reconciler(secret)
	if err != nil {
		t.Fatalf("failed to re-reconcile kubeconfig Secret: %v", err)
	}
	if string(again.Data[tokenwebhook.KubeconfigSecretKey]) != string(secret.Data[tokenwebhook.KubeconfigSecretKey]) {
		t.Error("kubeconfig was regenerated although the existing one is valid")
	}
}
