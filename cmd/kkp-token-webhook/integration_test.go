//go:build integration

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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/token-webhook"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const (
	intNamespace  = "cluster-abc123"
	intClusterID  = "abc123"
	intClusterUID = "6f2b4c1e-1111-2222-3333-444455556666"
	intTokenID    = "aaaabbbbccccdddd"
	intSecret     = "integration-secret-1"
	intUserID     = "user-1a2b"
)

func freeAddress(t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// intCA issues the serving and client certificates for the test.
type intCA struct {
	certPEM []byte
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
}

func newIntCA(t *testing.T) *intCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "integration-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &intCA{certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key, cert: cert}
}

func (ca *intCA) issue(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func intToken(now time.Time) *kubermaticv1.UserClusterToken {
	sum := sha256Hex(intSecret)
	return &kubermaticv1.UserClusterToken{
		ObjectMeta: metav1.ObjectMeta{Name: intTokenID, Namespace: intNamespace, Generation: 1},
		Spec: kubermaticv1.UserClusterTokenSpec{
			TokenHash:      sum,
			UserID:         intUserID,
			ClusterID:      intClusterID,
			ClusterUID:     intClusterUID,
			SeedName:       "europe-west",
			IssueTime:      metav1.Time{Time: now.Add(-time.Minute)},
			ExpirationTime: metav1.Time{Time: now.Add(time.Hour)},
		},
		Status: kubermaticv1.UserClusterTokenStatus{
			ObservedGeneration: 1,
			State:              kubermaticv1.UserClusterTokenActive,
		},
	}
}

func intAttribute() *kubermaticv1.UserClusterAttribute {
	return &kubermaticv1.UserClusterAttribute{
		ObjectMeta: metav1.ObjectMeta{Name: intUserID, Namespace: intNamespace, Generation: 1},
		Spec:       kubermaticv1.UserClusterAttributeSpec{UserID: intUserID},
		Status: kubermaticv1.UserClusterAttributeStatus{
			ObservedGeneration: 1,
			State:              kubermaticv1.UserClusterTokenActive,
			Username:           "alice@example.com",
			Groups:             []string{"team-payments"},
		},
	}
}

// TestWebhookEndToEnd runs the full main wiring (informer store, prober, TLS
// server, health server) against a real API server and drives it exactly like
// kube-apiserver would.
// seedFixtures creates the cluster namespace, one Active token and its
// Active attribute, the way WP4 would leave them.
func seedFixtures(t *testing.T, ctx context.Context, client ctrlruntimeclient.Client) {
	t.Helper()

	if err := client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: intNamespace}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := client.Create(ctx, intToken(now)); err != nil {
		t.Fatal(err)
	}
	if err := client.Create(ctx, intAttribute()); err != nil {
		t.Fatal(err)
	}
	// the CRDs have a status subresource, so the status is written separately,
	// on a freshly read object like a controller would
	token := &kubermaticv1.UserClusterToken{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: intNamespace, Name: intTokenID}, token); err != nil {
		t.Fatal(err)
	}
	token.Status = intToken(now).Status
	if err := client.Status().Update(ctx, token); err != nil {
		t.Fatal(err)
	}
	attribute := &kubermaticv1.UserClusterAttribute{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: intNamespace, Name: intUserID}, attribute); err != nil {
		t.Fatal(err)
	}
	attribute.Status = intAttribute().Status
	if err := client.Status().Update(ctx, attribute); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookEndToEnd(t *testing.T) {
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../pkg/crd/k8c.io"},
		ErrorIfCRDPathMissing: true,
	}
	restConfig, err := env.Start()
	if err != nil {
		t.Fatalf("starting envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	scheme := runtime.NewScheme()
	if err := kubermaticv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client, err := ctrlruntimeclient.New(restConfig, ctrlruntimeclient.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	seedFixtures(t, ctx, client)

	// certificates on disk, like the Secret mounts in the Deployment
	ca := newIntCA(t)
	dir := t.TempDir()
	serving := ca.issue(t, "kkp-token-webhook", true)
	if err := tlsCertToFile(filepath.Join(dir, "serving.crt"), filepath.Join(dir, "serving.key"), serving); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// kubeconfig for the webhook process wiring
	kubeconfigFile := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfigFile, env.KubeConfig, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := options{
		clusterID:        intClusterID,
		clusterUID:       intClusterUID,
		namespace:        intNamespace,
		listenAddress:    freeAddress(t),
		healthAddress:    freeAddress(t),
		tlsCertFile:      filepath.Join(dir, "serving.crt"),
		tlsKeyFile:       filepath.Join(dir, "serving.key"),
		clientCAFile:     filepath.Join(dir, "ca.crt"),
		clientCommonName: "kkp-token-webhook-client",
		groupPrefix:      "oidc:",
		clockSkew:        30 * time.Second,
		maxStaleness:     30 * time.Second, // short, so the prober interval is short too
		idleTimeout:      24 * time.Hour,
		lastUsedInterval: 5 * time.Minute,
		kubeconfig:       kubeconfigFile,
	}

	runDone := make(chan error, 1)
	go func() { runDone <- run(ctx, opts, zap.NewNop().Sugar()) }()

	reviewURL := "https://" + opts.listenAddress + tokenwebhook.TokenReviewPath
	healthURL := "http://" + opts.healthAddress
	postReview := newReviewPoster(t, ctx, ca, reviewURL)
	// readiness follows the informer sync and the first probe
	waitFor(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL+"/readyz", nil)
		if err != nil {
			return false
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}, "webhook becoming ready")

	// 1. a valid token authenticates the user
	status, review := postReview(fmt.Sprintf("kkp_%s_%s:%s", intClusterID, intTokenID, intSecret))
	if status != http.StatusOK || !review.Status.Authenticated {
		t.Fatalf("got status %d, review %+v", status, review.Status)
	}
	if review.Status.User.Username != "alice@example.com" {
		t.Errorf("username: got %q", review.Status.User.Username)
	}
	if len(review.Status.User.Groups) != 2 || review.Status.User.Groups[0] != "oidc:team-payments" {
		t.Errorf("groups: got %v", review.Status.User.Groups)
	}

	// 2. the lastUsedTime write lands on the token
	waitFor(t, func() bool {
		token := &kubermaticv1.UserClusterToken{}
		if err := client.Get(ctx, types.NamespacedName{Namespace: intNamespace, Name: intTokenID}, token); err != nil {
			return false
		}
		return token.Status.LastUsedTime != nil
	}, "lastUsedTime being written")

	// 3. a wrong secret is refused, not errored
	status, review = postReview("kkp_" + intClusterID + "_" + intTokenID + ":wrong")
	if status != http.StatusOK || review.Status.Authenticated {
		t.Fatalf("wrong secret: got status %d, review %+v", status, review.Status)
	}

	// 4. a token of another cluster never reaches the store
	status, review = postReview("kkp_othercl_" + intTokenID + ":" + intSecret)
	if status != http.StatusOK || review.Status.Authenticated {
		t.Fatalf("other cluster: got status %d, review %+v", status, review.Status)
	}

	// 5. disabling the token flips the answer once the watch delivers it
	token := &kubermaticv1.UserClusterToken{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: intNamespace, Name: intTokenID}, token); err != nil {
		t.Fatal(err)
	}
	token.Status.State = kubermaticv1.UserClusterTokenDisabled
	token.Status.Reason = kubermaticv1.UserClusterTokenExpired
	if err := client.Status().Update(ctx, token); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool {
		status, review = postReview(fmt.Sprintf("kkp_%s_%s:%s", intClusterID, intTokenID, intSecret))
		return status == http.StatusOK && !review.Status.Authenticated && review.Status.Error != ""
	}, "disabled token being rejected")

	cancel()
	if err := <-runDone; err != nil {
		t.Errorf("run returned an error: %v", err)
	}
}

// newReviewPoster returns a function posting TokenReviews exactly like
// kube-apiserver: mTLS with the expected client certificate.
func newReviewPoster(t *testing.T, ctx context.Context, ca *intCA, reviewURL string) func(string) (int, authenticationv1.TokenReview) {
	t.Helper()

	serverPool := x509.NewCertPool()
	serverPool.AddCert(ca.cert)
	clientCert := ca.issue(t, "kkp-token-webhook-client", false)
	apiserverClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    serverPool,
				MinVersion: tls.VersionTLS12,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &clientCert, nil
				},
			},
		},
	}

	return func(token string) (int, authenticationv1.TokenReview) {
		body := fmt.Sprintf(`{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":%q}}`, token)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, reviewURL, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := apiserverClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		payload, _ := io.ReadAll(resp.Body)

		review := authenticationv1.TokenReview{}
		if err := json.Unmarshal(payload, &review); err != nil {
			t.Fatalf("response is not a TokenReview: %v (%s)", err, payload)
		}
		return resp.StatusCode, review
	}
}

func tlsCertToFile(certPath, keyPath string, pair tls.Certificate) error {
	certOut := []byte{}
	for _, c := range pair.Certificate {
		certOut = append(certOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(pair.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certOut, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyOut, 0o600)
}

func waitFor(t *testing.T, condition func() bool, what string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
