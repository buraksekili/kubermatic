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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
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

	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue returns a PEM certificate pair for the given CN. The certificate is
// usable for client authentication only, like the kube-apiserver one.
func (ca *testCA) issue(t *testing.T, cn string) (certPEM, keyPEM []byte) {
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

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// issueServing returns a certificate usable as the server certificate on
// 127.0.0.1.
func (ca *testCA) issueServing(t *testing.T, cn string) (certPEM, keyPEM []byte) {
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
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// startTLSServer starts an HTTPS server that requires a client certificate
// signed by ca with the given CN. It returns the server CA pool for clients.
func startTLSServer(t *testing.T, ca *testCA, requireCN string) (url string, serverCAPool *x509.CertPool) {
	t.Helper()

	servingCert, servingKey := ca.issueServing(t, "kkp-token-webhook")
	dir := t.TempDir()
	certFile := filepath.Join(dir, "serving.crt")
	keyFile := filepath.Join(dir, "serving.key")
	caFile := filepath.Join(dir, "ca.crt")
	for path, data := range map[string][]byte{certFile: servingCert, keyFile: servingKey, caFile: ca.certPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	tlsConfig, err := NewTLSConfig(certFile, keyFile, caFile, requireCN)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	return "https://" + listener.Addr().String() + "/healthz", pool
}

func tlsClient(serverCAPool *x509.CertPool, clientCert *tls.Certificate) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    serverCAPool,
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if clientCert == nil {
					return &tls.Certificate{}, nil
				}
				return clientCert, nil
			},
		},
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func loadClientPair(t *testing.T, certPEM, keyPEM []byte) *tls.Certificate {
	t.Helper()

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &pair
}

// Rule 8: the TLS handshake fails without a valid kube-apiserver client
// certificate, with a certificate from another CA, and with the right CA but
// the wrong CN.
func TestClientCertificateRequired(t *testing.T) {
	ca := newTestCA(t)
	url, pool := startTLSServer(t, ca, "kkp-token-webhook-client")
	otherCA := newTestCA(t)

	t.Run("no client certificate", func(t *testing.T) {
		wantHandshakeFailure(t, tlsClient(pool, nil), url)
	})

	t.Run("client certificate from wrong CA", func(t *testing.T) {
		certPEM, keyPEM := otherCA.issue(t, "kkp-token-webhook-client")
		wantHandshakeFailure(t, tlsClient(pool, loadClientPair(t, certPEM, keyPEM)), url)
	})

	t.Run("client certificate with wrong CN", func(t *testing.T) {
		certPEM, keyPEM := ca.issue(t, "someone-else")
		wantHandshakeFailure(t, tlsClient(pool, loadClientPair(t, certPEM, keyPEM)), url)
	})

	t.Run("valid client certificate", func(t *testing.T) {
		certPEM, keyPEM := ca.issue(t, "kkp-token-webhook-client")
		code, _ := doGet(t, tlsClient(pool, loadClientPair(t, certPEM, keyPEM)), url)
		if code != http.StatusOK {
			t.Fatalf("got status %d, want 200", code)
		}
	})
}

func TestNewTLSConfigErrors(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := ca.issue(t, "x")
	certFile := filepath.Join(dir, "c.crt")
	keyFile := filepath.Join(dir, "c.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewTLSConfig(filepath.Join(dir, "missing.crt"), keyFile, caFile, "cn"); err == nil {
		t.Error("missing cert file accepted")
	}
	if _, err := NewTLSConfig(certFile, filepath.Join(dir, "missing.key"), caFile, "cn"); err == nil {
		t.Error("missing key file accepted")
	}
	if _, err := NewTLSConfig(certFile, keyFile, filepath.Join(dir, "missing.crt"), "cn"); err == nil {
		t.Error("missing CA file accepted")
	}
	if _, err := NewTLSConfig(certFile, keyFile, caFile, "cn"); err != nil {
		t.Errorf("valid files rejected: %v", err)
	}
}
