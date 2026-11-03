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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// NewTLSConfig builds the serving TLS configuration: the serving certificate
// from certFile/keyFile, and a client certificate signed by clientCAFile and
// carrying clientCommonName as its CN is required for the handshake to
// succeed. kube-apiserver is the only intended holder of such a certificate.
func NewTLSConfig(certFile, keyFile, clientCAFile, clientCommonName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading serving certificate: %w", err)
	}

	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("loading client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client CA file contains no certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
		// the CN check runs after the standard verification and rejects a
		// certificate from the right CA for another purpose
		VerifyPeerCertificate: VerifyClientCommonName(clientCommonName),
	}, nil
}

// VerifyClientCommonName returns a VerifyPeerCertificate callback that
// accepts only leaf certificates with the given CN.
func VerifyClientCommonName(commonName string) func([][]byte, [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
			return errors.New("no verified client certificate")
		}
		if cn := verifiedChains[0][0].Subject.CommonName; cn != commonName {
			return fmt.Errorf("client certificate CN %q is not %q", cn, commonName)
		}
		return nil
	}
}
