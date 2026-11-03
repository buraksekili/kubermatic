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
	"crypto/x509"
	"fmt"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/resources"
	"k8c.io/kubermatic/v2/pkg/resources/certificates"
	"k8c.io/kubermatic/v2/pkg/resources/certificates/triple"
	"k8c.io/reconciler/pkg/reconciling"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
)

const (
	// KubeconfigSecretKey is the key of the webhook kubeconfig in KubeconfigSecretName.
	KubeconfigSecretKey = "webhook.kubeconfig"

	kubeconfigContextName = "webhook"
)

type certificateData interface {
	Cluster() *kubermaticv1.Cluster
	GetRootCA() (*triple.KeyPair, error)
}

type kubeconfigData interface {
	certificateData
	GetClusterSignerCA(secretName string) (*triple.KeyPair, error)
}

// servingCertAltNames returns every name the webhook Service can be reached under.
func servingCertAltNames(namespace string) certutil.AltNames {
	fqdn := ServiceFQDN(namespace)
	return certutil.AltNames{
		DNSNames: []string{
			Name,
			fmt.Sprintf("%s.%s", Name, namespace),
			fmt.Sprintf("%s.%s.svc", Name, namespace),
			fmt.Sprintf("%s.%s.svc.", Name, namespace),
			fqdn,
			fqdn + ".",
		},
	}
}

// ServingCertificateReconciler returns the reconciler for the webhook serving certificate,
// signed by the cluster root CA.
func ServingCertificateReconciler(data certificateData) reconciling.NamedSecretReconcilerFactory {
	return func() (string, reconciling.SecretReconciler) {
		return ServingCertSecretName, func(se *corev1.Secret) (*corev1.Secret, error) {
			if se.Data == nil {
				se.Data = map[string][]byte{}
			}

			ca, err := data.GetRootCA()
			if err != nil {
				return nil, fmt.Errorf("failed to get root ca: %w", err)
			}

			namespace := data.Cluster().Status.NamespaceName
			commonName := ServiceFQDN(namespace)
			altNames := servingCertAltNames(namespace)

			if b, exists := se.Data[resources.ServingCertSecretKey]; exists {
				certs, err := certutil.ParseCertsPEM(b)
				if err != nil {
					return nil, fmt.Errorf("failed to parse certificate (key=%s) from existing secret: %w", resources.ServingCertSecretKey, err)
				}
				if resources.IsServerCertificateValidForAllOf(certs[0], commonName, altNames, ca.Cert) {
					return se, nil
				}
			}

			keyConfig, err := certificates.CertificateKeyConfig(data.Cluster())
			if err != nil {
				return nil, err
			}

			// NewServerKeyPairWithConfig adds the short Service names and the
			// .svc.cluster.local name; the names with a trailing dot are added here.
			newKP, err := triple.NewServerKeyPairWithConfig(ca,
				commonName,
				Name,
				namespace,
				"cluster.local",
				nil,
				[]string{fmt.Sprintf("%s.%s.svc.", Name, namespace), commonName + "."},
				keyConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to generate serving cert: %w", err)
			}

			keyPEM, err := keyutil.MarshalPrivateKeyToPEM(newKP.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to encode the serving cert key: %w", err)
			}

			se.Data[resources.ServingCertSecretKey] = triple.EncodeCertPEM(newKP.Cert)
			se.Data[resources.ServingCertKeySecretKey] = keyPEM
			se.Data[resources.CACertSecretKey] = triple.EncodeCertPEM(ca.Cert)

			return se, nil
		}
	}
}

// ClientCAReconciler returns the reconciler for the dedicated CA that signs the
// kube-apiserver client certificate. An existing CA is never replaced.
func ClientCAReconciler(data certificateData) reconciling.NamedSecretReconcilerFactory {
	return func() (string, reconciling.SecretReconciler) {
		return ClientCASecretName, func(se *corev1.Secret) (*corev1.Secret, error) {
			keyConfig, err := certificates.CertificateKeyConfig(data.Cluster())
			if err != nil {
				return nil, err
			}

			return certificates.GetCAReconciler("kkp-token-webhook-client-ca", keyConfig)(se)
		}
	}
}

// KubeconfigReconciler returns the reconciler for the kube-apiserver webhook configuration
// file: the webhook URL, the cluster root CA to verify the webhook, and a client
// certificate signed by the dedicated client CA.
func KubeconfigReconciler(data kubeconfigData) reconciling.NamedSecretReconcilerFactory {
	return func() (string, reconciling.SecretReconciler) {
		return KubeconfigSecretName, func(se *corev1.Secret) (*corev1.Secret, error) {
			if se.Data == nil {
				se.Data = map[string][]byte{}
			}

			rootCA, err := data.GetRootCA()
			if err != nil {
				return nil, fmt.Errorf("failed to get root ca: %w", err)
			}

			clientCA, err := data.GetClusterSignerCA(ClientCASecretName)
			if err != nil {
				return nil, fmt.Errorf("failed to get token webhook client ca: %w", err)
			}

			server := URL(data.Cluster().Status.NamespaceName)

			valid, err := isValidKubeconfig(se.Data[KubeconfigSecretKey], rootCA.Cert, clientCA.Cert, server)
			if err == nil && valid {
				return se, nil
			}

			keyConfig, err := certificates.CertificateKeyConfig(data.Cluster())
			if err != nil {
				return nil, err
			}

			kp, err := triple.NewClientKeyPairWithConfig(clientCA, ClientCommonName, nil, keyConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create client certificate: %w", err)
			}

			keyPEM, err := keyutil.MarshalPrivateKeyToPEM(kp.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to encode the client key: %w", err)
			}

			config := baseKubeconfig(rootCA.Cert, server)
			config.AuthInfos = map[string]*clientcmdapi.AuthInfo{
				kubeconfigContextName: {
					ClientCertificateData: triple.EncodeCertPEM(kp.Cert),
					ClientKeyData:         keyPEM,
				},
			}

			se.Data[KubeconfigSecretKey], err = clientcmd.Write(*config)
			if err != nil {
				return nil, fmt.Errorf("failed to encode webhook kubeconfig: %w", err)
			}

			return se, nil
		}
	}
}

// baseKubeconfig is the webhook kubeconfig without credentials. In a webhook
// configuration file, "clusters" is the webhook and "users" is kube-apiserver.
func baseKubeconfig(serverCA *x509.Certificate, server string) *clientcmdapi.Config {
	return &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			kubeconfigContextName: {
				Server:                   server,
				CertificateAuthorityData: triple.EncodeCertPEM(serverCA),
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			kubeconfigContextName: {
				Cluster:  kubeconfigContextName,
				AuthInfo: kubeconfigContextName,
			},
		},
		CurrentContext: kubeconfigContextName,
	}
}

// isValidKubeconfig reports whether the existing kubeconfig points at the right server
// with the right CA and carries a client certificate from the client CA that does not
// expire soon.
func isValidKubeconfig(kubeconfig []byte, serverCA, clientCA *x509.Certificate, server string) (bool, error) {
	if len(kubeconfig) == 0 {
		return false, nil
	}

	existing, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return false, err
	}

	authInfo := existing.AuthInfos[kubeconfigContextName]
	if authInfo == nil {
		return false, nil
	}

	existing.AuthInfos = nil
	if !equality.Semantic.DeepEqual(baseKubeconfig(serverCA, server), existing) {
		return false, nil
	}

	certs, err := certutil.ParseCertsPEM(authInfo.ClientCertificateData)
	if err != nil {
		return false, err
	}

	return resources.IsClientCertificateValidForAllOf(certs[0], ClientCommonName, nil, clientCA), nil
}
