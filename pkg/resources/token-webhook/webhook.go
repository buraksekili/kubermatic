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

// Package tokenwebhook renders the per-cluster kkp-token-webhook: the Deployment and
// everything around it on the seed, and the kube-apiserver side of the webhook token
// authentication. All of it is only used when the UserClusterTokenWebhook feature gate
// is enabled.
package tokenwebhook

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/defaulting"

	corev1 "k8s.io/api/core/v1"
)

const (
	// Name is used for the Deployment, Service, ServiceAccount and the app label.
	Name = "kkp-token-webhook"

	// ImageRepository is the webhook image. It is versioned separately from KKP so that
	// a webhook release does not restart kube-apiserver and a KKP release does not
	// restart the webhook.
	ImageRepository = "quay.io/kubermatic/kkp-token-webhook"
	// ImageTag is the webhook image version. Placeholder until the image is published.
	ImageTag = "v0.1.0"

	// ServingCertSecretName holds the webhook serving certificate, signed by the cluster root CA.
	ServingCertSecretName = "kkp-token-webhook-serving-cert"
	// ClientCASecretName holds the CA that signs the kube-apiserver client certificate.
	// It is a dedicated CA, so a certificate signed by the cluster root CA (for example
	// through the CSR API of the user cluster) is not accepted by the webhook.
	ClientCASecretName = "kkp-token-webhook-client-ca"
	// KubeconfigSecretName holds the webhook configuration file for kube-apiserver.
	KubeconfigSecretName = "kkp-token-webhook-kubeconfig"

	// ClientCommonName is the CN of the kube-apiserver client certificate.
	ClientCommonName = "kkp-token-webhook-client"

	// ServicePort is the Service port kube-apiserver connects to.
	ServicePort = 443
	// ListenPort is the HTTPS TokenReview port of the webhook container.
	ListenPort = 8443
	// HealthPort serves /healthz, /readyz and /metrics over plain HTTP.
	HealthPort = 8080
	// TokenReviewPath is the HTTP path kube-apiserver posts TokenReviews to.
	TokenReviewPath = "/tokenreview"

	// MaxStaleness is how old the webhook's informer may get before it answers 503.
	MaxStaleness = 120 * time.Second
	// LastUsedUpdateInterval throttles the status.lastUsedTime writes per token.
	LastUsedUpdateInterval = 5 * time.Minute

	// NetworkPolicyIngress limits who can reach the webhook.
	NetworkPolicyIngress = "kkp-token-webhook-ingress"
	// NetworkPolicyEgress limits where the webhook can connect to.
	NetworkPolicyEgress = "kkp-token-webhook-egress"
	// NetworkPolicyAPIServerAllow lets kube-apiserver reach the webhook when the
	// apiserver egress policies are enabled for the cluster.
	NetworkPolicyAPIServerAllow = "kkp-token-webhook-allow"

	// apiserverKubeconfigDir is where the webhook kubeconfig is mounted in kube-apiserver.
	apiserverKubeconfigDir = "/etc/kubernetes/kkp-token-webhook"
)

// Image returns the full webhook image reference before registry rewriting.
func Image() string {
	return ImageRepository + ":" + ImageTag
}

// ServiceFQDN is the DNS name kube-apiserver uses to reach the webhook. It has no
// trailing dot, so that the same name in NO_PROXY matches it.
func ServiceFQDN(namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", Name, namespace)
}

// URL is the TokenReview endpoint written into the kube-apiserver webhook kubeconfig.
func URL(namespace string) string {
	return fmt.Sprintf("https://%s%s", net.JoinHostPort(ServiceFQDN(namespace), strconv.Itoa(ServicePort)), TokenReviewPath)
}

// Settings are the values from the KubermaticConfiguration that the webhook and
// kube-apiserver need.
type Settings struct {
	// CacheTTL is the kube-apiserver --authentication-token-webhook-cache-ttl.
	CacheTTL time.Duration
	// IdleTimeout is passed to the webhook.
	IdleTimeout time.Duration
}

// SettingsFrom returns the token webhook settings from the KubermaticConfiguration. The
// zero value of a Duration falls back to the defaulting constants, so a configuration
// that reached this code without defaults applied still renders usable values.
func SettingsFrom(config *kubermaticv1.KubermaticConfiguration) Settings {
	settings := Settings{
		CacheTTL:    defaulting.DefaultUserClusterTokenWebhookCacheTTL,
		IdleTimeout: defaulting.DefaultUserClusterTokenIdleTimeout,
	}

	if config != nil {
		if d := config.Spec.UserClusterTokens.WebhookCacheTTL.Duration; d > 0 {
			settings.CacheTTL = d
		}
		if d := config.Spec.UserClusterTokens.IdleTimeout.Duration; d > 0 {
			settings.IdleTimeout = d
		}
	}

	return settings
}

// APIServerConfigFilePath is where kube-apiserver finds the webhook configuration file.
func APIServerConfigFilePath() string {
	return filepath.Join(apiserverKubeconfigDir, KubeconfigSecretKey)
}

// APIServerFlags returns the kube-apiserver flags that enable the webhook token
// authentication against this webhook.
func APIServerFlags(config *kubermaticv1.KubermaticConfiguration) []string {
	settings := SettingsFrom(config)

	return []string{
		"--authentication-token-webhook-config-file", APIServerConfigFilePath(),
		"--authentication-token-webhook-version", "v1",
		"--authentication-token-webhook-cache-ttl", settings.CacheTTL.String(),
	}
}

// APIServerVolume is the kube-apiserver volume with the webhook configuration file. It is
// mounted into the kube-apiserver container only, so no sidecar can read the client
// certificate.
func APIServerVolume() corev1.Volume {
	return corev1.Volume{
		Name: KubeconfigSecretName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: KubeconfigSecretName,
			},
		},
	}
}

// APIServerVolumeMount is the matching mount for APIServerVolume.
func APIServerVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      KubeconfigSecretName,
		MountPath: apiserverKubeconfigDir,
		ReadOnly:  true,
	}
}

// NoProxyEntries are the hostnames that must never be sent through a seed HTTP proxy:
// the webhook Service FQDN, as kube-apiserver calls it with the TokenReview request.
func NoProxyEntries(namespace string) []string {
	return []string{ServiceFQDN(namespace)}
}
