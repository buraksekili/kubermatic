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
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/sdk/v2/semver"
	"k8c.io/kubermatic/v2/pkg/resources"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	apiserverinstall "k8s.io/apiserver/pkg/apis/apiserver/install"
	apiservervalidation "k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

type fakeAuthConfigData struct {
	cluster            *kubermaticv1.Cluster
	issuerURL          string
	clientID           string
	oidcAuthEnabled    bool
	authYAML           string
	tokenWebhookEnable bool
}

func (f *fakeAuthConfigData) Cluster() *kubermaticv1.Cluster             { return f.cluster }
func (f *fakeAuthConfigData) OIDCIssuerURL() string                      { return f.issuerURL }
func (f *fakeAuthConfigData) OIDCIssuerClientID() string                 { return f.clientID }
func (f *fakeAuthConfigData) IsAuthenticationConfigurationEnabled() bool { return f.oidcAuthEnabled }
func (f *fakeAuthConfigData) AuthenticationConfigurationYAML() []byte    { return []byte(f.authYAML) }
func (f *fakeAuthConfigData) UserClusterTokenWebhookEnabled() bool       { return f.tokenWebhookEnable }

func TestAuthenticationConfigurationReconciler(t *testing.T) {
	tests := []struct {
		name               string
		data               *fakeAuthConfigData
		caBundle           string
		existingSecret     *corev1.Secret
		expectName         string
		expectError        string
		expectYAMLContains []string
		expectDataRaw      string
		expectYAMLEmpty    bool
	}{
		{
			name: "custom secret exists with correct key",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					AuthenticationConfiguration: &kubermaticv1.AuthenticationConfiguration{
						SecretName: "my-auth-config",
						SecretKey:  "config.yaml",
					},
				}},
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.Time{Time: time.Now()}},
				Data:       map[string][]byte{"config.yaml": []byte("test")},
			},
			expectName: "my-auth-config",
		},
		{
			name: "custom secret does not exist should fail",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
					AuthenticationConfiguration: &kubermaticv1.AuthenticationConfiguration{
						SecretName: "missing-secret",
						SecretKey:  "config.yaml",
					},
				}},
			},
			existingSecret: &corev1.Secret{},
			expectName:     "missing-secret",
			expectError:    "non-existing secret",
		},
		{
			name: "custom secret missing required key should fail",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
					AuthenticationConfiguration: &kubermaticv1.AuthenticationConfiguration{
						SecretName: "my-auth-config",
						SecretKey:  "config.yaml",
					},
				}},
			},
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.Time{Time: time.Now()}},
				Data:       map[string][]byte{"wrong-key": []byte("test")},
			},
			expectName:  "my-auth-config",
			expectError: "does not specify the required key",
		},
		{
			name: "OIDC from cluster spec on k8s 1.34+",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
					OIDC: kubermaticv1.OIDCSettings{
						IssuerURL:      "https://issuer.example.com",
						ClientID:       "my-client",
						UsernameClaim:  "email",
						UsernamePrefix: "oidc:",
						GroupsClaim:    "groups",
						GroupsPrefix:   "oidc:",
					},
				}},
			},
			caBundle:   "ca-data",
			expectName: resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLContains: []string{
				"kind: AuthenticationConfiguration",
				"apiVersion: apiserver.config.k8s.io/v1",
				"url: https://issuer.example.com",
				"audiences:\n    - my-client",
				"certificateAuthority: ca-data",
			},
		},
		{
			name: "OIDC from cluster spec on k8s <1.34",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.33.10"),
					OIDC: kubermaticv1.OIDCSettings{
						IssuerURL:      "https://issuer.example.com",
						ClientID:       "my-client",
						UsernameClaim:  "email",
						UsernamePrefix: "oidc:",
						GroupsClaim:    "groups",
						GroupsPrefix:   "oidc:",
					},
				}},
			},
			caBundle:   "ca-data",
			expectName: resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLContains: []string{
				"kind: AuthenticationConfiguration",
				"apiVersion: apiserver.config.k8s.io/v1beta1",
				"url: https://issuer.example.com",
				"audiences:\n    - my-client",
				"certificateAuthority: ca-data",
			},
		},
		{
			name: "OIDC from cluster spec with required claims",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
					OIDC: kubermaticv1.OIDCSettings{
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "my-client",
						RequiredClaim: "aud=my-aud,sub=my-sub",
					},
				}},
			},
			expectName: resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLContains: []string{
				"claim: aud",
				"requiredValue: my-aud",
				"claim: sub",
				"requiredValue: my-sub",
			},
		},
		{
			name: "OIDC from cluster spec with malformed required claim",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
					OIDC: kubermaticv1.OIDCSettings{
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "my-client",
						RequiredClaim: "malformed",
					},
				}},
			},
			expectName:  resources.ApiserverAuthenticationConfigurationSecretName,
			expectError: "malformed",
		},
		{
			name: "seed authentication configuration YAML passthrough",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
				}},
				authYAML: "kind: AuthenticationConfiguration\napiVersion: apiserver.config.k8s.io/v1\njwt: []\n",
			},
			expectName:    resources.ApiserverAuthenticationConfigurationSecretName,
			expectDataRaw: "kind: AuthenticationConfiguration\napiVersion: apiserver.config.k8s.io/v1\njwt: []\n",
		},
		{
			name: "enable OIDC authentication from seed based on KubernetesOIDCAuthentication feature flag",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
				}},
				issuerURL:       "https://seed-issuer.example.com",
				clientID:        "seed-client",
				oidcAuthEnabled: true,
			},
			caBundle:   "seed-ca",
			expectName: resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLContains: []string{
				"kind: AuthenticationConfiguration",
				"apiVersion: apiserver.config.k8s.io/v1",
				"url: https://seed-issuer.example.com",
				"audiences:\n    - seed-client",
				"certificateAuthority: seed-ca",
				"claim: email",
				"claim: groups",
				"prefix: 'oidc:'",
			},
		},
		{
			name: "no OIDC configured produces empty JWT list",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
				}},
			},
			expectName: resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLContains: []string{
				"kind: AuthenticationConfiguration",
				"apiVersion: apiserver.config.k8s.io/v1",
				"jwt: []",
			},
		},
		{
			name: "token webhook gate on without annotation renders the default issuer entry",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
					Version: *semver.NewSemverOrDie("1.34.0"),
				}},
				issuerURL:          "https://dex.example.com/dex",
				clientID:           "kubermaticIssuer",
				oidcAuthEnabled:    true,
				tokenWebhookEnable: true,
			},
			expectName: resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLContains: []string{
				"url: https://dex.example.com/dex",
				"audiences:\n    - kubermaticIssuer",
			},
		},
		{
			name: "token webhook gate on with annotation omits the default issuer entry",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{TokenWebhookOnlyAnnotation: "true"},
					},
					Spec: kubermaticv1.ClusterSpec{
						Version: *semver.NewSemverOrDie("1.34.0"),
					},
				},
				issuerURL:          "https://dex.example.com/dex",
				clientID:           "kubermaticIssuer",
				oidcAuthEnabled:    true,
				tokenWebhookEnable: true,
			},
			expectName:      resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLEmpty: true,
		},
		{
			name: "token webhook gate on with annotation omits the spec.oidc entry",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{TokenWebhookOnlyAnnotation: "true"},
					},
					Spec: kubermaticv1.ClusterSpec{
						Version: *semver.NewSemverOrDie("1.34.0"),
						OIDC: kubermaticv1.OIDCSettings{
							IssuerURL: "https://issuer.example.com",
							ClientID:  "my-client",
						},
					},
				},
				tokenWebhookEnable: true,
			},
			expectName:      resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLEmpty: true,
		},
		{
			name: "token webhook gate off with annotation changes nothing",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{TokenWebhookOnlyAnnotation: "true"},
					},
					Spec: kubermaticv1.ClusterSpec{
						Version: *semver.NewSemverOrDie("1.34.0"),
					},
				},
				issuerURL:       "https://dex.example.com/dex",
				clientID:        "kubermaticIssuer",
				oidcAuthEnabled: true,
			},
			expectName: resources.ApiserverAuthenticationConfigurationSecretName,
			expectYAMLContains: []string{
				"url: https://dex.example.com/dex",
				"audiences:\n    - kubermaticIssuer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := AuthenticationConfigurationReconciler(tt.data, tt.caBundle)
			name, reconciler := factory()
			require.Equal(t, tt.expectName, name)

			existing := tt.existingSecret
			if existing == nil {
				existing = &corev1.Secret{}
			}

			secret, err := reconciler(existing)
			if tt.expectError != "" {
				require.ErrorContains(t, err, tt.expectError)
				return
			} else {
				require.NoError(t, err)
			}

			if tt.expectDataRaw != "" {
				got := string(secret.Data[resources.AuthenticationConfigurationKey])
				require.Equal(t, tt.expectDataRaw, got, "AuthenticationConfiguration YAML")
			}

			yamlData := string(secret.Data[resources.AuthenticationConfigurationKey])
			if tt.expectYAMLEmpty {
				require.Contains(t, yamlData, "jwt: []\n", "token-webhook-only must render an empty JWT list")
				require.NotContains(t, yamlData, "audiences", "no JWT authenticator may remain")
				require.NotContains(t, yamlData, "url:", "no JWT authenticator may remain")
			}
			for _, s := range tt.expectYAMLContains {
				require.Contains(t, yamlData, s+"\n", "AuthenticationConfigurationYAML should contain")
			}
		})
	}
}

var updateAuthConfigFixtures = flag.Bool("update-authconfig-fixtures", false, "rewrite the AuthenticationConfiguration fixtures in testdata/")

// TestAuthenticationConfigurationFixtures compares the full rendered
// AuthenticationConfiguration of the entries KKP generates itself with fixtures.
func TestAuthenticationConfigurationFixtures(t *testing.T) {
	specOIDC := kubermaticv1.OIDCSettings{
		IssuerURL:     "https://issuer.example.com",
		ClientID:      "my-client",
		UsernameClaim: "sub",
		GroupsClaim:   "groups",
		RequiredClaim: "hd=example.com",
	}

	tests := []struct {
		name    string
		fixture string
		data    *fakeAuthConfigData
	}{
		{
			name:    "default entry, Kubernetes 1.34",
			fixture: "authconfig-default-1.34.0.yaml",
			data: &fakeAuthConfigData{
				cluster:         &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{Version: *semver.NewSemverOrDie("1.34.0")}},
				issuerURL:       "https://dex.example.com/dex",
				clientID:        "kubermaticIssuer",
				oidcAuthEnabled: true,
			},
		},
		{
			name:    "default entry, Kubernetes 1.33",
			fixture: "authconfig-default-1.33.10.yaml",
			data: &fakeAuthConfigData{
				cluster:         &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{Version: *semver.NewSemverOrDie("1.33.10")}},
				issuerURL:       "https://dex.example.com/dex",
				clientID:        "kubermaticIssuer",
				oidcAuthEnabled: true,
			},
		},
		{
			name:    "spec.oidc entry with empty prefixes, Kubernetes 1.34",
			fixture: "authconfig-spec-oidc-1.34.0.yaml",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{Version: *semver.NewSemverOrDie("1.34.0"), OIDC: specOIDC}},
			},
		},
		{
			name:    "spec.oidc entry with empty prefixes, Kubernetes 1.33",
			fixture: "authconfig-spec-oidc-1.33.10.yaml",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{Version: *semver.NewSemverOrDie("1.33.10"), OIDC: specOIDC}},
			},
		},
		{
			name:    "token webhook only, empty JWT list, Kubernetes 1.34",
			fixture: "authconfig-tokenwebhook-only-1.34.0.yaml",
			data: &fakeAuthConfigData{
				cluster: &kubermaticv1.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{TokenWebhookOnlyAnnotation: "true"},
					},
					Spec: kubermaticv1.ClusterSpec{Version: *semver.NewSemverOrDie("1.34.0")},
				},
				issuerURL:          "https://dex.example.com/dex",
				clientID:           "kubermaticIssuer",
				oidcAuthEnabled:    true,
				tokenWebhookEnable: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// empty CA: kube-apiserver validation below rejects anything but a real PEM
			_, reconciler := AuthenticationConfigurationReconciler(tt.data, "")()
			secret, err := reconciler(&corev1.Secret{})
			require.NoError(t, err)

			got := secret.Data[resources.AuthenticationConfigurationKey]
			fixture := filepath.Join("testdata", tt.fixture)

			if *updateAuthConfigFixtures {
				require.NoError(t, os.WriteFile(fixture, got, 0o644))
			}

			expected, err := os.ReadFile(fixture)
			require.NoError(t, err)
			require.Equal(t, string(expected), string(got))

			requireValidForKubeAPIServer(t, got)
		})
	}
}

// TestTokenWebhookOnlyAnnotationIsReversible proves the migration switch is
// level-triggered: setting the annotation empties the JWT list and removing it
// brings the KKP-generated entry back on the next reconcile of the same Secret.
func TestTokenWebhookOnlyAnnotationIsReversible(t *testing.T) {
	cluster := &kubermaticv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{TokenWebhookOnlyAnnotation: "true"},
		},
		Spec: kubermaticv1.ClusterSpec{
			Version: *semver.NewSemverOrDie("1.34.0"),
		},
	}
	data := &fakeAuthConfigData{
		cluster:            cluster,
		issuerURL:          "https://dex.example.com/dex",
		clientID:           "kubermaticIssuer",
		oidcAuthEnabled:    true,
		tokenWebhookEnable: true,
	}

	secret := &corev1.Secret{}
	_, reconciler := AuthenticationConfigurationReconciler(data, "")()
	result, err := reconciler(secret)
	require.NoError(t, err)
	require.Contains(t, string(result.Data[resources.AuthenticationConfigurationKey]), "jwt: []")

	delete(cluster.Annotations, TokenWebhookOnlyAnnotation)
	_, reconciler = AuthenticationConfigurationReconciler(data, "")()
	result, err = reconciler(secret)
	require.NoError(t, err)
	require.Contains(t, string(result.Data[resources.AuthenticationConfigurationKey]), "audiences:\n    - kubermaticIssuer")
}

// TestAuthenticationConfigurationCustomerSourcesUnchanged makes sure the reserved name
// rules and the token-webhook-only switch never modify an AuthenticationConfiguration
// the customer supplies.
func TestAuthenticationConfigurationCustomerSourcesUnchanged(t *testing.T) {
	customerYAML := "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\njwt:\n- issuer:\n    url: https://idp.example.com\n    audiences: [customer]\n  claimMappings:\n    username:\n      claim: sub\n      prefix: \"\"\n"

	tokenWebhookOptIn := func() *kubermaticv1.Cluster {
		return &kubermaticv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{TokenWebhookOnlyAnnotation: "true"},
			},
			Spec: kubermaticv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.34.0"),
				AuthenticationConfiguration: &kubermaticv1.AuthenticationConfiguration{
					SecretName: "customer-auth",
					SecretKey:  "config.yaml",
				},
			},
		}
	}

	t.Run("cluster Secret", func(t *testing.T) {
		data := &fakeAuthConfigData{
			cluster: &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{
				Version: *semver.NewSemverOrDie("1.34.0"),
				AuthenticationConfiguration: &kubermaticv1.AuthenticationConfiguration{
					SecretName: "customer-auth",
					SecretKey:  "config.yaml",
				},
			}},
			// would produce the default entry if the customer Secret were ignored
			issuerURL:       "https://dex.example.com/dex",
			clientID:        "kubermaticIssuer",
			oidcAuthEnabled: true,
		}

		existing := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "customer-auth",
				CreationTimestamp: metav1.Time{Time: time.Now()},
				Labels:            map[string]string{"owner": "customer"},
			},
			Data: map[string][]byte{"config.yaml": []byte(customerYAML)},
		}
		original := existing.DeepCopy()

		_, reconciler := AuthenticationConfigurationReconciler(data, "ca-data")()
		secret, err := reconciler(existing)
		require.NoError(t, err)
		require.Equal(t, original, secret)
	})

	t.Run("cluster Secret with token-webhook-only annotation", func(t *testing.T) {
		data := &fakeAuthConfigData{
			cluster:            tokenWebhookOptIn(),
			issuerURL:          "https://dex.example.com/dex",
			clientID:           "kubermaticIssuer",
			oidcAuthEnabled:    true,
			tokenWebhookEnable: true,
		}

		existing := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "customer-auth",
				CreationTimestamp: metav1.Time{Time: time.Now()},
				Labels:            map[string]string{"owner": "customer"},
			},
			Data: map[string][]byte{"config.yaml": []byte(customerYAML)},
		}
		original := existing.DeepCopy()

		_, reconciler := AuthenticationConfigurationReconciler(data, "ca-data")()
		secret, err := reconciler(existing)
		require.NoError(t, err)
		require.Equal(t, original, secret)
	})

	t.Run("datacenter or seed YAML", func(t *testing.T) {
		data := &fakeAuthConfigData{
			cluster:         &kubermaticv1.Cluster{Spec: kubermaticv1.ClusterSpec{Version: *semver.NewSemverOrDie("1.34.0")}},
			issuerURL:       "https://dex.example.com/dex",
			clientID:        "kubermaticIssuer",
			oidcAuthEnabled: true,
			authYAML:        customerYAML,
		}

		_, reconciler := AuthenticationConfigurationReconciler(data, "ca-data")()
		secret, err := reconciler(&corev1.Secret{})
		require.NoError(t, err)
		require.Equal(t, customerYAML, string(secret.Data[resources.AuthenticationConfigurationKey]))
	})

	t.Run("datacenter or seed YAML with token-webhook-only annotation", func(t *testing.T) {
		data := &fakeAuthConfigData{
			cluster: &kubermaticv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{TokenWebhookOnlyAnnotation: "true"},
				},
				Spec: kubermaticv1.ClusterSpec{Version: *semver.NewSemverOrDie("1.34.0")},
			},
			issuerURL:          "https://dex.example.com/dex",
			clientID:           "kubermaticIssuer",
			oidcAuthEnabled:    true,
			authYAML:           customerYAML,
			tokenWebhookEnable: true,
		}

		_, reconciler := AuthenticationConfigurationReconciler(data, "ca-data")()
		secret, err := reconciler(&corev1.Secret{})
		require.NoError(t, err)
		require.Equal(t, customerYAML, string(secret.Data[resources.AuthenticationConfigurationKey]))
	})
}

// requireValidForKubeAPIServer runs kube-apiserver's own validation, which also
// compiles the CEL expressions, so a broken rule fails here and not at apiserver start.
func requireValidForKubeAPIServer(t *testing.T, data []byte) {
	t.Helper()

	scheme := runtime.NewScheme()
	apiserverinstall.Install(scheme)

	obj, _, err := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder().Decode(data, nil, nil)
	require.NoError(t, err)

	cfg, ok := obj.(*apiserverapi.AuthenticationConfiguration)
	require.True(t, ok, "decoded %T, want internal AuthenticationConfiguration", obj)

	errs := apiservervalidation.ValidateAuthenticationConfiguration(authenticationcel.NewDefaultCompiler(), cfg, nil)
	require.Empty(t, errs.ToAggregate())
}
