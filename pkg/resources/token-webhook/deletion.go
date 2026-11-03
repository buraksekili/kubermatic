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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ResourcesForDeletion returns every object of the token webhook, so that turning the
// UserClusterTokenWebhook feature gate off removes them again (the kube-apiserver flags
// and volume revert with the next apiserver Deployment reconcile).
func ResourcesForDeletion(namespace string) []ctrlruntimeclient.Object {
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: namespace}
	}

	return []ctrlruntimeclient.Object{
		&appsv1.Deployment{ObjectMeta: meta(Name)},
		&corev1.Service{ObjectMeta: meta(Name)},
		&corev1.ServiceAccount{ObjectMeta: meta(Name)},
		&policyv1.PodDisruptionBudget{ObjectMeta: meta(Name)},
		&rbacv1.Role{ObjectMeta: meta(roleName)},
		&rbacv1.RoleBinding{ObjectMeta: meta(roleName)},
		&corev1.Secret{ObjectMeta: meta(ServingCertSecretName)},
		&corev1.Secret{ObjectMeta: meta(ClientCASecretName)},
		&corev1.Secret{ObjectMeta: meta(KubeconfigSecretName)},
		&networkingv1.NetworkPolicy{ObjectMeta: meta(NetworkPolicyIngress)},
		&networkingv1.NetworkPolicy{ObjectMeta: meta(NetworkPolicyEgress)},
		&networkingv1.NetworkPolicy{ObjectMeta: meta(NetworkPolicyAPIServerAllow)},
	}
}
