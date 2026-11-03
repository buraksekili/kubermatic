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
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/reconciler/pkg/reconciling"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const roleName = "kubermatic:kkp-token-webhook"

// ServiceAccountReconciler returns the reconciler for the webhook ServiceAccount.
func ServiceAccountReconciler() (string, reconciling.ServiceAccountReconciler) {
	return Name, func(sa *corev1.ServiceAccount) (*corev1.ServiceAccount, error) {
		return sa, nil
	}
}

// RoleReconciler returns the reconciler for the webhook Role in the cluster namespace. The
// webhook reads the token records and the per-user attributes, and writes only the token
// status (lastUsedTime). It gets no access to Secrets or other objects.
func RoleReconciler() (string, reconciling.RoleReconciler) {
	return roleName, func(r *rbacv1.Role) (*rbacv1.Role, error) {
		r.Rules = []rbacv1.PolicyRule{
			{
				APIGroups: []string{kubermaticv1.GroupName},
				Resources: []string{
					kubermaticv1.UserClusterTokenResourceName,
					kubermaticv1.UserClusterAttributeResourceName,
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{kubermaticv1.GroupName},
				Resources: []string{kubermaticv1.UserClusterTokenResourceName + "/status"},
				Verbs:     []string{"patch"},
			},
		}
		return r, nil
	}
}

// RoleBindingReconciler returns the reconciler for the RoleBinding of the webhook
// ServiceAccount in the given namespace.
func RoleBindingReconciler(namespace string) reconciling.NamedRoleBindingReconcilerFactory {
	return func() (string, reconciling.RoleBindingReconciler) {
		return roleName, func(rb *rbacv1.RoleBinding) (*rbacv1.RoleBinding, error) {
			rb.RoleRef = rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     roleName,
			}
			rb.Subjects = []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      Name,
					Namespace: namespace,
				},
			}
			return rb, nil
		}
	}
}
