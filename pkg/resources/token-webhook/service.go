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
	"k8c.io/kubermatic/v2/pkg/kubernetes"
	"k8c.io/kubermatic/v2/pkg/resources"
	"k8c.io/reconciler/pkg/reconciling"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// ServiceReconciler returns the reconciler for the webhook Service.
func ServiceReconciler() reconciling.NamedServiceReconcilerFactory {
	return func() (string, reconciling.ServiceReconciler) {
		return Name, func(se *corev1.Service) (*corev1.Service, error) {
			kubernetes.EnsureLabels(se, resources.BaseAppLabels(Name, nil))

			se.Spec.Type = corev1.ServiceTypeClusterIP
			se.Spec.Selector = resources.BaseAppLabels(Name, nil)
			se.Spec.Ports = []corev1.ServicePort{
				{
					Name:       "https",
					Port:       ServicePort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(ListenPort),
				},
			}

			return se, nil
		}
	}
}

// PodDisruptionBudgetReconciler returns the reconciler for the webhook PodDisruptionBudget.
func PodDisruptionBudgetReconciler() reconciling.NamedPodDisruptionBudgetReconcilerFactory {
	return func() (string, reconciling.PodDisruptionBudgetReconciler) {
		return Name, func(pdb *policyv1.PodDisruptionBudget) (*policyv1.PodDisruptionBudget, error) {
			minAvailable := intstr.FromInt32(1)
			pdb.Spec = policyv1.PodDisruptionBudgetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: resources.BaseAppLabels(Name, nil),
				},
				MinAvailable: &minAvailable,
				// a crash-looping replica must not block node drains
				UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
			}

			return pdb, nil
		}
	}
}
