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
	"fmt"
	"net"

	"k8c.io/kubermatic/v2/pkg/resources"
	"k8c.io/reconciler/pkg/reconciling"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// IngressPolicyReconciler returns the reconciler for the webhook ingress policy: only
// kube-apiserver pods of the same cluster namespace may call the TokenReview port. The
// health port stays open for kubelet probes and metrics scraping.
func IngressPolicyReconciler() reconciling.NamedNetworkPolicyReconcilerFactory {
	return func() (string, reconciling.NetworkPolicyReconciler) {
		return NetworkPolicyIngress, func(np *networkingv1.NetworkPolicy) (*networkingv1.NetworkPolicy, error) {
			httpsPort := intstr.FromInt32(ListenPort)
			healthPort := intstr.FromInt32(HealthPort)

			np.Spec = networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: resources.BaseAppLabels(Name, nil),
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										resources.AppLabelKey: resources.ApiserverDeploymentName,
									},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolTCP),
								Port:     &httpsPort,
							},
						},
					},
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolTCP),
								Port:     &healthPort,
							},
						},
					},
				},
			}

			return np, nil
		}
	}
}

// EgressPolicyReconciler returns the reconciler for the webhook egress policy: the webhook
// only talks to the seed kube-apiserver (informer and lastUsedTime patches), so egress is
// limited to its endpoints.
func EgressPolicyReconciler(seedApiserverIPs []net.IP) reconciling.NamedNetworkPolicyReconcilerFactory {
	return func() (string, reconciling.NetworkPolicyReconciler) {
		return NetworkPolicyEgress, func(np *networkingv1.NetworkPolicy) (*networkingv1.NetworkPolicy, error) {
			np.Spec = networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: resources.BaseAppLabels(Name, nil),
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeEgress,
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						// no port: policies match after the Service DNAT, so the
						// port is the endpoint's (6443 on many seeds), not the
						// kubernetes Service's 443. same shape as the apiserver's
						// own seed-apiserver-allow policy.
						To: ipListToPeers(seedApiserverIPs),
					},
				},
			}

			return np, nil
		}
	}
}

func ipListToPeers(ips []net.IP) []networkingv1.NetworkPolicyPeer {
	result := make([]networkingv1.NetworkPolicyPeer, 0, len(ips))

	for _, ip := range ips {
		cidr := fmt.Sprintf("%s/%d", ip.String(), net.IPv4len*8)
		if ip.To4() == nil {
			cidr = fmt.Sprintf("%s/%d", ip.String(), net.IPv6len*8)
		}
		result = append(result, networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{
				CIDR: cidr,
			},
		})
	}

	return result
}
