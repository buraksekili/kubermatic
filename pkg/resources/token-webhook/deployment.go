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
	"path/filepath"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/kubernetes"
	"k8c.io/kubermatic/v2/pkg/resources"
	"k8c.io/reconciler/pkg/reconciling"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

const (
	replicas = 2

	servingCertVolume = "serving-cert"
	servingCertDir    = "/etc/kkp-token-webhook/serving"
	clientCAVolume    = "client-ca"
	clientCADir       = "/etc/kkp-token-webhook/client-ca"
)

var defaultResourceRequirements = corev1.ResourceRequirements{
	Requests: corev1.ResourceList{
		corev1.ResourceMemory: resource.MustParse("32Mi"),
		corev1.ResourceCPU:    resource.MustParse("25m"),
	},
	Limits: corev1.ResourceList{
		corev1.ResourceMemory: resource.MustParse("256Mi"),
		corev1.ResourceCPU:    resource.MustParse("500m"),
	},
}

type deploymentData interface {
	Cluster() *kubermaticv1.Cluster
	KubermaticConfiguration() *kubermaticv1.KubermaticConfiguration
	RewriteImage(string) (string, error)
	SupportsFailureDomainZoneAntiAffinity() bool
}

// DeploymentReconciler returns the function to create and update the token webhook Deployment.
func DeploymentReconciler(data deploymentData) reconciling.NamedDeploymentReconcilerFactory {
	return func() (string, reconciling.DeploymentReconciler) {
		return Name, func(d *appsv1.Deployment) (*appsv1.Deployment, error) {
			cluster := data.Cluster()
			baseLabels := resources.BaseAppLabels(Name, nil)
			kubernetes.EnsureLabels(d, baseLabels)

			d.Spec.Replicas = ptr.To[int32](replicas)
			d.Spec.Selector = &metav1.LabelSelector{MatchLabels: baseLabels}

			// never drop below the desired replicas during a rollout, so a webhook
			// update cannot leave kube-apiserver without a ready webhook
			maxUnavailable := intstr.FromInt32(0)
			maxSurge := intstr.FromInt32(1)
			d.Spec.Strategy = appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
					MaxSurge:       &maxSurge,
				},
			}

			kubernetes.EnsureLabels(&d.Spec.Template, baseLabels)
			kubernetes.EnsureAnnotations(&d.Spec.Template, map[string]string{
				"prometheus.io/scrape":                 "true",
				"prometheus.io/port":                   fmt.Sprint(HealthPort),
				"fluentbit.io/parser":                  "json_iso",
				resources.ClusterLastRestartAnnotation: cluster.Annotations[resources.ClusterLastRestartAnnotation],
			})

			podSpec := &d.Spec.Template.Spec
			podSpec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: resources.ImagePullSecretName}}
			podSpec.ServiceAccountName = Name
			podSpec.AutomountServiceAccountToken = ptr.To(true)
			podSpec.SecurityContext = &corev1.PodSecurityContext{
				RunAsNonRoot: ptr.To(true),
				RunAsUser:    ptr.To[int64](65534),
				RunAsGroup:   ptr.To[int64](65534),
				FSGroup:      ptr.To[int64](65534),
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			}

			podSpec.Affinity = resources.HostnameAntiAffinity(Name, kubermaticv1.AntiAffinityTypePreferred)
			if data.SupportsFailureDomainZoneAntiAffinity() {
				zoneAntiAffinity := resources.FailureDomainZoneAntiAffinity(Name, kubermaticv1.AntiAffinityTypePreferred)
				podSpec.Affinity = resources.MergeAffinities(podSpec.Affinity, zoneAntiAffinity)
			}

			podSpec.Volumes = []corev1.Volume{
				{
					Name: servingCertVolume,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: ServingCertSecretName,
							Items: []corev1.KeyToPath{
								{Key: resources.ServingCertSecretKey, Path: resources.ServingCertSecretKey},
								{Key: resources.ServingCertKeySecretKey, Path: resources.ServingCertKeySecretKey},
							},
						},
					},
				},
				{
					Name: clientCAVolume,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: ClientCASecretName,
							// only the certificate; the CA key stays out of the pod
							Items: []corev1.KeyToPath{
								{Key: resources.CACertSecretKey, Path: resources.CACertSecretKey},
							},
						},
					},
				},
			}

			image, err := data.RewriteImage(Image())
			if err != nil {
				return nil, fmt.Errorf("failed to rewrite image %q: %w", Image(), err)
			}

			podSpec.Containers = []corev1.Container{
				{
					Name:    Name,
					Image:   image,
					Command: []string{Name},
					Args:    containerArgs(cluster, SettingsFrom(data.KubermaticConfiguration())),
					Ports: []corev1.ContainerPort{
						{
							Name:          "https",
							ContainerPort: ListenPort,
							Protocol:      corev1.ProtocolTCP,
						},
						{
							Name:          "health",
							ContainerPort: HealthPort,
							Protocol:      corev1.ProtocolTCP,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      servingCertVolume,
							MountPath: servingCertDir,
							ReadOnly:  true,
						},
						{
							Name:      clientCAVolume,
							MountPath: clientCADir,
							ReadOnly:  true,
						},
					},
					Resources: *defaultResourceRequirements.DeepCopy(),
					// readiness follows the informer sync and staleness, so a pod that cannot
					// decide gets no traffic; this is safe because the webhook is not a
					// container of the kube-apiserver pod
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/readyz",
								Port:   intstr.FromString("health"),
								Scheme: corev1.URISchemeHTTP,
							},
						},
						PeriodSeconds:    5,
						TimeoutSeconds:   2,
						SuccessThreshold: 1,
						FailureThreshold: 3,
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/healthz",
								Port:   intstr.FromString("health"),
								Scheme: corev1.URISchemeHTTP,
							},
						},
						InitialDelaySeconds: 15,
						PeriodSeconds:       10,
						TimeoutSeconds:      2,
						SuccessThreshold:    1,
						FailureThreshold:    6,
					},
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: ptr.To(false),
						ReadOnlyRootFilesystem:   ptr.To(true),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
				},
			}

			return d, nil
		}
	}
}

func containerArgs(cluster *kubermaticv1.Cluster, settings Settings) []string {
	args := []string{
		"-cluster-id=" + cluster.Name,
		"-cluster-uid=" + string(cluster.UID),
		"-namespace=" + cluster.Status.NamespaceName,
		fmt.Sprintf("-listen-address=:%d", ListenPort),
		"-tls-cert-file=" + filepath.Join(servingCertDir, resources.ServingCertSecretKey),
		"-tls-key-file=" + filepath.Join(servingCertDir, resources.ServingCertKeySecretKey),
		"-client-ca-file=" + filepath.Join(clientCADir, resources.CACertSecretKey),
		"-client-common-name=" + ClientCommonName,
		fmt.Sprintf("-health-address=:%d", HealthPort),
		"-max-staleness=" + MaxStaleness.String(),
		"-idle-timeout=" + settings.IdleTimeout.String(),
		"-last-used-update-interval=" + LastUsedUpdateInterval.String(),
		"-log-format=json",
	}

	if cluster.Spec.DebugLog {
		args = append(args, "-log-debug=true")
	}

	return args
}
