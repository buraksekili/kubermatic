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

package resources

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"k8c.io/kubermatic/v2/pkg/resources"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestEnsureExternalAdminUserIsRemoved(t *testing.T) {
	externalAdminUserServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: resources.UserClusterLegacyExternalAdminUserServiceAccountName, Namespace: metav1.NamespaceSystem},
	}
	externalAdminUserClusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: resources.UserClusterLegacyExternalAdminUserClusterRoleBindingName},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      resources.UserClusterLegacyExternalAdminUserServiceAccountName,
			Namespace: metav1.NamespaceSystem,
		}},
	}
	// Objects with the same name in another namespace, or unrelated objects
	// in kube-system, must survive the cleanup.
	unrelatedObjects := []ctrlruntimeclient.Object{
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: resources.UserClusterLegacyExternalAdminUserServiceAccountName, Namespace: metav1.NamespaceDefault},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: metav1.NamespaceSystem},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "system:coredns"},
		},
	}

	testCases := []struct {
		name    string
		objects []ctrlruntimeclient.Object
	}{
		{
			name:    "ServiceAccount and ClusterRoleBinding exist",
			objects: []ctrlruntimeclient.Object{externalAdminUserServiceAccount, externalAdminUserClusterRoleBinding},
		},
		{
			name:    "only the ClusterRoleBinding exists",
			objects: []ctrlruntimeclient.Object{externalAdminUserClusterRoleBinding},
		},
		{
			name:    "only the ServiceAccount exists",
			objects: []ctrlruntimeclient.Object{externalAdminUserServiceAccount},
		},
		{
			name: "nothing to remove",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatalf("add core API to scheme: %v", err)
			}
			if err := rbacv1.AddToScheme(scheme); err != nil {
				t.Fatalf("add rbac API to scheme: %v", err)
			}

			var objects []ctrlruntimeclient.Object
			for _, obj := range append(tc.objects, unrelatedObjects...) {
				objects = append(objects, obj.DeepCopyObject().(ctrlruntimeclient.Object))
			}
			client := ctrlruntimefakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			r := &reconciler{Client: client}

			ctx := context.Background()
			if err := r.ensureExternalAdminUserIsRemoved(ctx); err != nil {
				t.Fatalf("ensureExternalAdminUserIsRemoved() error = %v", err)
			}

			assertNotFound(t, client, types.NamespacedName{Name: resources.UserClusterLegacyExternalAdminUserClusterRoleBindingName}, &rbacv1.ClusterRoleBinding{})
			assertNotFound(t, client, types.NamespacedName{Name: resources.UserClusterLegacyExternalAdminUserServiceAccountName, Namespace: metav1.NamespaceSystem}, &corev1.ServiceAccount{})

			for _, obj := range unrelatedObjects {
				key := ctrlruntimeclient.ObjectKeyFromObject(obj)
				if err := client.Get(ctx, key, obj.DeepCopyObject().(ctrlruntimeclient.Object)); err != nil {
					t.Errorf("expected unrelated %T %s to be kept, got error: %v", obj, key, err)
				}
			}

			// A second run must be a no-op.
			if err := r.ensureExternalAdminUserIsRemoved(ctx); err != nil {
				t.Fatalf("second ensureExternalAdminUserIsRemoved() error = %v", err)
			}
		})
	}
}

func assertNotFound(t *testing.T, client ctrlruntimeclient.Client, key types.NamespacedName, obj ctrlruntimeclient.Object) {
	t.Helper()

	if err := client.Get(context.Background(), key, obj); !apierrors.IsNotFound(err) {
		t.Errorf("expected %T %s to be removed, got error: %v", obj, key, err)
	}
}

func TestEnsureLeftoverWebTerminalSecretsAreRemoved(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef"

	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	old := now.Add(-webTerminalSecretGracePeriod - time.Minute)
	young := now.Add(-time.Minute)

	secret := func(name string, annotations map[string]string) *corev1.Secret {
		return webTerminalTestSecret(name, annotations, old)
	}
	terminalPod := func(secretName string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "webterminal-" + hash, Namespace: metav1.NamespaceSystem},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: "kubeconfig",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: secretName},
					},
				}},
			},
		}
	}
	userAnnotation := map[string]string{"user": "user@example.com"}

	testCases := []struct {
		name          string
		secret        *corev1.Secret
		pod           *corev1.Pod
		expectDeleted bool
	}{
		{
			name:          "no terminal pod",
			secret:        secret("kubeconfig-"+hash, userAnnotation),
			expectDeleted: true,
		},
		{
			name:   "young secret without terminal pod",
			secret: webTerminalTestSecret("kubeconfig-"+hash, userAnnotation, young),
		},
		{
			name: "old secret rewritten recently without terminal pod",
			secret: func() *corev1.Secret {
				s := secret("kubeconfig-"+hash, userAnnotation)
				s.ManagedFields = []metav1.ManagedFieldsEntry{
					managedFieldsEntry(old),
					managedFieldsEntry(young),
				}
				return s
			}(),
		},
		{
			name:   "terminal pod mounts the secret",
			secret: secret("kubeconfig-"+hash, userAnnotation),
			pod:    terminalPod("kubeconfig-" + hash),
		},
		{
			name:          "terminal pod does not mount the secret",
			secret:        secret("kubeconfig-"+hash, userAnnotation),
			pod:           terminalPod("something-else"),
			expectDeleted: true,
		},
		{
			name:   "no user annotation",
			secret: secret("kubeconfig-"+hash, nil),
		},
		{
			name:   "unrelated name",
			secret: secret("admin-kubeconfig", userAnnotation),
		},
		{
			name:   "hash is not hex",
			secret: secret("kubeconfig-0123456789abcdef0123456789abcdeZ", userAnnotation),
		},
		{
			name:   "hash has the wrong length",
			secret: secret("kubeconfig-"+hash+"0", userAnnotation),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			objects := []ctrlruntimeclient.Object{tc.secret}
			if tc.pod != nil {
				objects = append(objects, tc.pod)
			}
			client := ctrlruntimefakeclient.NewClientBuilder().WithObjects(objects...).WithReturnManagedFields().Build()
			r := &reconciler{Client: client, apiReader: client}

			ctx := context.Background()
			if err := r.ensureLeftoverWebTerminalSecretsAreRemoved(ctx, now); err != nil {
				t.Fatalf("ensureLeftoverWebTerminalSecretsAreRemoved() error = %v", err)
			}

			err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(tc.secret), &corev1.Secret{})
			switch {
			case tc.expectDeleted && !apierrors.IsNotFound(err):
				t.Errorf("expected Secret to be deleted, got error: %v", err)
			case !tc.expectDeleted && err != nil:
				t.Errorf("expected Secret to be kept, got error: %v", err)
			}
		})
	}
}

func TestEnsureLeftoverWebTerminalSecretsAreRemovedErrors(t *testing.T) {
	const (
		hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		hashC = "cccccccccccccccccccccccccccccccc"
	)

	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	old := now.Add(-webTerminalSecretGracePeriod - time.Minute)
	userAnnotation := map[string]string{"user": "user@example.com"}
	secretsGR := schema.GroupResource{Resource: "secrets"}

	t.Run("NotFound on delete is ignored", func(t *testing.T) {
		client := ctrlruntimefakeclient.NewClientBuilder().
			WithObjects(webTerminalTestSecret("kubeconfig-"+hashA, userAnnotation, old)).
			WithInterceptorFuncs(interceptor.Funcs{
				Delete: func(_ context.Context, _ ctrlruntimeclient.WithWatch, obj ctrlruntimeclient.Object, _ ...ctrlruntimeclient.DeleteOption) error {
					return apierrors.NewNotFound(secretsGR, obj.GetName())
				},
			}).Build()
		r := &reconciler{Client: client, apiReader: client}

		if err := r.ensureLeftoverWebTerminalSecretsAreRemoved(context.Background(), now); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("Secret changed after listing is kept", func(t *testing.T) {
		secret := webTerminalTestSecret("kubeconfig-"+hashA, userAnnotation, old)
		client := ctrlruntimefakeclient.NewClientBuilder().
			WithObjects(secret).
			WithInterceptorFuncs(interceptor.Funcs{
				// the API rewrites the Secret between the list and the delete.
				Get: func(ctx context.Context, c ctrlruntimeclient.WithWatch, key ctrlruntimeclient.ObjectKey, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.GetOption) error {
					if _, ok := obj.(*corev1.Pod); ok {
						current := &corev1.Secret{}
						if err := c.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(secret), current); err != nil {
							return err
						}
						current.Data = map[string][]byte{"kubeconfig": []byte("new")}
						if err := c.Update(ctx, current); err != nil {
							return err
						}
					}
					return c.Get(ctx, key, obj, opts...)
				},
			}).Build()
		r := &reconciler{Client: client, apiReader: client}

		ctx := context.Background()
		if err := r.ensureLeftoverWebTerminalSecretsAreRemoved(ctx, now); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(secret), &corev1.Secret{}); err != nil {
			t.Errorf("expected Secret to be kept, got error: %v", err)
		}
	})

	t.Run("errors are aggregated and other Secrets are still deleted", func(t *testing.T) {
		client := ctrlruntimefakeclient.NewClientBuilder().
			WithObjects(
				webTerminalTestSecret("kubeconfig-"+hashA, userAnnotation, old),
				webTerminalTestSecret("kubeconfig-"+hashB, userAnnotation, old),
				webTerminalTestSecret("kubeconfig-"+hashC, userAnnotation, old),
			).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c ctrlruntimeclient.WithWatch, key ctrlruntimeclient.ObjectKey, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.GetOption) error {
					if key.Name == "webterminal-"+hashA {
						return errors.New("pod get failed")
					}
					return c.Get(ctx, key, obj, opts...)
				},
				Delete: func(ctx context.Context, c ctrlruntimeclient.WithWatch, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.DeleteOption) error {
					if obj.GetName() == "kubeconfig-"+hashB {
						return errors.New("secret delete failed")
					}
					return c.Delete(ctx, obj, opts...)
				},
			}).Build()
		r := &reconciler{Client: client, apiReader: client}

		ctx := context.Background()
		err := r.ensureLeftoverWebTerminalSecretsAreRemoved(ctx, now)
		if err == nil || !strings.Contains(err.Error(), "pod get failed") || !strings.Contains(err.Error(), "secret delete failed") {
			t.Fatalf("expected both errors to be aggregated, got %v", err)
		}

		assertNotFound(t, client, types.NamespacedName{Name: "kubeconfig-" + hashC, Namespace: metav1.NamespaceSystem}, &corev1.Secret{})
		for _, name := range []string{"kubeconfig-" + hashA, "kubeconfig-" + hashB} {
			if err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: metav1.NamespaceSystem}, &corev1.Secret{}); err != nil {
				t.Errorf("expected Secret %s to be kept, got error: %v", name, err)
			}
		}
	})
}

func webTerminalTestSecret(name string, annotations map[string]string, created time.Time) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         metav1.NamespaceSystem,
			Annotations:       annotations,
			CreationTimestamp: metav1.NewTime(created),
		},
	}
}

func managedFieldsEntry(written time.Time) metav1.ManagedFieldsEntry {
	return metav1.ManagedFieldsEntry{
		Manager:    "kubermatic-api",
		Operation:  metav1.ManagedFieldsOperationUpdate,
		APIVersion: "v1",
		Time:       ptr.To(metav1.NewTime(written)),
		FieldsType: "FieldsV1",
		FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:data":{}}`)},
	}
}
