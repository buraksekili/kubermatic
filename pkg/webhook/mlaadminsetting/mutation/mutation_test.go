/*
Copyright 2022 The Kubermatic Kubernetes Platform contributors.

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

package mutation

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/go-test/deep"
	"go.uber.org/zap"
	jsonpatch "gomodules.xyz/jsonpatch/v2"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/test"
	"k8c.io/kubermatic/v2/pkg/test/fake"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	testScheme = fake.NewScheme()
)

func TestHandle(t *testing.T) {
	cluster := &kubermaticv1.Cluster{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Cluster",
			APIVersion: "kubermatic.k8c.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "xyz",
			UID:  "12345",
		},
		Status: kubermaticv1.ClusterStatus{
			NamespaceName: "cluster-xyz",
		},
	}

	tests := []struct {
		name        string
		req         webhook.AdmissionRequest
		clusters    []ctrlruntimeclient.Object
		wantError   bool
		wantPatches []jsonpatch.JsonPatchOperation
	}{
		{
			name:     "Add missing cluster name to new setting",
			clusters: []ctrlruntimeclient.Object{cluster},
			req: webhook.AdmissionRequest{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					RequestKind: &metav1.GroupVersionKind{
						Group:   kubermaticv1.GroupName,
						Version: kubermaticv1.GroupVersion,
						Kind:    "MLAAdminSetting",
					},
					Name: "foo",
					Object: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:      "my-setting",
							Namespace: cluster.Status.NamespaceName,
						}.Do(),
					},
				},
			},
			wantError: false,
			wantPatches: []jsonpatch.Operation{
				jsonpatch.NewOperation("replace", "/spec/clusterName", cluster.Name),
			},
		},
		{
			name:     "Fix broken cluster name in MLAAdminSetting",
			clusters: []ctrlruntimeclient.Object{cluster},
			req: webhook.AdmissionRequest{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					RequestKind: &metav1.GroupVersionKind{
						Group:   kubermaticv1.GroupName,
						Version: kubermaticv1.GroupVersion,
						Kind:    "MLAAdminSetting",
					},
					Name: "foo",
					Object: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:        "my-setting",
							Namespace:   cluster.Status.NamespaceName,
							ClusterName: "not-the-correct-name",
						}.Do(),
					},
				},
			},
			wantError: false,
			wantPatches: []jsonpatch.Operation{
				jsonpatch.NewOperation("replace", "/spec/clusterName", cluster.Name),
			},
		},
		{
			name:     "Reject settings outside of cluster namespaces",
			clusters: []ctrlruntimeclient.Object{cluster},
			req: webhook.AdmissionRequest{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					RequestKind: &metav1.GroupVersionKind{
						Group:   kubermaticv1.GroupName,
						Version: kubermaticv1.GroupVersion,
						Kind:    "MLAAdminSetting",
					},
					Name: "foo",
					Object: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:      "my-setting",
							Namespace: "this-does-not-exist",
						}.Do(),
					},
				},
			},
			wantError: true,
		},
		{
			name: "Reject new settings in deleted clusters",
			clusters: []ctrlruntimeclient.Object{
				(func(c *kubermaticv1.Cluster) *kubermaticv1.Cluster {
					cluster := c.DeepCopy()
					now := metav1.Now()
					cluster.DeletionTimestamp = &now
					cluster.Finalizers = []string{"dummy"}
					return cluster
				}(cluster)),
			},
			req: webhook.AdmissionRequest{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					RequestKind: &metav1.GroupVersionKind{
						Group:   kubermaticv1.GroupName,
						Version: kubermaticv1.GroupVersion,
						Kind:    "MLAAdminSetting",
					},
					Name: "foo",
					Object: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:      "my-setting",
							Namespace: cluster.Status.NamespaceName,
						}.Do(),
					},
				},
			},
			wantError: true,
		},
		{
			name:     "Allow updating settings when the Cluster is already gone (to allow cleanups to complete)",
			clusters: []ctrlruntimeclient.Object{},
			req: webhook.AdmissionRequest{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					RequestKind: &metav1.GroupVersionKind{
						Group:   kubermaticv1.GroupName,
						Version: kubermaticv1.GroupVersion,
						Kind:    "MLAAdminSetting",
					},
					Name: "foo",
					OldObject: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:       "my-setting",
							Namespace:  cluster.Status.NamespaceName,
							Finalizers: []string{"a", "b"},
						}.Do(),
					},
					Object: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:       "my-setting",
							Namespace:  cluster.Status.NamespaceName,
							Finalizers: []string{"a"},
						}.Do(),
					},
				},
			},
			wantError: false,
		},
		{
			name:     "Forbid changing the Cluster name",
			clusters: []ctrlruntimeclient.Object{cluster},
			req: webhook.AdmissionRequest{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					RequestKind: &metav1.GroupVersionKind{
						Group:   kubermaticv1.GroupName,
						Version: kubermaticv1.GroupVersion,
						Kind:    "MLAAdminSetting",
					},
					Name: "foo",
					OldObject: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:        "my-setting",
							Namespace:   cluster.Status.NamespaceName,
							ClusterName: cluster.Name,
						}.Do(),
					},
					Object: runtime.RawExtension{
						Raw: rawSettingGen{
							Name:        "my-setting",
							Namespace:   cluster.Status.NamespaceName,
							ClusterName: "wrong",
						}.Do(),
					},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seedClient := fake.NewClientBuilder().WithObjects(tt.clusters...).Build()
			seed := &kubermaticv1.Seed{}

			handler := AdmissionHandler{
				log:        zap.NewNop().Sugar(),
				decoder:    admission.NewDecoder(testScheme),
				seedGetter: test.NewSeedGetter(seed),
				seedClientGetter: func(seed *kubermaticv1.Seed) (ctrlruntimeclient.Client, error) {
					return seedClient, nil
				},
			}
			res := handler.Handle(context.Background(), tt.req)
			if res.Result != nil && res.Result.Code == http.StatusInternalServerError {
				if tt.wantError {
					return
				}

				t.Fatalf("Request failed: %v", res.Result.Message)
			}

			a := map[string]jsonpatch.JsonPatchOperation{}
			for _, p := range res.Patches {
				a[p.Path] = p
			}
			w := map[string]jsonpatch.JsonPatchOperation{}
			for _, p := range tt.wantPatches {
				w[p.Path] = p
			}
			if diff := deep.Equal(a, w); len(diff) > 0 {
				t.Errorf("Diff found between wanted and actual patches: %+v", diff)
			}
		})
	}
}

type rawSettingGen struct {
	Name        string
	Namespace   string
	Finalizers  []string
	ClusterName string
}

func (r rawSettingGen) Do() []byte {
	setting := kubermaticv1.MLAAdminSetting{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kubermatic.k8c.io/v1",
			Kind:       "MLAAdminSetting",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       r.Name,
			Namespace:  r.Namespace,
			Finalizers: r.Finalizers,
		},
		Spec: kubermaticv1.MLAAdminSettingSpec{
			ClusterName: r.ClusterName,
		},
	}

	s := json.NewSerializerWithOptions(json.DefaultMetaFactory, testScheme, testScheme, json.SerializerOptions{Pretty: true})
	buff := bytes.NewBuffer([]byte{})
	_ = s.Encode(&setting, buff)

	return buff.Bytes()
}
