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

package projectmember

import (
	"context"
	"testing"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testProject = "ks"
	testEmail   = "bob@example.com"
	testGroup   = "kkp-users"
)

func testUser() *kubermaticv1.User {
	return &kubermaticv1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "5ff860bf1190596c7188ab851db691f0f3169c453936e9e1eba2f9a47f7a0018"},
		Spec:       kubermaticv1.UserSpec{Email: testEmail, Groups: []string{testGroup}},
	}
}

// deleting marks an object as being deleted. The fake client refuses a deletion
// timestamp without a finalizer, and a real binding keeps one while KKP cleans up.
func deleting(obj metav1.Object) {
	now := metav1.Now()
	obj.SetDeletionTimestamp(&now)
	obj.SetFinalizers([]string{"kubermatic.k8c.io/cleanup-seed-user-project-bindings"})
}

func TestIsMemberIgnoresBindingsBeingDeleted(t *testing.T) {
	upb := func() *kubermaticv1.UserProjectBinding {
		return &kubermaticv1.UserProjectBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "bob-ks"},
			Spec:       kubermaticv1.UserProjectBindingSpec{UserEmail: testEmail, ProjectID: testProject, Group: "editors-" + testProject},
		}
	}
	gpb := func() *kubermaticv1.GroupProjectBinding {
		return &kubermaticv1.GroupProjectBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "users-ks"},
			Spec:       kubermaticv1.GroupProjectBindingSpec{Group: testGroup, ProjectID: testProject, Role: "viewers"},
		}
	}

	testCases := []struct {
		name     string
		bindings func() []ctrlruntimeclient.Object
		want     bool
	}{
		{
			name:     "user binding",
			bindings: func() []ctrlruntimeclient.Object { return []ctrlruntimeclient.Object{upb()} },
			want:     true,
		},
		{
			// seen on a real seed: the binding sat in deletion behind its cleanup
			// finalizer for about 7 minutes while the user kept access
			name: "user binding being deleted",
			bindings: func() []ctrlruntimeclient.Object {
				b := upb()
				deleting(b)
				return []ctrlruntimeclient.Object{b}
			},
			want: false,
		},
		{
			name:     "group binding",
			bindings: func() []ctrlruntimeclient.Object { return []ctrlruntimeclient.Object{gpb()} },
			want:     true,
		},
		{
			name: "group binding being deleted",
			bindings: func() []ctrlruntimeclient.Object {
				b := gpb()
				deleting(b)
				return []ctrlruntimeclient.Object{b}
			},
			want: false,
		},
		{
			name: "one binding being deleted, another one active",
			bindings: func() []ctrlruntimeclient.Object {
				b := upb()
				deleting(b)
				return []ctrlruntimeclient.Object{b, gpb()}
			},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := kubermaticv1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			client := ctrlruntimefakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(tc.bindings()...).Build()

			got, err := IsMember(context.Background(), client, testUser(), testProject)
			if err != nil {
				t.Fatalf("IsMember: %v", err)
			}
			if got != tc.want {
				t.Errorf("IsMember = %v, want %v", got, tc.want)
			}
		})
	}
}
