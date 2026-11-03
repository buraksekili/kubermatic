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
	"context"
	"testing"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fakeInformer struct {
	synced bool
}

func (f fakeInformer) HasSynced() bool { return f.synced }

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := kubermaticv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func newStoreClient(t *testing.T, objects ...ctrlruntimeclient.Object) *ctrlruntimefakeclient.ClientBuilder {
	t.Helper()
	return ctrlruntimefakeclient.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objects...)
}

func TestCacheStore(t *testing.T) {
	token := testToken()
	token.SetGeneration(1)
	attribute := testAttribute()

	client := newStoreClient(t, token, attribute).WithStatusSubresource(&kubermaticv1.UserClusterToken{}).Build()
	store := NewCacheStore(testNamespace, client, fakeInformer{true}, fakeInformer{true})

	got, err := store.GetToken(context.Background(), testTokenID)
	if err != nil || got == nil {
		t.Fatalf("GetToken: got %v, %v", got, err)
	}
	if got.Spec.TokenHash != token.Spec.TokenHash {
		t.Errorf("got hash %q, want %q", got.Spec.TokenHash, token.Spec.TokenHash)
	}

	// a token object with the same name in another namespace is invisible
	missing, err := store.GetToken(context.Background(), "zzzzzzzzzzzz")
	if err != nil || missing != nil {
		t.Errorf("GetToken unknown id: got %v, %v, want nil, nil", missing, err)
	}

	attr, err := store.GetAttribute(context.Background(), testUserID)
	if err != nil || attr == nil {
		t.Fatalf("GetAttribute: got %v, %v", attr, err)
	}
	missingAttr, err := store.GetAttribute(context.Background(), "user-nobody")
	if err != nil || missingAttr != nil {
		t.Errorf("GetAttribute unknown user: got %v, %v, want nil, nil", missingAttr, err)
	}

	tokens, attributes := store.CacheSizes()
	if tokens != 1 || attributes != 1 {
		t.Errorf("cache sizes: got %d tokens, %d attributes, want 1, 1", tokens, attributes)
	}

	if !store.HasSynced() {
		t.Error("HasSynced false with both informers synced")
	}
	store.tokenInformer = fakeInformer{false}
	if store.HasSynced() {
		t.Error("HasSynced true with unsynced token informer")
	}
}

func TestCacheStoreContact(t *testing.T) {
	client := newStoreClient(t).Build()
	store := NewCacheStore(testNamespace, client, fakeInformer{false}, fakeInformer{false})

	if !store.LastContact().IsZero() {
		t.Error("LastContact not zero before any contact")
	}

	mark := time.Now()
	store.MarkContact(mark)
	if !store.LastContact().Equal(mark) {
		t.Errorf("LastContact: got %v, want %v", store.LastContact(), mark)
	}
}

// Rule 10: the lastUsedTime write must be a merge patch of that one field,
// so the fields owned by the seed token controller survive it.
func TestLastUsedPatchWriterTouchesOnlyLastUsedTime(t *testing.T) {
	token := testToken()
	token.Status.State = kubermaticv1.UserClusterTokenActive
	token.Status.ObservedGeneration = 7
	token.Status.Reason = kubermaticv1.UserClusterTokenExpired // set on purpose: must survive

	client := newStoreClient(t, token).WithStatusSubresource(&kubermaticv1.UserClusterToken{}).Build()
	writer := NewLastUsedPatchWriter(client)

	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if err := writer.WriteLastUsed(context.Background(), testNamespace, testTokenID, now); err != nil {
		t.Fatalf("WriteLastUsed: %v", err)
	}

	updated := &kubermaticv1.UserClusterToken{}
	if err := client.Get(context.Background(), objectKey(testNamespace, testTokenID), updated); err != nil {
		t.Fatal(err)
	}

	if updated.Status.LastUsedTime == nil || !updated.Status.LastUsedTime.Time.Equal(now) {
		t.Errorf("lastUsedTime: got %v, want %v", updated.Status.LastUsedTime, now)
	}
	if updated.Status.State != kubermaticv1.UserClusterTokenActive {
		t.Errorf("state overwritten: got %q", updated.Status.State)
	}
	if updated.Status.ObservedGeneration != 7 {
		t.Errorf("observedGeneration overwritten: got %d", updated.Status.ObservedGeneration)
	}
	if updated.Status.Reason != kubermaticv1.UserClusterTokenExpired {
		t.Errorf("reason overwritten: got %q", updated.Status.Reason)
	}
}

func objectKey(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}
