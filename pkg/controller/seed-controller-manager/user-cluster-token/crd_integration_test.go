//go:build integration

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

package userclustertoken

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const (
	testHash      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testNamespace = "cluster-abc123"
)

func validSpec() map[string]any {
	return map[string]any{
		"tokenHash":      testHash,
		"userID":         "user-1",
		"clusterID":      "abc123",
		"clusterUID":     "6f2b4c1e-1111-2222-3333-444455556666",
		"seedName":       "europe-west",
		"issueTime":      "2026-11-02T10:00:00Z",
		"expirationTime": "2026-11-03T10:00:00Z",
		"label":          "laptop",
	}
}

func object(kind, name, namespace string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubermatic.k8c.io", Version: "v1", Kind: kind})
	u.SetName(name)
	u.SetNamespace(namespace)

	return u
}

func startEnv(t *testing.T) (context.Context, ctrlruntimeclient.Client) {
	t.Helper()

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../../crd/k8c.io"},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("failed to start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	client, err := ctrlruntimeclient.New(cfg, ctrlruntimeclient.Options{})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}); err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}

	return ctx, client
}

func TestUserClusterTokenCRDValidation(t *testing.T) {
	ctx, client := startEnv(t)

	without := func(field string) map[string]any {
		s := validSpec()
		delete(s, field)
		return s
	}
	with := func(field string, value any) map[string]any {
		s := validSpec()
		s[field] = value
		return s
	}

	testcases := []struct {
		name      string
		kind      string
		objName   string
		namespace string
		spec      map[string]any
		wantErr   string
	}{
		{name: "valid token", kind: "UserClusterToken", objName: "aaaabbbbccccdddd", namespace: testNamespace, spec: validSpec()},
		{name: "valid issuance", kind: "UserClusterTokenIssuance", objName: "aaaabbbbccccdddd", spec: validSpec()},
		{name: "missing hash", kind: "UserClusterToken", objName: "missinghash00001", namespace: testNamespace, spec: without("tokenHash"), wantErr: "spec.tokenHash: Required value"},
		{name: "missing expiry", kind: "UserClusterToken", objName: "missingexpiry001", namespace: testNamespace, spec: without("expirationTime"), wantErr: "spec.expirationTime: Required value"},
		{name: "missing issue time", kind: "UserClusterTokenIssuance", objName: "missingissue0001", spec: without("issueTime"), wantErr: "spec.issueTime: Required value"},
		{name: "missing seed name", kind: "UserClusterTokenIssuance", objName: "missingseed00001", spec: without("seedName"), wantErr: "spec.seedName: Required value"},
		{name: "missing cluster UID", kind: "UserClusterTokenIssuance", objName: "missinguid000001", spec: without("clusterUID"), wantErr: "spec.clusterUID: Required value"},
		{name: "uppercase hash", kind: "UserClusterToken", objName: "upperhash0000001", namespace: testNamespace, spec: with("tokenHash", strings.ToUpper(testHash)), wantErr: "spec.tokenHash"},
		{name: "short hash", kind: "UserClusterToken", objName: "shorthash0000001", namespace: testNamespace, spec: with("tokenHash", "abc"), wantErr: "spec.tokenHash"},
		{name: "expiry before issue", kind: "UserClusterToken", objName: "expirybefore0001", namespace: testNamespace, spec: with("expirationTime", "2026-11-01T10:00:00Z"), wantErr: "spec.expirationTime must be after spec.issueTime"},
		{name: "name not a token ID", kind: "UserClusterToken", objName: "not-a-token-id", namespace: testNamespace, spec: validSpec(), wantErr: "name must be the token ID"},
		{name: "secret-like name too long", kind: "UserClusterTokenIssuance", objName: strings.Repeat("a", 33), spec: validSpec(), wantErr: "name must be the token ID"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := client.Create(ctx, object(tc.kind, tc.objName, tc.namespace, tc.spec))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestUserClusterTokenCRDImmutability(t *testing.T) {
	ctx, client := startEnv(t)

	obj := object("UserClusterToken", "immutable000001", testNamespace, validSpec())
	if err := client.Create(ctx, obj); err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	for field, value := range map[string]any{
		"tokenHash":      strings.Repeat("f", 64),
		"userID":         "user-2",
		"clusterID":      "xyz789",
		"clusterUID":     "other",
		"seedName":       "other-seed",
		"issueTime":      "2026-11-02T09:00:00Z",
		"expirationTime": "2026-11-09T10:00:00Z",
	} {
		t.Run(field, func(t *testing.T) {
			changed := obj.DeepCopy()
			spec := changed.Object["spec"].(map[string]any)
			spec[field] = value

			err := client.Update(ctx, changed)
			if err == nil || !strings.Contains(err.Error(), field+" is immutable") {
				t.Fatalf("expected %s to be immutable, got: %v", field, err)
			}
		})
	}

	t.Run("label is mutable", func(t *testing.T) {
		changed := obj.DeepCopy()
		changed.Object["spec"].(map[string]any)["label"] = "ci"
		if err := client.Update(ctx, changed); err != nil {
			t.Fatalf("expected label update to succeed: %v", err)
		}
	})
}

func TestUserClusterTokenStatusIsSubresource(t *testing.T) {
	ctx, client := startEnv(t)

	obj := object("UserClusterToken", "statussub000001", testNamespace, validSpec())
	obj.Object["status"] = map[string]any{"state": "Active", "username": "other-user@example.com"}
	if err := client.Create(ctx, obj); err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	got := object("UserClusterToken", "", "", nil)
	if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(obj), got); err != nil {
		t.Fatalf("failed to get token: %v", err)
	}
	if _, ok := got.Object["status"]; ok {
		t.Fatalf("status set on create must be dropped, got %v", got.Object["status"])
	}
}

func TestUserClusterTokenRevocationCRDValidation(t *testing.T) {
	ctx, client := startEnv(t)

	testcases := []struct {
		name    string
		spec    map[string]any
		wantErr string
	}{
		{name: "cluster", spec: map[string]any{"clusterID": "abc123", "issuedBefore": "2026-11-02T10:00:00Z"}},
		{name: "seed", spec: map[string]any{"seedName": "europe", "issuedBefore": "2026-11-02T10:00:00Z"}},
		{name: "both", spec: map[string]any{"clusterID": "abc123", "seedName": "europe", "issuedBefore": "2026-11-02T10:00:00Z"}, wantErr: "exactly one of clusterID and seedName"},
		{name: "neither", spec: map[string]any{"issuedBefore": "2026-11-02T10:00:00Z"}, wantErr: "exactly one of clusterID and seedName"},
		{name: "no time", spec: map[string]any{"clusterID": "abc123"}, wantErr: "spec.issuedBefore: Required value"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := client.Create(ctx, object("UserClusterTokenRevocation", "rev-"+tc.name, "", tc.spec))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestUserClusterAttributeCRDValidation(t *testing.T) {
	ctx, client := startEnv(t)

	attribute := func(name, userID string) *unstructured.Unstructured {
		return object("UserClusterAttribute", name, testNamespace, map[string]any{"userID": userID})
	}

	if err := client.Create(ctx, attribute("user-alice", "user-alice")); err != nil {
		t.Fatalf("expected valid attribute to be accepted: %v", err)
	}

	if err := client.Create(ctx, attribute("user-bob", "user-alice")); err == nil || !strings.Contains(err.Error(), "name must equal spec.userID") {
		t.Fatalf("expected name/userID mismatch to be rejected, got: %v", err)
	}

	if err := client.Create(ctx, object("UserClusterAttribute", "user-carol", testNamespace, map[string]any{})); err == nil || !strings.Contains(err.Error(), "spec.userID: Required value") {
		t.Fatalf("expected missing userID to be rejected, got: %v", err)
	}
}
