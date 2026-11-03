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
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	now        = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	clusterUID = types.UID("6f2b4c1e-1111-2222-3333-444455556666")
)

const (
	clusterID = "abc123"
	clusterNS = "cluster-abc123"
	projectID = "payments"
	tokenName = "aaaabbbbccccdddd"
	userID    = "user-alice"
)

func genCluster(mods ...func(*kubermaticv1.Cluster)) *kubermaticv1.Cluster {
	c := &kubermaticv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:   clusterID,
			UID:    clusterUID,
			Labels: map[string]string{kubermaticv1.ProjectIDLabelKey: projectID},
		},
		Status: kubermaticv1.ClusterStatus{NamespaceName: clusterNS},
	}
	for _, m := range mods {
		m(c)
	}

	return c
}

func genUser(mods ...func(*kubermaticv1.User)) *kubermaticv1.User {
	u := &kubermaticv1.User{
		ObjectMeta: metav1.ObjectMeta{Name: userID},
		Spec: kubermaticv1.UserSpec{
			Name:   "Alice",
			Email:  "Alice@Example.com",
			Groups: []string{"team-b", "team-a", "team-b"},
		},
	}
	for _, m := range mods {
		m(u)
	}

	return u
}

func genToken(mods ...func(*kubermaticv1.UserClusterToken)) *kubermaticv1.UserClusterToken {
	t := &kubermaticv1.UserClusterToken{
		ObjectMeta: metav1.ObjectMeta{
			Name:       tokenName,
			Namespace:  clusterNS,
			Generation: 1,
		},
		Spec: kubermaticv1.UserClusterTokenSpec{
			TokenHash:      strings.Repeat("a", 64),
			UserID:         userID,
			ClusterID:      clusterID,
			ClusterUID:     string(clusterUID),
			SeedName:       "europe-west",
			IssueTime:      metav1.NewTime(now.Add(-time.Hour)),
			ExpirationTime: metav1.NewTime(now.Add(23 * time.Hour)),
		},
	}
	for _, m := range mods {
		m(t)
	}

	return t
}

func upb(email, project string) *kubermaticv1.UserProjectBinding {
	return &kubermaticv1.UserProjectBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "upb-" + project + "-" + strings.ToLower(email)},
		Spec:       kubermaticv1.UserProjectBindingSpec{UserEmail: email, ProjectID: project, Group: "editors-" + project},
	}
}

func gpb(group, project string) *kubermaticv1.GroupProjectBinding {
	return &kubermaticv1.GroupProjectBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "gpb-" + project + "-" + group},
		Spec:       kubermaticv1.GroupProjectBindingSpec{Group: group, ProjectID: project, Role: "viewers"},
	}
}

func newClientBuilder(objs ...ctrlruntimeclient.Object) *ctrlruntimefakeclient.ClientBuilder {
	scheme := runtime.NewScheme()
	_ = kubermaticv1.AddToScheme(scheme)

	return ctrlruntimefakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&kubermaticv1.UserClusterToken{}, &kubermaticv1.UserClusterAttribute{}).
		WithIndex(&kubermaticv1.UserClusterToken{}, tokenUserIDIndex, tokenUserID).
		WithIndex(&kubermaticv1.User{}, userEmailIndex, userEmail).
		WithIndex(&kubermaticv1.User{}, userGroupIndex, userGroups)
}

func clockNow() time.Time { return now }

func newTokenReconciler(client ctrlruntimeclient.Client, workerName string) *TokenReconciler {
	return &TokenReconciler{Client: client, log: zap.NewNop().Sugar(), workerName: workerName, now: clockNow}
}

func newAttributeReconciler(client ctrlruntimeclient.Client, workerName string) *AttributeReconciler {
	return &AttributeReconciler{Client: client, log: zap.NewNop().Sugar(), workerName: workerName, now: clockNow}
}

func reconcileToken(t *testing.T, r *TokenReconciler) (*kubermaticv1.UserClusterToken, reconcile.Result) {
	t.Helper()

	key := types.NamespacedName{Namespace: clusterNS, Name: tokenName}
	result, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	token := &kubermaticv1.UserClusterToken{}
	if err := r.Get(context.Background(), key, token); err != nil {
		t.Fatalf("failed to get token: %v", err)
	}

	return token, result
}

// reconcileAttribute runs the attribute reconciler and returns the attribute, or nil when
// it does not exist.
func reconcileAttribute(t *testing.T, r *AttributeReconciler) *kubermaticv1.UserClusterAttribute {
	t.Helper()

	key := types.NamespacedName{Namespace: clusterNS, Name: userID}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	attribute := &kubermaticv1.UserClusterAttribute{}
	err := r.Get(context.Background(), key, attribute)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("failed to get attribute: %v", err)
	}

	return attribute
}

func TestTokenTransitions(t *testing.T) {
	deleting := metav1.NewTime(now)

	testcases := []struct {
		name        string
		token       *kubermaticv1.UserClusterToken
		cluster     *kubermaticv1.Cluster
		wantState   kubermaticv1.UserClusterTokenState
		wantReason  kubermaticv1.UserClusterTokenReason
		wantRequeue time.Duration
	}{
		{name: "active", token: genToken(), cluster: genCluster(), wantState: kubermaticv1.UserClusterTokenActive, wantRequeue: 23*time.Hour + time.Second},
		{name: "cluster does not exist", token: genToken(), wantState: kubermaticv1.UserClusterTokenDisabled, wantReason: kubermaticv1.UserClusterTokenClusterNotFound},
		{name: "cluster created again", token: genToken(), cluster: genCluster(func(c *kubermaticv1.Cluster) { c.UID = "new" }), wantState: kubermaticv1.UserClusterTokenDisabled, wantReason: kubermaticv1.UserClusterTokenClusterUIDMismatch},
		{
			name:  "cluster being deleted",
			token: genToken(),
			cluster: genCluster(func(c *kubermaticv1.Cluster) {
				c.DeletionTimestamp = &deleting
				c.Finalizers = []string{"test"}
			}),
			wantState:  kubermaticv1.UserClusterTokenDisabled,
			wantReason: kubermaticv1.UserClusterTokenClusterDeleting,
		},
		{
			name:       "expired",
			token:      genToken(func(tok *kubermaticv1.UserClusterToken) { tok.Spec.ExpirationTime = metav1.NewTime(now) }),
			cluster:    genCluster(),
			wantState:  kubermaticv1.UserClusterTokenDisabled,
			wantReason: kubermaticv1.UserClusterTokenExpired,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			objs := []ctrlruntimeclient.Object{tc.token}
			if tc.cluster != nil {
				objs = append(objs, tc.cluster)
			}
			r := newTokenReconciler(newClientBuilder(objs...).Build(), "")

			token, result := reconcileToken(t, r)

			if token.Status.State != tc.wantState || token.Status.Reason != tc.wantReason {
				t.Fatalf("got %s/%s, want %s/%s", token.Status.State, token.Status.Reason, tc.wantState, tc.wantReason)
			}
			if token.Status.ObservedGeneration != token.Generation || token.Status.LastEvaluationTime == nil {
				t.Errorf("observedGeneration or lastEvaluationTime not set: %+v", token.Status)
			}
			if result.RequeueAfter != tc.wantRequeue {
				t.Errorf("got RequeueAfter %v, want %v", result.RequeueAfter, tc.wantRequeue)
			}
		})
	}
}

func TestTokenKeepsLastUsedTime(t *testing.T) {
	lastUsed := metav1.NewTime(now.Add(-time.Minute).Truncate(time.Second))
	token := genToken(func(tok *kubermaticv1.UserClusterToken) { tok.Status.LastUsedTime = &lastUsed })
	r := newTokenReconciler(newClientBuilder(token, genCluster()).Build(), "")

	got, _ := reconcileToken(t, r)
	if got.Status.LastUsedTime == nil || !got.Status.LastUsedTime.Equal(&lastUsed) {
		t.Fatalf("lastUsedTime changed: got %v, want %v", got.Status.LastUsedTime, lastUsed)
	}
}

func TestTokenWritesOnlyOnChange(t *testing.T) {
	patches := 0
	client := newClientBuilder(genToken(), genCluster()).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c ctrlruntimeclient.Client, sub string, o ctrlruntimeclient.Object, p ctrlruntimeclient.Patch, opts ...ctrlruntimeclient.SubResourcePatchOption) error {
				patches++
				return c.SubResource(sub).Patch(ctx, o, p, opts...)
			},
		}).Build()
	r := newTokenReconciler(client, "")

	reconcileToken(t, r)
	reconcileToken(t, r)
	reconcileToken(t, r)

	if patches != 1 {
		t.Fatalf("expected 1 status patch for 3 reconciles of an unchanged token, got %d", patches)
	}
}

func TestWorkerName(t *testing.T) {
	testcases := []struct {
		name          string
		clusterWorker string
		ourWorker     string
		wantEvaluated bool
	}{
		{name: "both empty", wantEvaluated: true},
		{name: "same worker", clusterWorker: "dev", ourWorker: "dev", wantEvaluated: true},
		{name: "cluster has a worker, we do not", clusterWorker: "dev"},
		{name: "we have a worker, cluster does not", ourWorker: "dev"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := genCluster(func(c *kubermaticv1.Cluster) {
				if tc.clusterWorker != "" {
					c.Labels[kubermaticv1.WorkerNameLabelKey] = tc.clusterWorker
				}
			})
			client := newClientBuilder(genToken(), cluster, genUser(), upb("alice@example.com", projectID)).Build()

			token, _ := reconcileToken(t, newTokenReconciler(client, tc.ourWorker))
			if evaluated := token.Status.State != ""; evaluated != tc.wantEvaluated {
				t.Fatalf("token evaluated = %v, want %v", evaluated, tc.wantEvaluated)
			}

			attribute := reconcileAttribute(t, newAttributeReconciler(client, tc.ourWorker))
			if evaluated := attribute != nil && attribute.Status.State != ""; evaluated != tc.wantEvaluated {
				t.Fatalf("attribute evaluated = %v, want %v", evaluated, tc.wantEvaluated)
			}
		})
	}
}

func TestAttributeTransitions(t *testing.T) {
	deleting := metav1.NewTime(now)

	testcases := []struct {
		name       string
		objects    []ctrlruntimeclient.Object
		wantState  kubermaticv1.UserClusterTokenState
		wantReason kubermaticv1.UserClusterAttributeReason
		wantGroups []string
		wantUser   string
	}{
		{
			name:       "member through UserProjectBinding, email case differs",
			objects:    []ctrlruntimeclient.Object{genUser(), upb("alice@example.com", projectID)},
			wantState:  kubermaticv1.UserClusterTokenActive,
			wantGroups: []string{"team-a", "team-b"},
			wantUser:   "alice@example.com",
		},
		{
			name:       "member through GroupProjectBinding only",
			objects:    []ctrlruntimeclient.Object{genUser(), gpb("team-a", projectID)},
			wantState:  kubermaticv1.UserClusterTokenActive,
			wantGroups: []string{"team-a", "team-b"},
			wantUser:   "alice@example.com",
		},
		{
			name:       "KKP admin without binding",
			objects:    []ctrlruntimeclient.Object{genUser(func(u *kubermaticv1.User) { u.Spec.IsAdmin = true })},
			wantState:  kubermaticv1.UserClusterTokenActive,
			wantGroups: []string{"team-a", "team-b"},
			wantUser:   "alice@example.com",
		},
		{
			name:       "bindings in another project only",
			objects:    []ctrlruntimeclient.Object{genUser(), upb("alice@example.com", "hr"), gpb("team-a", "hr")},
			wantState:  kubermaticv1.UserClusterTokenDisabled,
			wantReason: kubermaticv1.UserClusterAttributeNotProjectMember,
			wantUser:   "alice@example.com",
		},
		{
			name:       "group binding for a group the user does not have",
			objects:    []ctrlruntimeclient.Object{genUser(), gpb("team-c", projectID)},
			wantState:  kubermaticv1.UserClusterTokenDisabled,
			wantReason: kubermaticv1.UserClusterAttributeNotProjectMember,
			wantUser:   "alice@example.com",
		},
		{
			name:       "user does not exist",
			objects:    []ctrlruntimeclient.Object{upb("alice@example.com", projectID)},
			wantState:  kubermaticv1.UserClusterTokenDisabled,
			wantReason: kubermaticv1.UserClusterAttributeUserNotFound,
		},
		{
			name: "user being deleted",
			objects: []ctrlruntimeclient.Object{upb("alice@example.com", projectID), genUser(func(u *kubermaticv1.User) {
				u.DeletionTimestamp = &deleting
				u.Finalizers = []string{"test"}
			})},
			wantState:  kubermaticv1.UserClusterTokenDisabled,
			wantReason: kubermaticv1.UserClusterAttributeUserNotFound,
			wantUser:   "alice@example.com",
		},
		{
			name: "project service account",
			objects: []ctrlruntimeclient.Object{upb("serviceaccount-xyz@localhost", projectID), genUser(func(u *kubermaticv1.User) {
				u.Spec.Email = "serviceaccount-xyz@localhost"
				u.Spec.Project = projectID
			})},
			wantState:  kubermaticv1.UserClusterTokenDisabled,
			wantReason: kubermaticv1.UserClusterAttributeServiceAccountUser,
			wantUser:   "serviceaccount-xyz@localhost",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			objs := append([]ctrlruntimeclient.Object{genToken(), genCluster()}, tc.objects...)
			r := newAttributeReconciler(newClientBuilder(objs...).Build(), "")

			attribute := reconcileAttribute(t, r)
			if attribute == nil {
				t.Fatal("attribute not created")
			}
			if attribute.Spec.UserID != userID {
				t.Errorf("got spec.userID %q, want %q", attribute.Spec.UserID, userID)
			}

			st := attribute.Status
			if st.State != tc.wantState || st.Reason != tc.wantReason {
				t.Fatalf("got %s/%s, want %s/%s", st.State, st.Reason, tc.wantState, tc.wantReason)
			}
			if st.Username != tc.wantUser {
				t.Errorf("got username %q, want %q", st.Username, tc.wantUser)
			}
			if !slices.Equal(st.Groups, tc.wantGroups) {
				t.Errorf("got groups %v, want %v", st.Groups, tc.wantGroups)
			}
			if st.LastTransitionTime == nil || st.LastEvaluationTime == nil || st.ObservedGeneration != attribute.Generation {
				t.Errorf("bookkeeping fields not set: %+v", st)
			}
		})
	}
}

func TestAttributeLifecycleFollowsTokens(t *testing.T) {
	ctx := context.Background()
	second := genToken(func(tok *kubermaticv1.UserClusterToken) { tok.Name = "bbbbccccddddeeee" })
	client := newClientBuilder(genToken(), second, genCluster(), genUser(), upb("alice@example.com", projectID)).Build()
	r := newAttributeReconciler(client, "")

	if reconcileAttribute(t, r) == nil {
		t.Fatal("attribute not created for a user with tokens")
	}

	if err := client.Delete(ctx, genToken()); err != nil {
		t.Fatalf("failed to delete token: %v", err)
	}
	if reconcileAttribute(t, r) == nil {
		t.Fatal("attribute deleted while the user still has a token")
	}

	if err := client.Delete(ctx, second); err != nil {
		t.Fatalf("failed to delete token: %v", err)
	}
	if reconcileAttribute(t, r) != nil {
		t.Fatal("attribute not deleted after the last token was gone")
	}
}

func TestAttributeMembershipRemovedAndGroupsChange(t *testing.T) {
	ctx := context.Background()
	binding := upb("alice@example.com", projectID)
	user := genUser()
	client := newClientBuilder(genToken(), genCluster(), user, binding, gpb("team-a", "hr")).Build()
	r := newAttributeReconciler(client, "")

	r.now = func() time.Time { return now }
	first := reconcileAttribute(t, r)
	if first.Status.State != kubermaticv1.UserClusterTokenActive {
		t.Fatalf("expected Active, got %s/%s", first.Status.State, first.Status.Reason)
	}

	// groups change without a state change: lastTransitionTime stays
	user.Spec.Groups = []string{"team-z"}
	if err := client.Update(ctx, user); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}
	r.now = func() time.Time { return now.Add(time.Minute) }
	got := reconcileAttribute(t, r)
	if !slices.Equal(got.Status.Groups, []string{"team-z"}) {
		t.Fatalf("groups not updated: %v", got.Status.Groups)
	}
	if !got.Status.LastTransitionTime.Equal(first.Status.LastTransitionTime) {
		t.Errorf("lastTransitionTime moved without a state change")
	}

	// removal: Disabled, no groups, new lastTransitionTime
	if err := client.Delete(ctx, binding); err != nil {
		t.Fatalf("failed to delete binding: %v", err)
	}
	r.now = func() time.Time { return now.Add(2 * time.Minute) }
	got = reconcileAttribute(t, r)
	if got.Status.Reason != kubermaticv1.UserClusterAttributeNotProjectMember || len(got.Status.Groups) != 0 {
		t.Fatalf("expected NotProjectMember without groups, got %+v", got.Status)
	}
	if !got.Status.LastTransitionTime.Time.Equal(now.Add(2 * time.Minute)) {
		t.Errorf("lastTransitionTime not moved on the transition: %v", got.Status.LastTransitionTime)
	}
}

func TestAttributeMapFunctions(t *testing.T) {
	alice := genUser()
	bob := genUser(func(u *kubermaticv1.User) {
		u.Name = "user-bob"
		u.Spec.Email = "bob@example.com"
		u.Spec.Groups = []string{"team-c"}
	})
	aliceToken := genToken()
	aliceSecond := genToken(func(tok *kubermaticv1.UserClusterToken) { tok.Name = "ddddeeeeffffgggg" })
	bobToken := genToken(func(tok *kubermaticv1.UserClusterToken) {
		tok.Name = "bbbbccccddddeeee"
		tok.Spec.UserID = "user-bob"
	})
	otherClusterToken := genToken(func(tok *kubermaticv1.UserClusterToken) {
		tok.Name = "ccccddddeeeeffff"
		tok.Namespace = "cluster-xyz789"
		tok.Spec.ClusterID = "xyz789"
	})

	client := newClientBuilder(alice, bob, aliceToken, aliceSecond, bobToken, otherClusterToken).Build()
	r := newAttributeReconciler(client, "")
	tr := newTokenReconciler(client, "")
	ctx := context.Background()

	keys := func(reqs []reconcile.Request) []string {
		var out []string
		for _, req := range reqs {
			out = append(out, req.String())
		}
		slices.Sort(out)
		return out
	}

	testcases := []struct {
		name string
		got  []reconcile.Request
		want []string
	}{
		{name: "token maps to its owner's attribute", got: r.attributeForToken(ctx, bobToken), want: []string{clusterNS + "/user-bob"}},
		{name: "cluster maps to one attribute per user", got: r.attributesForCluster(ctx, genCluster()), want: []string{clusterNS + "/user-alice", clusterNS + "/user-bob"}},
		{name: "user maps to every cluster namespace with tokens", got: r.attributesForUser(ctx, alice), want: []string{clusterNS + "/user-alice", "cluster-xyz789/user-alice"}},
		{name: "user binding matches email case-insensitively", got: r.attributesForUserProjectBinding(ctx, upb("BOB@example.com", projectID)), want: []string{clusterNS + "/user-bob"}},
		{name: "group binding maps to users with the group", got: r.attributesForGroupProjectBinding(ctx, gpb("team-c", projectID)), want: []string{clusterNS + "/user-bob"}},
		{name: "unknown user maps to nothing", got: r.attributesForUserProjectBinding(ctx, upb("carol@example.com", projectID))},
		{name: "cluster maps to its tokens", got: tr.tokensForCluster(ctx, genCluster()), want: []string{clusterNS + "/" + aliceToken.Name, clusterNS + "/" + bobToken.Name, clusterNS + "/" + aliceSecond.Name}},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if got := keys(tc.got); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}
