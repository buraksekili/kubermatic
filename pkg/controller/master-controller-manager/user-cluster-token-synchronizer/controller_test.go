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

package userclustertokensynchronizer

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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

const (
	tokenID    = "aaaabbbbccccdddd"
	clusterID  = "abc123"
	clusterNS  = "cluster-abc123"
	clusterUID = "6f2b4c1e-1111-2222-3333-444455556666"
	seedA      = "europe"
	seedB      = "asia"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = kubermaticv1.AddToScheme(s)
	return s
}

func genIssuance(mods ...func(*kubermaticv1.UserClusterTokenIssuance)) *kubermaticv1.UserClusterTokenIssuance {
	i := &kubermaticv1.UserClusterTokenIssuance{
		ObjectMeta: metav1.ObjectMeta{
			Name: tokenID,
			Labels: map[string]string{
				kubermaticv1.UserClusterTokenUserIDLabel:    "user-alice",
				kubermaticv1.UserClusterTokenClusterIDLabel: clusterID,
			},
		},
		Spec: kubermaticv1.UserClusterTokenSpec{
			TokenHash:      strings.Repeat("a", 64),
			UserID:         "user-alice",
			ClusterID:      clusterID,
			ClusterUID:     clusterUID,
			SeedName:       seedA,
			IssueTime:      metav1.NewTime(now.Add(-time.Hour)),
			ExpirationTime: metav1.NewTime(now.Add(23 * time.Hour)),
			Label:          "laptop",
		},
	}
	for _, m := range mods {
		m(i)
	}

	return i
}

func genCluster(mods ...func(*kubermaticv1.Cluster)) *kubermaticv1.Cluster {
	c := &kubermaticv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: clusterID, UID: clusterUID, Labels: map[string]string{kubermaticv1.ProjectIDLabelKey: "payments"}},
		Status:     kubermaticv1.ClusterStatus{NamespaceName: clusterNS},
	}
	for _, m := range mods {
		m(c)
	}

	return c
}

func seedCopyOf(i *kubermaticv1.UserClusterTokenIssuance, namespace string) *kubermaticv1.UserClusterToken {
	return &kubermaticv1.UserClusterToken{
		ObjectMeta: metav1.ObjectMeta{Name: i.Name, Namespace: namespace, Labels: i.Labels},
		Spec:       i.Spec,
	}
}

func genRevocation(name string, mods ...func(*kubermaticv1.UserClusterTokenRevocation)) *kubermaticv1.UserClusterTokenRevocation {
	r := &kubermaticv1.UserClusterTokenRevocation{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       kubermaticv1.UserClusterTokenRevocationSpec{IssuedBefore: metav1.NewTime(now)},
	}
	for _, m := range mods {
		m(r)
	}

	return r
}

func newSeedClient(objs ...ctrlruntimeclient.Object) ctrlruntimeclient.Client {
	return ctrlruntimefakeclient.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(objs...).
		WithStatusSubresource(&kubermaticv1.UserClusterToken{}).
		WithIndex(&kubermaticv1.UserClusterToken{}, seedTokenNameIndex, func(o ctrlruntimeclient.Object) []string {
			return []string{o.GetName()}
		}).
		Build()
}

func newMasterClient(objs ...ctrlruntimeclient.Object) ctrlruntimeclient.Client {
	return ctrlruntimefakeclient.NewClientBuilder().WithScheme(newScheme()).WithObjects(objs...).Build()
}

// env is one master and any number of seeds. Each fake client serves as both cache and
// API reader unless a test sets them apart.
type env struct {
	master ctrlruntimeclient.Client
	seeds  map[string]ctrlruntimeclient.Client
	r      *reconciler
}

func newEnv(master ctrlruntimeclient.Client, seeds map[string]ctrlruntimeclient.Client) *env {
	r := &reconciler{
		log:               zap.NewNop().Sugar(),
		masterClient:      master,
		masterAPIReader:   master,
		seeds:             map[string]seedAccess{},
		expiryGracePeriod: DefaultExpiryGracePeriod,
		removalGrace:      MembershipRemovalGracePeriod,
		now:               func() time.Time { return now },
	}
	for name, c := range seeds {
		r.seeds[name] = seedAccess{client: c, apiReader: c}
	}

	return &env{master: master, seeds: seeds, r: r}
}

func (e *env) reconcile(t *testing.T) reconcile.Result {
	t.Helper()

	result, err := e.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: tokenID}})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	return result
}

func (e *env) seedCopy(t *testing.T, seed, namespace string) *kubermaticv1.UserClusterToken {
	t.Helper()

	token := &kubermaticv1.UserClusterToken{}
	err := e.seeds[seed].Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: tokenID}, token)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("failed to get seed copy: %v", err)
	}

	return token
}

func (e *env) issuanceExists(t *testing.T) bool {
	t.Helper()

	err := e.master.Get(context.Background(), types.NamespacedName{Name: tokenID}, &kubermaticv1.UserClusterTokenIssuance{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("failed to get issuance: %v", err)
	}

	return err == nil
}

func TestCreateCopy(t *testing.T) {
	e := newEnv(newMasterClient(genIssuance()), map[string]ctrlruntimeclient.Client{
		seedA: newSeedClient(genCluster()),
		seedB: newSeedClient(),
	})

	result := e.reconcile(t)

	got := e.seedCopy(t, seedA, clusterNS)
	if got == nil {
		t.Fatal("seed copy not created")
	}
	if !immutableSpecEqual(got.Spec, genIssuance().Spec) || got.Spec.Label != "laptop" {
		t.Errorf("seed copy spec differs from issuance: %+v", got.Spec)
	}
	if got.Labels[kubermaticv1.UserClusterTokenUserIDLabel] != "user-alice" {
		t.Errorf("labels not copied: %v", got.Labels)
	}
	if e.seedCopy(t, seedB, clusterNS) != nil {
		t.Error("copy created on the wrong seed")
	}
	if want := MaxIssuanceRequeue; result.RequeueAfter != want {
		t.Errorf("got RequeueAfter %v, want %v (expiry plus grace, capped)", result.RequeueAfter, want)
	}

	// a second run changes nothing
	e.reconcile(t)
	if e.seedCopy(t, seedA, clusterNS) == nil {
		t.Fatal("seed copy disappeared on the second reconcile")
	}
}

func TestLabelUpdateIsCopied(t *testing.T) {
	issuance := genIssuance()
	master := newMasterClient(issuance)
	e := newEnv(master, map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS))})

	issuance.Spec.Label = "ci"
	if err := master.Update(context.Background(), issuance); err != nil {
		t.Fatalf("failed to update issuance: %v", err)
	}

	e.reconcile(t)

	if got := e.seedCopy(t, seedA, clusterNS); got == nil || got.Spec.Label != "ci" {
		t.Fatalf("label not updated on the seed copy: %+v", got)
	}
}

func TestRevokeDeletesCopy(t *testing.T) {
	issuance := genIssuance()
	master := newMasterClient(issuance)
	e := newEnv(master, map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS))})

	if err := master.Delete(context.Background(), issuance); err != nil {
		t.Fatalf("failed to delete issuance: %v", err)
	}

	e.reconcile(t)

	if e.seedCopy(t, seedA, clusterNS) != nil {
		t.Fatal("seed copy still exists after the issuance was deleted")
	}
}

func TestRestoredCopyWithoutIssuanceIsDeleted(t *testing.T) {
	// R-06: a seed backup brings back the copy of a token whose issuance is gone
	restored := seedCopyOf(genIssuance(), clusterNS)
	e := newEnv(newMasterClient(), map[string]ctrlruntimeclient.Client{
		seedA: newSeedClient(genCluster(), restored),
		seedB: newSeedClient(seedCopyOf(genIssuance(), clusterNS)),
	})

	e.reconcile(t)

	if e.seedCopy(t, seedA, clusterNS) != nil || e.seedCopy(t, seedB, clusterNS) != nil {
		t.Fatal("restored seed copies without issuance were not deleted")
	}
}

func TestStaleMasterCacheKeepsCopy(t *testing.T) {
	issuance := genIssuance()
	e := newEnv(newMasterClient(), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS))})
	// the cache has not seen the issuance yet, the API server has
	e.r.masterAPIReader = newMasterClient(issuance)

	result := e.reconcile(t)

	if e.seedCopy(t, seedA, clusterNS) == nil {
		t.Fatal("seed copy of a live issuance deleted because of a stale master cache")
	}
	if result.RequeueAfter != CacheLagRequeue {
		t.Fatalf("got RequeueAfter %v, want %v: without a requeue no event ever retries this token", result.RequeueAfter, CacheLagRequeue)
	}

	// the API server confirms the deletion: the requeued reconcile deletes the copy,
	// without any event
	e.r.masterAPIReader = newMasterClient()
	e.reconcile(t)
	if e.seedCopy(t, seedA, clusterNS) != nil {
		t.Fatal("seed copy not deleted once the master confirms the issuance is gone")
	}
}

func TestSeedUnreachableThenBack(t *testing.T) {
	ctx := context.Background()
	seedClient := newSeedClient(genCluster())
	master := newMasterClient(genIssuance())

	// seed unreachable: nothing happens, no error
	down := newEnv(master, map[string]ctrlruntimeclient.Client{seedB: newSeedClient()})
	down.reconcile(t)

	// seed back: the lifecycle controller builds a new synchronizer with the seed in it
	up := newEnv(master, map[string]ctrlruntimeclient.Client{seedA: seedClient, seedB: newSeedClient()})
	up.reconcile(t)
	if up.seedCopy(t, seedA, clusterNS) == nil {
		t.Fatal("seed copy not created after the seed came back")
	}

	// revoke while the seed is unreachable again
	if err := master.Delete(ctx, genIssuance()); err != nil {
		t.Fatalf("failed to delete issuance: %v", err)
	}
	down.reconcile(t)
	if up.seedCopy(t, seedA, clusterNS) == nil {
		t.Fatal("the unreachable seed must not have been touched")
	}

	// seed back: the copy is found and deleted
	up.reconcile(t)
	if up.seedCopy(t, seedA, clusterNS) != nil {
		t.Fatal("copy revoked while the seed was unreachable still exists after it came back")
	}
}

func TestIssuanceDeletedWithCluster(t *testing.T) {
	deleting := metav1.NewTime(now)

	testcases := []struct {
		name         string
		cacheCluster *kubermaticv1.Cluster
		apiCluster   *kubermaticv1.Cluster
		wantDeleted  bool
	}{
		{name: "cluster exists", cacheCluster: genCluster(), apiCluster: genCluster()},
		{name: "cluster gone", wantDeleted: true},
		{name: "cluster missing in cache only", apiCluster: genCluster()},
		{name: "cluster created again", cacheCluster: genCluster(func(c *kubermaticv1.Cluster) { c.UID = "new" }), wantDeleted: true},
		{
			name: "cluster being deleted",
			cacheCluster: genCluster(func(c *kubermaticv1.Cluster) {
				c.DeletionTimestamp = &deleting
				c.Finalizers = []string{"test"}
			}),
			wantDeleted: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var cacheObjs, apiObjs []ctrlruntimeclient.Object
			if tc.cacheCluster != nil {
				cacheObjs = append(cacheObjs, tc.cacheCluster)
			}
			if tc.apiCluster != nil {
				apiObjs = append(apiObjs, tc.apiCluster)
			} else if tc.cacheCluster != nil {
				apiObjs = append(apiObjs, tc.cacheCluster)
			}

			e := newEnv(newMasterClient(genIssuance()), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(cacheObjs...)})
			e.r.seeds[seedA] = seedAccess{client: e.seeds[seedA], apiReader: newSeedClient(apiObjs...)}

			e.reconcile(t)

			if deleted := !e.issuanceExists(t); deleted != tc.wantDeleted {
				t.Fatalf("issuance deleted = %v, want %v", deleted, tc.wantDeleted)
			}
		})
	}
}

func TestRevocation(t *testing.T) {
	testcases := []struct {
		name        string
		revocation  *kubermaticv1.UserClusterTokenRevocation
		wantDeleted bool
	}{
		{name: "this cluster, issued before", revocation: genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) { r.Spec.ClusterID = clusterID }), wantDeleted: true},
		{name: "this seed, issued before", revocation: genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) { r.Spec.SeedName = seedA }), wantDeleted: true},
		{name: "other cluster", revocation: genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) { r.Spec.ClusterID = "xyz789" })},
		{name: "other seed", revocation: genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) { r.Spec.SeedName = seedB })},
		{
			name: "issued after the revocation time",
			revocation: genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) {
				r.Spec.ClusterID = clusterID
				r.Spec.IssuedBefore = metav1.NewTime(now.Add(-2 * time.Hour))
			}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			issuance := genIssuance()
			e := newEnv(newMasterClient(issuance, tc.revocation), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS))})

			// one reconcile must be enough: the copies are deleted together with the
			// issuance, not by the delete event of the issuance, which may never come
			e.reconcile(t)
			if deleted := !e.issuanceExists(t); deleted != tc.wantDeleted {
				t.Fatalf("issuance deleted = %v, want %v", deleted, tc.wantDeleted)
			}

			if hasCopy := e.seedCopy(t, seedA, clusterNS) != nil; hasCopy == tc.wantDeleted {
				t.Fatalf("seed copy exists = %v after revocation = %v", hasCopy, tc.wantDeleted)
			}

			e.reconcile(t)
			if hasCopy := e.seedCopy(t, seedA, clusterNS) != nil; hasCopy == tc.wantDeleted {
				t.Fatalf("seed copy exists = %v after the second reconcile, revocation = %v", hasCopy, tc.wantDeleted)
			}
		})
	}
}

func TestExpiryGracePeriod(t *testing.T) {
	testcases := []struct {
		name        string
		expiry      time.Time
		wantDeleted bool
	}{
		{name: "not expired", expiry: now.Add(time.Hour)},
		{name: "expired within grace", expiry: now.Add(-time.Hour)},
		{name: "expired beyond grace", expiry: now.Add(-DefaultExpiryGracePeriod - time.Minute), wantDeleted: true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			issuance := genIssuance(func(i *kubermaticv1.UserClusterTokenIssuance) {
				i.Spec.IssueTime = metav1.NewTime(tc.expiry.Add(-24 * time.Hour))
				i.Spec.ExpirationTime = metav1.NewTime(tc.expiry)
			})
			e := newEnv(newMasterClient(issuance), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster())})

			e.reconcile(t)

			if deleted := !e.issuanceExists(t); deleted != tc.wantDeleted {
				t.Fatalf("issuance deleted = %v, want %v", deleted, tc.wantDeleted)
			}
		})
	}
}

func TestMisplacedAndTamperedCopies(t *testing.T) {
	issuance := genIssuance()
	tampered := seedCopyOf(issuance, clusterNS)
	tampered.Spec.TokenHash = strings.Repeat("b", 64)

	testcases := []struct {
		name  string
		seedA []ctrlruntimeclient.Object
		seedB []ctrlruntimeclient.Object
	}{
		{name: "copy on another seed", seedB: []ctrlruntimeclient.Object{seedCopyOf(issuance, clusterNS)}},
		{name: "copy in another namespace", seedA: []ctrlruntimeclient.Object{seedCopyOf(issuance, "cluster-xyz789")}},
		{name: "copy with another hash", seedA: []ctrlruntimeclient.Object{tampered}},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(newMasterClient(issuance), map[string]ctrlruntimeclient.Client{
				seedA: newSeedClient(append(tc.seedA, genCluster())...),
				seedB: newSeedClient(tc.seedB...),
			})

			e.reconcile(t)
			e.reconcile(t)

			got := e.seedCopy(t, seedA, clusterNS)
			if got == nil || got.Spec.TokenHash != issuance.Spec.TokenHash {
				t.Fatalf("expected a correct copy in %s on %s, got %+v", clusterNS, seedA, got)
			}
			if e.seedCopy(t, seedA, "cluster-xyz789") != nil || e.seedCopy(t, seedB, clusterNS) != nil {
				t.Fatal("misplaced copy still exists")
			}
		})
	}
}

func TestMapFunctions(t *testing.T) {
	other := genIssuance(func(i *kubermaticv1.UserClusterTokenIssuance) {
		i.Name = "zzzzyyyyxxxxwwww"
		i.Spec.ClusterID = "xyz789"
		i.Spec.SeedName = seedB
	})
	e := newEnv(newMasterClient(genIssuance(), other), nil)
	ctx := context.Background()

	names := func(reqs []reconcile.Request) []string {
		var out []string
		for _, r := range reqs {
			out = append(out, r.Name)
		}
		slices.Sort(out)
		return out
	}

	testcases := []struct {
		name string
		got  []reconcile.Request
		want []string
	}{
		{name: "cluster", got: e.r.issuancesForCluster(ctx, genCluster()), want: []string{tokenID}},
		{name: "revocation by seed", got: e.r.issuancesForRevocation(ctx, genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) { r.Spec.SeedName = seedB })), want: []string{other.Name}},
		{name: "revocation before issue", got: e.r.issuancesForRevocation(ctx, genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) {
			r.Spec.ClusterID = clusterID
			r.Spec.IssuedBefore = metav1.NewTime(now.Add(-2 * time.Hour))
		}))},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if got := names(tc.got); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func genAttribute(reason kubermaticv1.UserClusterAttributeReason, since time.Time, mods ...func(*kubermaticv1.UserClusterAttribute)) *kubermaticv1.UserClusterAttribute {
	transition := metav1.NewTime(since)
	a := &kubermaticv1.UserClusterAttribute{
		ObjectMeta: metav1.ObjectMeta{Name: "user-alice", Namespace: clusterNS, Generation: 1},
		Spec:       kubermaticv1.UserClusterAttributeSpec{UserID: "user-alice"},
		Status: kubermaticv1.UserClusterAttributeStatus{
			ObservedGeneration: 1,
			State:              kubermaticv1.UserClusterTokenDisabled,
			Reason:             reason,
			LastTransitionTime: &transition,
		},
	}
	if reason == "" {
		a.Status.State = kubermaticv1.UserClusterTokenActive
	}
	for _, m := range mods {
		m(a)
	}

	return a
}

func TestPermanentRemoval(t *testing.T) {
	alice := &kubermaticv1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-alice"},
		Spec:       kubermaticv1.UserSpec{Email: "alice@example.com", Groups: []string{"team-a"}},
	}
	aliceBinding := &kubermaticv1.UserProjectBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "alice-payments"},
		Spec:       kubermaticv1.UserProjectBindingSpec{UserEmail: "alice@example.com", ProjectID: "payments", Group: "editors-payments"},
	}
	groupBinding := &kubermaticv1.GroupProjectBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-payments"},
		Spec:       kubermaticv1.GroupProjectBindingSpec{Group: "team-a", ProjectID: "payments", Role: "viewers"},
	}
	afterGrace := now.Add(-MembershipRemovalGracePeriod - time.Second)
	withinGrace := now.Add(-30 * time.Second)

	testcases := []struct {
		name        string
		attribute   *kubermaticv1.UserClusterAttribute
		masterObjs  []ctrlruntimeclient.Object
		wantDeleted bool
		wantRequeue time.Duration
	}{
		{name: "no attribute yet", masterObjs: []ctrlruntimeclient.Object{alice}},
		{name: "active", attribute: genAttribute("", afterGrace), masterObjs: []ctrlruntimeclient.Object{alice}},
		{
			name:        "not a member, within grace",
			attribute:   genAttribute(kubermaticv1.UserClusterAttributeNotProjectMember, withinGrace),
			masterObjs:  []ctrlruntimeclient.Object{alice},
			wantRequeue: 90*time.Second + time.Second,
		},
		{
			name:        "not a member after grace, master agrees",
			attribute:   genAttribute(kubermaticv1.UserClusterAttributeNotProjectMember, afterGrace),
			masterObjs:  []ctrlruntimeclient.Object{alice},
			wantDeleted: true,
		},
		{
			name:       "not a member after grace, master has a user binding",
			attribute:  genAttribute(kubermaticv1.UserClusterAttributeNotProjectMember, afterGrace),
			masterObjs: []ctrlruntimeclient.Object{alice, aliceBinding},
		},
		{
			name:       "not a member after grace, master has a group binding",
			attribute:  genAttribute(kubermaticv1.UserClusterAttributeNotProjectMember, afterGrace),
			masterObjs: []ctrlruntimeclient.Object{alice, groupBinding},
		},
		{
			name:        "user gone after grace, master agrees",
			attribute:   genAttribute(kubermaticv1.UserClusterAttributeUserNotFound, afterGrace),
			wantDeleted: true,
		},
		{
			name:       "user disabled is never permanent",
			attribute:  genAttribute(kubermaticv1.UserClusterAttributeUserDisabled, afterGrace),
			masterObjs: []ctrlruntimeclient.Object{alice},
		},
		{
			name: "status from an older generation",
			attribute: genAttribute(kubermaticv1.UserClusterAttributeNotProjectMember, afterGrace, func(a *kubermaticv1.UserClusterAttribute) {
				a.Generation = 2
			}),
			masterObjs: []ctrlruntimeclient.Object{alice},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			issuance := genIssuance()
			seedObjs := []ctrlruntimeclient.Object{genCluster(), seedCopyOf(issuance, clusterNS)}
			if tc.attribute != nil {
				seedObjs = append(seedObjs, tc.attribute)
			}
			e := newEnv(newMasterClient(append(tc.masterObjs, issuance)...), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(seedObjs...)})

			result := e.reconcile(t)

			if deleted := !e.issuanceExists(t); deleted != tc.wantDeleted {
				t.Fatalf("issuance deleted = %v, want %v", deleted, tc.wantDeleted)
			}
			if !tc.wantDeleted {
				want := tc.wantRequeue
				if want == 0 {
					want = MaxIssuanceRequeue
				}
				if result.RequeueAfter != want {
					t.Errorf("got RequeueAfter %v, want %v", result.RequeueAfter, want)
				}
			} else {
				// the copies are deleted together with the issuance, so one reconcile
				// is enough even if the delete event is never delivered
				if e.seedCopy(t, seedA, clusterNS) != nil {
					t.Fatal("seed copy still exists after permanent removal")
				}
				e.reconcile(t)
				if e.seedCopy(t, seedA, clusterNS) != nil {
					t.Fatal("seed copy reappeared after permanent removal")
				}
			}
		})
	}
}

func TestRevocationWithIssuanceStillInCache(t *testing.T) {
	// bug 14: the revocation reconcile deleted the issuance, but its delete event was
	// never processed and the cache still returned the issuance; the seed copy of the
	// revoked token survived. The reconcile must delete both together.
	issuance := genIssuance()
	revocation := genRevocation("r", func(r *kubermaticv1.UserClusterTokenRevocation) { r.Spec.ClusterID = clusterID })
	e := newEnv(newMasterClient(issuance, revocation), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS))})

	result := e.reconcile(t)

	if e.issuanceExists(t) {
		t.Fatal("issuance still exists after the revoked reconcile")
	}
	if e.seedCopy(t, seedA, clusterNS) != nil {
		t.Fatal("seed copy still exists after the revoked reconcile")
	}
	if result.RequeueAfter != CacheLagRequeue {
		t.Errorf("got RequeueAfter %v, want %v", result.RequeueAfter, CacheLagRequeue)
	}
}

func TestDeletingIssuanceWithFinalizerCleansCopies(t *testing.T) {
	deleting := metav1.NewTime(now)
	issuance := genIssuance(func(i *kubermaticv1.UserClusterTokenIssuance) {
		i.DeletionTimestamp = &deleting
		i.Finalizers = []string{"test"}
	})
	e := newEnv(newMasterClient(issuance), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS))})

	e.reconcile(t)

	if e.seedCopy(t, seedA, clusterNS) != nil {
		t.Fatal("seed copy still exists while the issuance is being deleted")
	}
}

func TestOrphanSweepRequests(t *testing.T) {
	issuance := genIssuance()
	other := genIssuance(func(i *kubermaticv1.UserClusterTokenIssuance) { i.Name = "1111222233334444" })
	orphan1 := seedCopyOf(genIssuance(), clusterNS)
	orphan1.Name = "aaaa0000bbbb1111"
	orphan2 := seedCopyOf(genIssuance(), clusterNS)
	orphan2.Name = "cccc2222dddd3333"

	e := newEnv(newMasterClient(issuance, other), map[string]ctrlruntimeclient.Client{
		seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS), orphan1),
		seedB: newSeedClient(orphan2),
	})

	var got []string
	for _, req := range e.r.sweepRequests(context.Background()) {
		got = append(got, req.Name)
	}
	slices.Sort(got)

	// both directions: issuances without a copy (other) and copies without an
	// issuance (orphan1, orphan2)
	want := []string{issuance.Name, other.Name, orphan1.Name, orphan2.Name}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("sweep requests %v, want %v", got, want)
	}

	// reconciling the swept requests repairs both: the orphan copies are gone, the
	// copy of the live issuance stays and the copyless issuance gets one
	for _, name := range want {
		_, err := e.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		if err != nil {
			t.Fatalf("reconcile of %s failed: %v", name, err)
		}
	}

	if !orphanStillExists(t, e.seeds[seedA], seedCopyOf(genIssuance(), clusterNS)) {
		t.Fatal("expected the live copy to survive")
	}
	if orphanStillExists(t, e.seeds[seedA], orphan1) {
		t.Fatal("orphan copy 1 still exists")
	}
	if orphanStillExists(t, e.seeds[seedB], orphan2) {
		t.Fatal("orphan copy 2 still exists")
	}
	if !orphanStillExists(t, e.seeds[seedA], seedCopyOf(other, clusterNS)) {
		t.Fatal("sweep did not create the missing copy of a live issuance")
	}
}

func orphanStillExists(t *testing.T, c ctrlruntimeclient.Client, token *kubermaticv1.UserClusterToken) bool {
	t.Helper()

	err := c.Get(context.Background(), types.NamespacedName{Namespace: token.Namespace, Name: token.Name}, &kubermaticv1.UserClusterToken{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("failed to get seed copy: %v", err)
	}

	return err == nil
}

func TestSweepRepairsLostCreateEvent(t *testing.T) {
	// a freshly exported issuance whose create event was dropped: nothing re-enqueues
	// it before expiry. The sweep must pick it up and the reconcile must create the copy.
	issuance := genIssuance()
	e := newEnv(newMasterClient(issuance), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster())})

	requests := e.r.sweepRequests(context.Background())
	if len(requests) != 1 || requests[0].Name != tokenID {
		t.Fatalf("sweep requests %v, want [%s]", requests, tokenID)
	}

	e.reconcile(t)

	if e.seedCopy(t, seedA, clusterNS) == nil {
		t.Fatal("seed copy not created from the sweep request")
	}
}

func TestRequeueCappedAtMaxIssuanceRequeue(t *testing.T) {
	// every path that returns the expiry requeue must cap it, so a lost event is
	// repaired within minutes even without the sweep
	testcases := []struct {
		name  string
		setup func() (*env, func())
	}{
		{name: "fresh issuance", setup: func() (*env, func()) {
			return newEnv(newMasterClient(genIssuance()), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster())}), func() {}
		}},
		{name: "copy already there", setup: func() (*env, func()) {
			issuance := genIssuance()
			return newEnv(newMasterClient(issuance), map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS))}), func() {}
		}},
		{name: "removal grace ends before the cap", setup: func() (*env, func()) {
			attribute := genAttribute(kubermaticv1.UserClusterAttributeNotProjectMember, now.Add(-30*time.Second))
			issuance := genIssuance()
			return newEnv(
				newMasterClient(&kubermaticv1.User{ObjectMeta: metav1.ObjectMeta{Name: "user-alice"}, Spec: kubermaticv1.UserSpec{Email: "alice@example.com"}}, issuance),
				map[string]ctrlruntimeclient.Client{seedA: newSeedClient(genCluster(), seedCopyOf(issuance, clusterNS), attribute)},
			), func() {}
		}},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			e, cleanup := tc.setup()
			defer cleanup()

			result := e.reconcile(t)

			if result.RequeueAfter <= 0 || result.RequeueAfter > MaxIssuanceRequeue {
				t.Fatalf("got RequeueAfter %v, want (0, %v]", result.RequeueAfter, MaxIssuanceRequeue)
			}
		})
	}
}
