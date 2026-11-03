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

// Package userclustertokensynchronizer contains the master controller that makes the seed
// copies (UserClusterToken) follow the authoritative records on the master
// (UserClusterTokenIssuance).
//
// For each token ID it makes sure that exactly one seed copy exists, in the namespace of
// the token's cluster on the token's seed, while the issuance exists, and that no copy
// exists anywhere once the issuance is gone. Deleting an issuance therefore revokes the
// token, and a seed copy brought back by a seed backup restore is deleted again.
//
// It also deletes issuances that are covered by a UserClusterTokenRevocation, whose cluster
// is gone or was created again, that expired longer than the grace period ago, or whose
// owner lost access to the cluster (removal is permanent; a user added again needs a new
// export).
//
// There is no finalizer: a seed copy without an issuance is deleted whenever the controller
// sees it, including after a seed was unreachable during the deletion.
package userclustertokensynchronizer

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/controller/util/projectmember"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	ControllerName = "kkp-user-cluster-token-synchronizer"

	// DefaultExpiryGracePeriod is how long an expired issuance is kept before it is deleted,
	// so admins can still look it up shortly after expiry.
	DefaultExpiryGracePeriod = 24 * time.Hour

	// MembershipRemovalGracePeriod is how long a seed must report a user as no longer
	// allowed on a cluster before the synchronizer checks the master and deletes the user's
	// tokens for that cluster for good. It covers the delay of binding sync from the master
	// to the seed, so a user added to a project and exporting at once is not hit.
	MembershipRemovalGracePeriod = 2 * time.Minute

	// CacheLagRequeue is how long a reconcile waits before it looks again, when the cached
	// and the uncached view of the master disagree about an issuance. No watch event comes
	// for a deletion the cache has already processed, so waiting for one deadlocks.
	CacheLagRequeue = 10 * time.Second

	// MaxIssuanceRequeue caps how long any issuance reconcile may sleep. Without it, one
	// lost watch event leaves a token unsynced until its expiry requeue, a day or more.
	MaxIssuanceRequeue = 5 * time.Minute

	// OrphanSweepInterval is how often every token ID found anywhere (issuance on the
	// master, copy on a seed) is reconciled again, whether or not an event was seen.
	OrphanSweepInterval = 5 * time.Minute

	// seedTokenNameIndex indexes seed UserClusterTokens by name, to find all copies of one
	// token ID across namespaces without listing every token of the seed.
	seedTokenNameIndex = "metadata.name"
)

// seedAccess holds the clients for one seed.
type seedAccess struct {
	// client reads from the seed manager cache.
	client ctrlruntimeclient.Client
	// apiReader reads from the seed API server, for decisions that delete something.
	apiReader ctrlruntimeclient.Reader
}

type reconciler struct {
	log               *zap.SugaredLogger
	masterClient      ctrlruntimeclient.Client
	masterAPIReader   ctrlruntimeclient.Reader
	seeds             map[string]seedAccess
	expiryGracePeriod time.Duration
	removalGrace      time.Duration
	now               func() time.Time
}

// Add creates the synchronizer. It is called again with new seed managers whenever the set
// of reachable seeds changes; each new seed manager starts with a full list of its seed
// copies, so copies left over while a seed was unreachable are handled then.
func Add(
	ctx context.Context,
	masterManager manager.Manager,
	seedManagers map[string]manager.Manager,
	log *zap.SugaredLogger,
	numWorkers int,
) error {
	r := &reconciler{
		log:               log.Named(ControllerName),
		masterClient:      masterManager.GetClient(),
		masterAPIReader:   masterManager.GetAPIReader(),
		seeds:             map[string]seedAccess{},
		expiryGracePeriod: DefaultExpiryGracePeriod,
		removalGrace:      MembershipRemovalGracePeriod,
		now:               time.Now,
	}

	// the periodic sweep feeds every token ID it finds into the normal reconcile path,
	// so a watch event lost anywhere (create or delete) is repaired within minutes
	sweepEvents := make(chan event.TypedGenericEvent[*kubermaticv1.UserClusterToken], 1024)

	bldr := builder.ControllerManagedBy(masterManager).
		Named(ControllerName).
		WithOptions(controller.Options{MaxConcurrentReconciles: numWorkers}).
		For(&kubermaticv1.UserClusterTokenIssuance{}).
		Watches(&kubermaticv1.UserClusterTokenRevocation{}, handler.EnqueueRequestsFromMapFunc(r.issuancesForRevocation)).
		WatchesRawSource(source.Channel(
			sweepEvents,
			handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, t *kubermaticv1.UserClusterToken) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: t.Name}}}
			}),
		))

	for seedName, seedManager := range seedManagers {
		if err := seedManager.GetFieldIndexer().IndexField(ctx, &kubermaticv1.UserClusterToken{}, seedTokenNameIndex, func(o ctrlruntimeclient.Object) []string {
			return []string{o.GetName()}
		}); err != nil {
			return fmt.Errorf("failed to add name index for UserClusterTokens on seed %q: %w", seedName, err)
		}

		r.seeds[seedName] = seedAccess{
			client:    seedManager.GetClient(),
			apiReader: seedManager.GetAPIReader(),
		}

		bldr.WatchesRawSource(source.Kind(
			seedManager.GetCache(),
			&kubermaticv1.UserClusterToken{},
			handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, t *kubermaticv1.UserClusterToken) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: t.Name}}}
			}),
			// status writes (state, lastUsedTime) do not concern the synchronizer
			predicate.TypedGenerationChangedPredicate[*kubermaticv1.UserClusterToken]{},
		))

		bldr.WatchesRawSource(source.Kind(
			seedManager.GetCache(),
			&kubermaticv1.UserClusterAttribute{},
			handler.TypedEnqueueRequestsFromMapFunc(r.issuancesForAttribute),
		))

		bldr.WatchesRawSource(source.Kind(
			seedManager.GetCache(),
			&kubermaticv1.Cluster{},
			handler.TypedEnqueueRequestsFromMapFunc(r.issuancesForCluster),
			clusterGonePredicate(),
		))
	}

	if _, err := bldr.Build(r); err != nil {
		return err
	}

	go r.runOrphanSweep(ctx, sweepEvents)

	return nil
}

// runOrphanSweep periodically enqueues every token ID that exists anywhere: every
// issuance on the master and every copy on every reachable seed. Reconciling such a
// request repairs both directions of a lost event: a missing copy is created, an orphan
// copy without an issuance is deleted.
func (r *reconciler) runOrphanSweep(ctx context.Context, events chan<- event.TypedGenericEvent[*kubermaticv1.UserClusterToken]) {
	ticker := time.NewTicker(OrphanSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		for _, req := range r.sweepRequests(ctx) {
			ev := event.TypedGenericEvent[*kubermaticv1.UserClusterToken]{
				Object: &kubermaticv1.UserClusterToken{ObjectMeta: metav1.ObjectMeta{Name: req.Name}},
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// sweepRequests lists all issuances from the master cache and all seed copies and turns
// their names into reconcile requests. Failures are logged, not returned: the sweep runs
// again soon, and a partial sweep still repairs what it saw.
func (r *reconciler) sweepRequests(ctx context.Context) []reconcile.Request {
	requests := map[string]reconcile.Request{}

	issuances := &kubermaticv1.UserClusterTokenIssuanceList{}
	if err := r.masterClient.List(ctx, issuances); err != nil {
		r.log.Errorw("Orphan sweep failed to list issuances", zap.Error(err))
	}
	for i := range issuances.Items {
		requests[issuances.Items[i].Name] = reconcile.Request{NamespacedName: types.NamespacedName{Name: issuances.Items[i].Name}}
	}

	for seedName, seed := range r.seeds {
		tokens := &kubermaticv1.UserClusterTokenList{}
		if err := seed.client.List(ctx, tokens); err != nil {
			r.log.Errorw("Orphan sweep failed to list seed copies", "seed", seedName, zap.Error(err))
			continue
		}
		for i := range tokens.Items {
			requests[tokens.Items[i].Name] = reconcile.Request{NamespacedName: types.NamespacedName{Name: tokens.Items[i].Name}}
		}
	}

	return slices.Collect(maps.Values(requests))
}

func (r *reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := r.log.With("token", request.Name)

	issuance := &kubermaticv1.UserClusterTokenIssuance{}
	if err := r.masterClient.Get(ctx, request.NamespacedName, issuance); err != nil {
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, fmt.Errorf("failed to get issuance: %w", err)
		}

		return r.handleMissingIssuance(ctx, log, request.Name)
	}

	if issuance.DeletionTimestamp != nil {
		// the issuance is going away; clean up the copies now instead of waiting for
		// the delete event, which a busy queue may never deliver
		copies, err := r.findSeedCopies(ctx, issuance.Name)
		if err != nil {
			return reconcile.Result{}, err
		}
		log.Debugw("Issuance is being deleted", "seedCopies", len(copies))
		if err := r.deleteCopies(ctx, log, copies, "issuance is being deleted"); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{RequeueAfter: CacheLagRequeue}, nil
	}

	if reason, revoked, err := r.shouldDeleteIssuance(ctx, issuance); err != nil {
		return reconcile.Result{}, err
	} else if revoked {
		return r.deleteIssuance(ctx, log, issuance, reason)
	}

	return r.syncSeedCopy(ctx, log, issuance)
}

// handleMissingIssuance deletes all seed copies of a token ID once the master API server
// confirms that the issuance does not exist. The cached read alone is not enough, because
// deleting a copy of a live token would lock its owner out. When the uncached read still
// sees the issuance, it requeues instead of returning for good: no event announces that
// the cache caught up, so without a requeue the copies would stay forever.
func (r *reconciler) handleMissingIssuance(ctx context.Context, log *zap.SugaredLogger, tokenID string) (reconcile.Result, error) {
	copies, err := r.findSeedCopies(ctx, tokenID)
	if err != nil {
		return reconcile.Result{}, err
	}
	if len(copies) == 0 {
		log.Debugw("No issuance and no seed copy; nothing to do")
		return reconcile.Result{}, nil
	}

	issuance := &kubermaticv1.UserClusterTokenIssuance{}
	err = r.masterAPIReader.Get(ctx, types.NamespacedName{Name: tokenID}, issuance)
	if err == nil {
		// the cache is behind; no event will come for a deletion the cache has already
		// processed, so look again in a few seconds
		log.Debugw("Cache does not have the issuance, but the master does; requeueing", "seedCopies", len(copies))
		return reconcile.Result{RequeueAfter: CacheLagRequeue}, nil
	}
	if !apierrors.IsNotFound(err) {
		return reconcile.Result{}, fmt.Errorf("failed to confirm that the issuance does not exist: %w", err)
	}

	var errs []error
	for _, c := range copies {
		log.Infow("Deleting seed copy without issuance", "seed", c.seed, "namespace", c.token.Namespace)
		if err := r.seeds[c.seed].client.Delete(ctx, c.token); ctrlruntimeclient.IgnoreNotFound(err) != nil {
			errs = append(errs, fmt.Errorf("failed to delete seed copy on seed %q: %w", c.seed, err))
		}
	}

	// requeue once more: a copy the seed cache had not delivered yet was invisible above
	return reconcile.Result{RequeueAfter: CacheLagRequeue}, kerrors.NewAggregate(errs)
}

// shouldDeleteIssuance reports whether the issuance must be deleted, and why.
func (r *reconciler) shouldDeleteIssuance(ctx context.Context, issuance *kubermaticv1.UserClusterTokenIssuance) (string, bool, error) {
	if r.now().After(issuance.Spec.ExpirationTime.Add(r.expiryGracePeriod)) {
		return "expired", true, nil
	}

	revocations := &kubermaticv1.UserClusterTokenRevocationList{}
	if err := r.masterClient.List(ctx, revocations); err != nil {
		return "", false, fmt.Errorf("failed to list revocations: %w", err)
	}

	for _, rev := range revocations.Items {
		if revokes(&rev, issuance) {
			return fmt.Sprintf("revoked by UserClusterTokenRevocation %s", rev.Name), true, nil
		}
	}

	return "", false, nil
}

func revokes(rev *kubermaticv1.UserClusterTokenRevocation, issuance *kubermaticv1.UserClusterTokenIssuance) bool {
	if !issuance.Spec.IssueTime.Before(&rev.Spec.IssuedBefore) {
		return false
	}

	switch {
	case rev.Spec.ClusterID != "":
		return rev.Spec.ClusterID == issuance.Spec.ClusterID
	case rev.Spec.SeedName != "":
		return rev.Spec.SeedName == issuance.Spec.SeedName
	default:
		// the CRD requires one of both; an empty revocation revokes nothing
		return false
	}
}

func (r *reconciler) syncSeedCopy(ctx context.Context, log *zap.SugaredLogger, issuance *kubermaticv1.UserClusterTokenIssuance) (reconcile.Result, error) {
	requeue := reconcile.Result{RequeueAfter: issuance.Spec.ExpirationTime.Add(r.expiryGracePeriod).Sub(r.now()) + time.Second}

	copies, err := r.findSeedCopies(ctx, issuance.Name)
	if err != nil {
		return reconcile.Result{}, err
	}

	seed, ok := r.seeds[issuance.Spec.SeedName]
	if !ok {
		// seed unknown or unreachable; the seed lifecycle controller restarts this
		// controller when the seed comes back, which reconciles every issuance again.
		// Copies found now are on other seeds and therefore misplaced.
		log.Debugw("Seed of the token is not available", "seed", issuance.Spec.SeedName)
		return reconcile.Result{}, r.deleteCopies(ctx, log, copies, "seed of the token is not available")
	}

	cluster, err := r.getCluster(ctx, seed, issuance.Spec.ClusterID)
	if err != nil {
		return reconcile.Result{}, err
	}

	switch {
	case cluster == nil:
		return r.deleteIssuance(ctx, log, issuance, "cluster does not exist")
	case string(cluster.UID) != issuance.Spec.ClusterUID:
		return r.deleteIssuance(ctx, log, issuance, "cluster was created again")
	case cluster.DeletionTimestamp != nil:
		return r.deleteIssuance(ctx, log, issuance, "cluster is being deleted")
	case cluster.Status.NamespaceName == "":
		return reconcile.Result{}, fmt.Errorf("cluster %s has no namespace yet", cluster.Name)
	}

	removed, recheckAfter, err := r.checkRemoval(ctx, log, seed, issuance, cluster)
	if err != nil {
		return reconcile.Result{}, err
	}
	if removed {
		return reconcile.Result{RequeueAfter: CacheLagRequeue}, nil
	}
	if recheckAfter > 0 && recheckAfter < requeue.RequeueAfter {
		requeue.RequeueAfter = recheckAfter
	}
	if requeue.RequeueAfter > MaxIssuanceRequeue {
		// a lost create event must not leave the issuance unsynced until its expiry
		log.Debugw("Capping requeue", "after", requeue.RequeueAfter)
		requeue.RequeueAfter = MaxIssuanceRequeue
	}

	want := seedLocation{seed: issuance.Spec.SeedName, namespace: cluster.Status.NamespaceName}

	var current *kubermaticv1.UserClusterToken
	var unwanted []seedCopy
	for _, c := range copies {
		switch {
		case c.location() != want:
			unwanted = append(unwanted, c)
		case !immutableSpecEqual(c.token.Spec, issuance.Spec):
			// a copy with other immutable fields cannot be fixed in place
			unwanted = append(unwanted, c)
		default:
			current = c.token
		}
	}

	if err := r.deleteCopies(ctx, log, unwanted, "misplaced or differing from the issuance"); err != nil {
		return reconcile.Result{}, err
	}

	if current == nil {
		if len(unwanted) > 0 {
			// recreate after the deletion was observed, so a recreated copy with the same
			// name and namespace is not rejected as already existing
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}

		token := &kubermaticv1.UserClusterToken{}
		token.Name = issuance.Name
		token.Namespace = want.namespace
		token.Labels = maps.Clone(issuance.Labels)
		token.Spec = issuance.Spec

		log.Infow("Creating seed copy", "seed", want.seed, "namespace", want.namespace)
		if err := seed.client.Create(ctx, token); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return reconcile.Result{RequeueAfter: time.Second}, nil
			}
			return reconcile.Result{}, fmt.Errorf("failed to create seed copy: %w", err)
		}

		return requeue, nil
	}

	if current.Spec.Label != issuance.Spec.Label || !maps.Equal(current.Labels, issuance.Labels) {
		oldToken := current.DeepCopy()
		current.Spec.Label = issuance.Spec.Label
		current.Labels = maps.Clone(issuance.Labels)
		if err := seed.client.Patch(ctx, current, ctrlruntimeclient.MergeFrom(oldToken)); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update seed copy: %w", err)
		}
	} else {
		log.Debugw("Seed copy is up to date", "seed", want.seed, "namespace", want.namespace)
	}

	return requeue, nil
}

// checkRemoval deletes the issuance for good when the seed has reported for longer than
// the grace period that the owner may no longer use the cluster (not a project member,
// user gone, service account) and the master's own objects, read without cache, agree.
// Within the grace period it returns when to look again. A seed that is behind the master
// (binding not synced yet) therefore never removes a token on its own.
func (r *reconciler) checkRemoval(ctx context.Context, log *zap.SugaredLogger, seed seedAccess, issuance *kubermaticv1.UserClusterTokenIssuance, cluster *kubermaticv1.Cluster) (bool, time.Duration, error) {
	attribute := &kubermaticv1.UserClusterAttribute{}
	if err := seed.client.Get(ctx, types.NamespacedName{Namespace: cluster.Status.NamespaceName, Name: issuance.Spec.UserID}, attribute); err != nil {
		if apierrors.IsNotFound(err) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("failed to get user attribute: %w", err)
	}

	st := attribute.Status
	if st.State != kubermaticv1.UserClusterTokenDisabled || st.ObservedGeneration != attribute.Generation || st.LastTransitionTime == nil {
		return false, 0, nil
	}

	switch st.Reason {
	case kubermaticv1.UserClusterAttributeNotProjectMember, kubermaticv1.UserClusterAttributeUserNotFound, kubermaticv1.UserClusterAttributeServiceAccountUser:
	default:
		// UserDisabled is reversible by design (phase 2 identity provider refresh)
		return false, 0, nil
	}

	if wait := st.LastTransitionTime.Add(r.removalGrace).Sub(r.now()); wait > 0 {
		return false, wait + time.Second, nil
	}

	result, err := projectmember.Evaluate(ctx, r.masterAPIReader, issuance.Spec.UserID, cluster.Labels[kubermaticv1.ProjectIDLabelKey])
	if err != nil {
		return false, 0, fmt.Errorf("failed to check membership on the master: %w", err)
	}

	if result.Reason == "" {
		log.Infow("Seed reports the user as not allowed, but the master disagrees; keeping the token", "user", issuance.Spec.UserID, "seedReason", st.Reason)
		return false, 0, nil
	}

	if _, err := r.deleteIssuance(ctx, log, issuance, fmt.Sprintf("user no longer allowed on the cluster (%s)", result.Reason)); err != nil {
		return false, 0, err
	}

	return true, 0, nil
}

// getCluster returns the cluster or nil when it does not exist. NotFound from the cache is
// confirmed with the seed API server, because the caller deletes the issuance on nil.
func (r *reconciler) getCluster(ctx context.Context, seed seedAccess, name string) (*kubermaticv1.Cluster, error) {
	cluster := &kubermaticv1.Cluster{}
	err := seed.client.Get(ctx, types.NamespacedName{Name: name}, cluster)
	if err == nil {
		return cluster, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get cluster: %w", err)
	}

	err = seed.apiReader.Get(ctx, types.NamespacedName{Name: name}, cluster)
	switch {
	case err == nil:
		return cluster, nil
	case apierrors.IsNotFound(err):
		return nil, nil
	default:
		return nil, fmt.Errorf("failed to confirm that the cluster does not exist: %w", err)
	}
}

// deleteIssuance deletes the issuance and, in the same reconcile, every seed copy of it.
// Leaving the copies to the issuance's delete event loses them whenever that event is
// dropped (observed after a bulk revocation): the revoked kubeconfig kept working. The
// copies go first, so a failure of the master delete cannot keep a revoked token alive.
func (r *reconciler) deleteIssuance(ctx context.Context, log *zap.SugaredLogger, issuance *kubermaticv1.UserClusterTokenIssuance, reason string) (reconcile.Result, error) {
	log.Infow("Deleting token issuance", "user", issuance.Spec.UserID, "cluster", issuance.Spec.ClusterID, "reason", reason)

	copies, err := r.findSeedCopies(ctx, issuance.Name)
	if err != nil {
		return reconcile.Result{}, err
	}
	if err := r.deleteCopies(ctx, log, copies, "issuance deleted: "+reason); err != nil {
		return reconcile.Result{}, err
	}

	if err := r.masterClient.Delete(ctx, issuance); ctrlruntimeclient.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete issuance: %w", err)
	}

	log.Debugw("Deleted issuance and its seed copies", "seedCopies", len(copies))

	// requeue to confirm both are really gone, in case an event was lost or a seed
	// cache served a copy this reconcile did not see
	return reconcile.Result{RequeueAfter: CacheLagRequeue}, nil
}

type seedLocation struct {
	seed      string
	namespace string
}

type seedCopy struct {
	seed  string
	token *kubermaticv1.UserClusterToken
}

func (c seedCopy) location() seedLocation {
	return seedLocation{seed: c.seed, namespace: c.token.Namespace}
}

// findSeedCopies returns every seed copy of the token ID on every reachable seed.
func (r *reconciler) findSeedCopies(ctx context.Context, tokenID string) ([]seedCopy, error) {
	var copies []seedCopy
	var errs []error

	for seedName, seed := range r.seeds {
		tokens := &kubermaticv1.UserClusterTokenList{}
		if err := seed.client.List(ctx, tokens, ctrlruntimeclient.MatchingFields{seedTokenNameIndex: tokenID}); err != nil {
			errs = append(errs, fmt.Errorf("failed to list seed copies on seed %q: %w", seedName, err))
			continue
		}

		for i := range tokens.Items {
			copies = append(copies, seedCopy{seed: seedName, token: &tokens.Items[i]})
		}
	}

	return copies, kerrors.NewAggregate(errs)
}

func (r *reconciler) deleteCopies(ctx context.Context, log *zap.SugaredLogger, copies []seedCopy, reason string) error {
	var errs []error
	for _, c := range copies {
		log.Infow("Deleting seed copy", "seed", c.seed, "namespace", c.token.Namespace, "reason", reason)
		if err := r.seeds[c.seed].client.Delete(ctx, c.token); ctrlruntimeclient.IgnoreNotFound(err) != nil {
			errs = append(errs, fmt.Errorf("failed to delete seed copy on seed %q: %w", c.seed, err))
		}
	}

	return kerrors.NewAggregate(errs)
}

func (r *reconciler) issuancesForRevocation(ctx context.Context, o ctrlruntimeclient.Object) []reconcile.Request {
	rev := o.(*kubermaticv1.UserClusterTokenRevocation)

	return r.issuancesMatching(ctx, func(i *kubermaticv1.UserClusterTokenIssuance) bool {
		return revokes(rev, i)
	})
}

func (r *reconciler) issuancesForAttribute(ctx context.Context, attribute *kubermaticv1.UserClusterAttribute) []reconcile.Request {
	return r.issuancesMatching(ctx, func(i *kubermaticv1.UserClusterTokenIssuance) bool {
		return i.Spec.UserID == attribute.Spec.UserID
	})
}

func (r *reconciler) issuancesForCluster(ctx context.Context, cluster *kubermaticv1.Cluster) []reconcile.Request {
	return r.issuancesMatching(ctx, func(i *kubermaticv1.UserClusterTokenIssuance) bool {
		return i.Spec.ClusterID == cluster.Name
	})
}

// issuancesMatching lists all issuances from the cache. It runs only on revocation events
// and cluster deletions, both rare.
func (r *reconciler) issuancesMatching(ctx context.Context, match func(*kubermaticv1.UserClusterTokenIssuance) bool) []reconcile.Request {
	issuances := &kubermaticv1.UserClusterTokenIssuanceList{}
	if err := r.masterClient.List(ctx, issuances); err != nil {
		r.log.Errorw("Failed to list issuances", zap.Error(err))
		return nil
	}

	var requests []reconcile.Request
	for i := range issuances.Items {
		if match(&issuances.Items[i]) {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: issuances.Items[i].Name}})
		}
	}

	return requests
}

// clusterGonePredicate admits Cluster deletions and the start of a deletion.
func clusterGonePredicate() predicate.TypedFuncs[*kubermaticv1.Cluster] {
	return predicate.TypedFuncs[*kubermaticv1.Cluster]{
		CreateFunc:  func(event.TypedCreateEvent[*kubermaticv1.Cluster]) bool { return false },
		GenericFunc: func(event.TypedGenericEvent[*kubermaticv1.Cluster]) bool { return false },
		DeleteFunc:  func(event.TypedDeleteEvent[*kubermaticv1.Cluster]) bool { return true },
		UpdateFunc: func(e event.TypedUpdateEvent[*kubermaticv1.Cluster]) bool {
			return e.ObjectOld.DeletionTimestamp == nil && e.ObjectNew.DeletionTimestamp != nil
		},
	}
}

// immutableSpecEqual compares every spec field except the mutable label. Times are
// compared as instants, since the two objects come from different API servers.
func immutableSpecEqual(a, b kubermaticv1.UserClusterTokenSpec) bool {
	return a.TokenHash == b.TokenHash &&
		a.UserID == b.UserID &&
		a.ClusterID == b.ClusterID &&
		a.ClusterUID == b.ClusterUID &&
		a.SeedName == b.SeedName &&
		a.IssueTime.Equal(&b.IssueTime) &&
		a.ExpirationTime.Equal(&b.ExpirationTime) &&
		a.IssuanceRequestID == b.IssuanceRequestID
}
