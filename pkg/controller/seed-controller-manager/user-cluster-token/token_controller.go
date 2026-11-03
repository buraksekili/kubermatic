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
	"fmt"
	"time"

	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// TokenReconciler writes the per-token part of a UserClusterToken's status.
type TokenReconciler struct {
	ctrlruntimeclient.Client

	log        *zap.SugaredLogger
	workerName string
	now        func() time.Time
}

func addTokenController(mgr manager.Manager, log *zap.SugaredLogger, numWorkers int, workerName string) error {
	r := &TokenReconciler{
		Client:     mgr.GetClient(),
		log:        log.Named(TokenControllerName),
		workerName: workerName,
		now:        time.Now,
	}

	_, err := builder.ControllerManagedBy(mgr).
		Named(TokenControllerName).
		WithOptions(controller.Options{MaxConcurrentReconciles: numWorkers}).
		// status writes (ours and the webhook's lastUsedTime) do not bump the generation
		For(&kubermaticv1.UserClusterToken{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&kubermaticv1.Cluster{}, handler.EnqueueRequestsFromMapFunc(r.tokensForCluster), builder.WithPredicates(clusterChangedPredicate())).
		Build(r)

	return err
}

func (r *TokenReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	token := &kubermaticv1.UserClusterToken{}
	if err := r.Get(ctx, request.NamespacedName, token); err != nil {
		return reconcile.Result{}, ctrlruntimeclient.IgnoreNotFound(err)
	}

	if token.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}

	cluster := &kubermaticv1.Cluster{}
	if err := r.Get(ctx, types.NamespacedName{Name: token.Spec.ClusterID}, cluster); err != nil {
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, fmt.Errorf("failed to get cluster: %w", err)
		}
		cluster = nil
	}

	// a seed-controller-manager with a worker name only handles clusters with that worker name
	if clusterWorkerName(cluster) != r.workerName {
		return reconcile.Result{}, nil
	}

	state, reason := r.evaluate(token, cluster)

	if err := r.patchStatus(ctx, request, token, state, reason); err != nil {
		return reconcile.Result{}, err
	}

	// expiry is the one transition that no watch event announces
	if state == kubermaticv1.UserClusterTokenActive {
		return reconcile.Result{RequeueAfter: requeueAt(r.now, token.Spec.ExpirationTime.Time)}, nil
	}

	return reconcile.Result{}, nil
}

func (r *TokenReconciler) evaluate(token *kubermaticv1.UserClusterToken, cluster *kubermaticv1.Cluster) (kubermaticv1.UserClusterTokenState, kubermaticv1.UserClusterTokenReason) {
	switch {
	case !r.now().Before(token.Spec.ExpirationTime.Time):
		return kubermaticv1.UserClusterTokenDisabled, kubermaticv1.UserClusterTokenExpired
	case cluster == nil:
		return kubermaticv1.UserClusterTokenDisabled, kubermaticv1.UserClusterTokenClusterNotFound
	case string(cluster.UID) != token.Spec.ClusterUID:
		return kubermaticv1.UserClusterTokenDisabled, kubermaticv1.UserClusterTokenClusterUIDMismatch
	case cluster.DeletionTimestamp != nil:
		return kubermaticv1.UserClusterTokenDisabled, kubermaticv1.UserClusterTokenClusterDeleting
	default:
		return kubermaticv1.UserClusterTokenActive, ""
	}
}

// patchStatus writes the controller-owned status fields with a merge patch, so the
// webhook's lastUsedTime is never overwritten.
func (r *TokenReconciler) patchStatus(ctx context.Context, request reconcile.Request, token *kubermaticv1.UserClusterToken, state kubermaticv1.UserClusterTokenState, reason kubermaticv1.UserClusterTokenReason) error {
	current := token.Status
	if current.ObservedGeneration == token.Generation && current.State == state && current.Reason == reason {
		return nil
	}

	oldToken := token.DeepCopy()
	now := metav1.NewTime(r.now())

	token.Status.ObservedGeneration = token.Generation
	token.Status.State = state
	token.Status.Reason = reason
	token.Status.LastEvaluationTime = &now

	if err := r.Status().Patch(ctx, token, ctrlruntimeclient.MergeFrom(oldToken)); err != nil {
		return fmt.Errorf("failed to patch status: %w", err)
	}

	if current.State != state || current.Reason != reason {
		r.log.Infow("Token state changed", "token", request.NamespacedName, "user", token.Spec.UserID, "state", state, "reason", reason)
	}

	return nil
}

func (r *TokenReconciler) tokensForCluster(ctx context.Context, o ctrlruntimeclient.Object) []reconcile.Request {
	cluster := o.(*kubermaticv1.Cluster)

	tokens, err := tokensInNamespaceOf(ctx, r, cluster)
	if err != nil {
		r.log.Errorw("Failed to list tokens of cluster", "cluster", cluster.Name, zap.Error(err))
		return nil
	}

	requests := make([]reconcile.Request, 0, len(tokens))
	for i := range tokens {
		requests = append(requests, tokenRequest(&tokens[i]))
	}

	return requests
}
