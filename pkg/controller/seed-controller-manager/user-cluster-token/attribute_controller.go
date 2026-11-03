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
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/controller/util/projectmember"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// AttributeReconciler keeps one UserClusterAttribute per user and cluster namespace while
// the user has tokens there. The reconcile key is <cluster namespace>/<user ID>.
type AttributeReconciler struct {
	ctrlruntimeclient.Client

	log        *zap.SugaredLogger
	workerName string
	now        func() time.Time
}

func addAttributeController(mgr manager.Manager, log *zap.SugaredLogger, numWorkers int, workerName string) error {
	r := &AttributeReconciler{
		Client:     mgr.GetClient(),
		log:        log.Named(AttributeControllerName),
		workerName: workerName,
		now:        time.Now,
	}

	_, err := builder.ControllerManagedBy(mgr).
		Named(AttributeControllerName).
		WithOptions(controller.Options{MaxConcurrentReconciles: numWorkers}).
		For(&kubermaticv1.UserClusterAttribute{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// token create and delete decide whether the attribute must exist
		Watches(&kubermaticv1.UserClusterToken{}, handler.EnqueueRequestsFromMapFunc(r.attributeForToken), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&kubermaticv1.Cluster{}, handler.EnqueueRequestsFromMapFunc(r.attributesForCluster), builder.WithPredicates(clusterChangedPredicate())).
		Watches(&kubermaticv1.User{}, handler.EnqueueRequestsFromMapFunc(r.attributesForUser), builder.WithPredicates(specOrDeletionChangedPredicate())).
		Watches(&kubermaticv1.UserProjectBinding{}, handler.EnqueueRequestsFromMapFunc(r.attributesForUserProjectBinding)).
		Watches(&kubermaticv1.GroupProjectBinding{}, handler.EnqueueRequestsFromMapFunc(r.attributesForGroupProjectBinding)).
		Build(r)

	return err
}

func (r *AttributeReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := r.log.With("namespace", request.Namespace, "user", request.Name)
	userID := request.Name

	tokens := &kubermaticv1.UserClusterTokenList{}
	if err := r.List(ctx, tokens, ctrlruntimeclient.InNamespace(request.Namespace), ctrlruntimeclient.MatchingFields{tokenUserIDIndex: userID}); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list tokens: %w", err)
	}

	attribute := &kubermaticv1.UserClusterAttribute{}
	if err := r.Get(ctx, request.NamespacedName, attribute); err != nil {
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, fmt.Errorf("failed to get attribute: %w", err)
		}
		attribute = nil
	}

	if len(tokens.Items) == 0 {
		if attribute != nil && attribute.DeletionTimestamp == nil {
			log.Debug("Deleting attribute, the user has no tokens left")
			if err := r.Delete(ctx, attribute); ctrlruntimeclient.IgnoreNotFound(err) != nil {
				return reconcile.Result{}, fmt.Errorf("failed to delete attribute: %w", err)
			}
		}
		return reconcile.Result{}, nil
	}

	// all tokens in one cluster namespace belong to the same cluster
	cluster := &kubermaticv1.Cluster{}
	if err := r.Get(ctx, types.NamespacedName{Name: tokens.Items[0].Spec.ClusterID}, cluster); err != nil {
		if apierrors.IsNotFound(err) {
			// the token controller disables the tokens and the master removes them
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to get cluster: %w", err)
	}

	if clusterWorkerName(cluster) != r.workerName {
		return reconcile.Result{}, nil
	}

	if attribute == nil {
		attribute = &kubermaticv1.UserClusterAttribute{
			ObjectMeta: metav1.ObjectMeta{Name: userID, Namespace: request.Namespace},
			Spec:       kubermaticv1.UserClusterAttributeSpec{UserID: userID},
		}
		if err := r.Create(ctx, attribute); err != nil {
			if apierrors.IsAlreadyExists(err) {
				// the cache is behind; the create event reconciles again
				return reconcile.Result{}, nil
			}
			return reconcile.Result{}, fmt.Errorf("failed to create attribute: %w", err)
		}
	}

	if attribute.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}

	result, err := projectmember.Evaluate(ctx, r, userID, cluster.Labels[kubermaticv1.ProjectIDLabelKey])
	if err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, r.patchStatus(ctx, log, attribute, result)
}

func (r *AttributeReconciler) patchStatus(ctx context.Context, log *zap.SugaredLogger, attribute *kubermaticv1.UserClusterAttribute, result projectmember.Result) error {
	desired := kubermaticv1.UserClusterAttributeStatus{
		State:  kubermaticv1.UserClusterTokenActive,
		Reason: result.Reason,
	}
	if result.Reason != "" {
		desired.State = kubermaticv1.UserClusterTokenDisabled
	}
	if result.User != nil {
		desired.Username = strings.ToLower(result.User.Spec.Email)
		if desired.State == kubermaticv1.UserClusterTokenActive {
			desired.Groups = normalizeGroups(result.User.Spec.Groups)
		}
	}

	current := attribute.Status
	transition := current.State != desired.State || current.Reason != desired.Reason
	if !transition &&
		current.ObservedGeneration == attribute.Generation &&
		current.Username == desired.Username &&
		slices.Equal(current.Groups, desired.Groups) {
		return nil
	}

	oldAttribute := attribute.DeepCopy()
	now := metav1.NewTime(r.now())

	attribute.Status.ObservedGeneration = attribute.Generation
	attribute.Status.State = desired.State
	attribute.Status.Reason = desired.Reason
	attribute.Status.Username = desired.Username
	attribute.Status.Groups = desired.Groups
	attribute.Status.LastEvaluationTime = &now
	if transition {
		attribute.Status.LastTransitionTime = &now
	}

	if err := r.Status().Patch(ctx, attribute, ctrlruntimeclient.MergeFrom(oldAttribute)); err != nil {
		return fmt.Errorf("failed to patch attribute status: %w", err)
	}

	if transition {
		log.Infow("User state changed", "state", desired.State, "reason", desired.Reason)
	}

	return nil
}

func (r *AttributeReconciler) attributeForToken(_ context.Context, o ctrlruntimeclient.Object) []reconcile.Request {
	return []reconcile.Request{attributeRequest(o.(*kubermaticv1.UserClusterToken))}
}

func (r *AttributeReconciler) attributesForCluster(ctx context.Context, o ctrlruntimeclient.Object) []reconcile.Request {
	cluster := o.(*kubermaticv1.Cluster)

	tokens, err := tokensInNamespaceOf(ctx, r, cluster)
	if err != nil {
		r.log.Errorw("Failed to list tokens of cluster", "cluster", cluster.Name, zap.Error(err))
		return nil
	}

	return attributeRequests(tokens)
}

func (r *AttributeReconciler) attributesForUser(ctx context.Context, o ctrlruntimeclient.Object) []reconcile.Request {
	return r.attributesForUserIDs(ctx, o.GetName())
}

func (r *AttributeReconciler) attributesForUserProjectBinding(ctx context.Context, o ctrlruntimeclient.Object) []reconcile.Request {
	upb := o.(*kubermaticv1.UserProjectBinding)

	users := &kubermaticv1.UserList{}
	if err := r.List(ctx, users, ctrlruntimeclient.MatchingFields{userEmailIndex: strings.ToLower(upb.Spec.UserEmail)}); err != nil {
		r.log.Errorw("Failed to list users by email", zap.Error(err))
		return nil
	}

	return r.attributesForUserIDs(ctx, userNames(users)...)
}

func (r *AttributeReconciler) attributesForGroupProjectBinding(ctx context.Context, o ctrlruntimeclient.Object) []reconcile.Request {
	gpb := o.(*kubermaticv1.GroupProjectBinding)

	users := &kubermaticv1.UserList{}
	if err := r.List(ctx, users, ctrlruntimeclient.MatchingFields{userGroupIndex: gpb.Spec.Group}); err != nil {
		r.log.Errorw("Failed to list users by group", zap.Error(err))
		return nil
	}

	return r.attributesForUserIDs(ctx, userNames(users)...)
}

// attributesForUserIDs maps users to the attribute keys of every cluster namespace where
// they hold tokens. Users without tokens map to nothing.
func (r *AttributeReconciler) attributesForUserIDs(ctx context.Context, userIDs ...string) []reconcile.Request {
	var all []kubermaticv1.UserClusterToken

	for _, userID := range userIDs {
		tokens := &kubermaticv1.UserClusterTokenList{}
		if err := r.List(ctx, tokens, ctrlruntimeclient.MatchingFields{tokenUserIDIndex: userID}); err != nil {
			r.log.Errorw("Failed to list tokens of user", "user", userID, zap.Error(err))
			continue
		}
		all = append(all, tokens.Items...)
	}

	return attributeRequests(all)
}

// attributeRequests returns one request per distinct namespace and user.
func attributeRequests(tokens []kubermaticv1.UserClusterToken) []reconcile.Request {
	keys := sets.New[types.NamespacedName]()
	for i := range tokens {
		keys.Insert(attributeRequest(&tokens[i]).NamespacedName)
	}

	requests := make([]reconcile.Request, 0, keys.Len())
	for key := range keys {
		requests = append(requests, reconcile.Request{NamespacedName: key})
	}

	return requests
}

func userNames(users *kubermaticv1.UserList) []string {
	names := make([]string, 0, len(users.Items))
	for _, u := range users.Items {
		names = append(names, u.Name)
	}

	return names
}
