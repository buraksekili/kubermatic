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

// Package userclustertoken contains the seed controllers that keep what the token webhook
// of a user cluster reads up to date:
//
//   - the token controller writes the per-token status of each UserClusterToken (expiry,
//     cluster exists, cluster UID, cluster not being deleted);
//   - the attribute controller keeps one UserClusterAttribute per user and cluster
//     namespace while the user has tokens there, and writes whether the user may use the
//     cluster, plus username and groups.
//
// Neither creates or deletes UserClusterTokens; the master synchronizer owns them.
package userclustertoken

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// TokenControllerName is the name of the per-token status controller.
	TokenControllerName = "kkp-user-cluster-token-controller"
	// AttributeControllerName is the name of the per-user attribute controller.
	AttributeControllerName = "kkp-user-cluster-attribute-controller"

	// tokenUserIDIndex indexes UserClusterTokens by spec.userID.
	tokenUserIDIndex = "spec.userID"
	// userEmailIndex indexes Users by lowercase spec.email.
	userEmailIndex = "spec.email.lower"
	// userGroupIndex indexes Users by each entry of spec.groups.
	userGroupIndex = "spec.groups"
)

// Add registers the field indexes and both controllers.
func Add(ctx context.Context, mgr manager.Manager, log *zap.SugaredLogger, numWorkers int, workerName string) error {
	if err := addIndexes(ctx, mgr); err != nil {
		return err
	}

	if err := addTokenController(mgr, log, numWorkers, workerName); err != nil {
		return fmt.Errorf("failed to create token controller: %w", err)
	}

	if err := addAttributeController(mgr, log, numWorkers, workerName); err != nil {
		return fmt.Errorf("failed to create attribute controller: %w", err)
	}

	return nil
}

func addIndexes(ctx context.Context, mgr manager.Manager) error {
	indexer := mgr.GetFieldIndexer()

	if err := indexer.IndexField(ctx, &kubermaticv1.UserClusterToken{}, tokenUserIDIndex, tokenUserID); err != nil {
		return fmt.Errorf("failed to add index on UserClusterToken %s: %w", tokenUserIDIndex, err)
	}

	if err := indexer.IndexField(ctx, &kubermaticv1.User{}, userEmailIndex, userEmail); err != nil {
		return fmt.Errorf("failed to add index on User %s: %w", userEmailIndex, err)
	}

	if err := indexer.IndexField(ctx, &kubermaticv1.User{}, userGroupIndex, userGroups); err != nil {
		return fmt.Errorf("failed to add index on User %s: %w", userGroupIndex, err)
	}

	return nil
}

func tokenUserID(o ctrlruntimeclient.Object) []string {
	return []string{o.(*kubermaticv1.UserClusterToken).Spec.UserID}
}

func userEmail(o ctrlruntimeclient.Object) []string {
	return []string{strings.ToLower(o.(*kubermaticv1.User).Spec.Email)}
}

func userGroups(o ctrlruntimeclient.Object) []string {
	return o.(*kubermaticv1.User).Spec.Groups
}

// clusterWorkerName returns the worker-name label of the cluster, or "" for nil.
func clusterWorkerName(cluster *kubermaticv1.Cluster) string {
	if cluster == nil {
		return ""
	}

	return cluster.Labels[kubermaticv1.WorkerNameLabelKey]
}

// requeueAt returns how long to wait until t, at least one second.
func requeueAt(now func() time.Time, t time.Time) time.Duration {
	if d := t.Sub(now()) + time.Second; d > time.Second {
		return d
	}

	return time.Second
}

// normalizeGroups returns the groups sorted and without duplicates, so the status only
// changes when the set of groups changes.
func normalizeGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}

	return sets.List(sets.New(groups...))
}

// clusterChangedPredicate admits Cluster events that can change a token or attribute:
// create, delete, deletion started, project or worker-name label changed. Clusters update
// their status often; those updates are dropped.
func clusterChangedPredicate() predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj, newObj := e.ObjectOld, e.ObjectNew
			return (oldObj.GetDeletionTimestamp() == nil) != (newObj.GetDeletionTimestamp() == nil) ||
				oldObj.GetLabels()[kubermaticv1.ProjectIDLabelKey] != newObj.GetLabels()[kubermaticv1.ProjectIDLabelKey] ||
				oldObj.GetLabels()[kubermaticv1.WorkerNameLabelKey] != newObj.GetLabels()[kubermaticv1.WorkerNameLabelKey]
		},
	}
}

// specOrDeletionChangedPredicate drops status-only updates (User.status.lastSeen changes
// on every KKP API request) but keeps spec changes and the start of a deletion.
func specOrDeletionChangedPredicate() predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() ||
				(e.ObjectOld.GetDeletionTimestamp() == nil) != (e.ObjectNew.GetDeletionTimestamp() == nil)
		},
	}
}

// tokensInNamespaceOf lists the tokens of a cluster from the cache.
func tokensInNamespaceOf(ctx context.Context, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster) ([]kubermaticv1.UserClusterToken, error) {
	tokens := &kubermaticv1.UserClusterTokenList{}
	if err := client.List(ctx, tokens, ctrlruntimeclient.InNamespace(cluster.Status.NamespaceName)); err != nil {
		return nil, err
	}

	var result []kubermaticv1.UserClusterToken
	for _, t := range tokens.Items {
		if t.Spec.ClusterID == cluster.Name {
			result = append(result, t)
		}
	}

	return result, nil
}

func tokenRequest(t *kubermaticv1.UserClusterToken) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: t.Namespace, Name: t.Name}}
}

// attributeRequest is the key of the attribute of the token's owner in the token's namespace.
func attributeRequest(t *kubermaticv1.UserClusterToken) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: t.Namespace, Name: t.Spec.UserID}}
}
