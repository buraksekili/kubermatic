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

// Package projectmember decides whether a KKP user may use the clusters of a project. The
// seed token controller and the master token synchronizer share it, so both sides apply
// the same rule.
package projectmember

import (
	"context"
	"fmt"
	"strings"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	kubermaticv1helper "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1/helper"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Result is the outcome of Evaluate.
type Result struct {
	// Reason is empty when the user may use the project's clusters.
	Reason kubermaticv1.UserClusterAttributeReason
	// User is nil when the user does not exist.
	User *kubermaticv1.User
}

// Evaluate checks, in this order, that the user exists and is not being deleted, is not a
// project service account, and is a member of the project. Member means a KKP admin, a
// UserProjectBinding for the project (email compared case-insensitively), or a
// GroupProjectBinding for the project whose group the user has. Any role counts.
func Evaluate(ctx context.Context, reader ctrlruntimeclient.Reader, userID, projectID string) (Result, error) {
	user := &kubermaticv1.User{}
	if err := reader.Get(ctx, types.NamespacedName{Name: userID}, user); err != nil {
		if apierrors.IsNotFound(err) {
			return Result{Reason: kubermaticv1.UserClusterAttributeUserNotFound}, nil
		}
		return Result{}, fmt.Errorf("failed to get user: %w", err)
	}

	if user.DeletionTimestamp != nil {
		return Result{Reason: kubermaticv1.UserClusterAttributeUserNotFound, User: user}, nil
	}

	if user.Spec.Project != "" || kubermaticv1helper.IsProjectServiceAccount(user.Spec.Email) {
		return Result{Reason: kubermaticv1.UserClusterAttributeServiceAccountUser, User: user}, nil
	}

	member, err := IsMember(ctx, reader, user, projectID)
	if err != nil {
		return Result{}, err
	}
	if !member {
		return Result{Reason: kubermaticv1.UserClusterAttributeNotProjectMember, User: user}, nil
	}

	return Result{User: user}, nil
}

// IsMember reports whether the user is a KKP admin or bound to the project.
func IsMember(ctx context.Context, reader ctrlruntimeclient.Reader, user *kubermaticv1.User, projectID string) (bool, error) {
	if user.Spec.IsAdmin {
		return true, nil
	}

	if projectID == "" {
		return false, nil
	}

	upbs := &kubermaticv1.UserProjectBindingList{}
	if err := reader.List(ctx, upbs); err != nil {
		return false, fmt.Errorf("failed to list UserProjectBindings: %w", err)
	}

	// a binding being deleted is a removal someone asked for: it no longer grants
	// membership, even while KKP's own cleanup finalizers still hold the object
	for _, upb := range upbs.Items {
		if upb.DeletionTimestamp != nil {
			continue
		}
		if upb.Spec.ProjectID == projectID && strings.EqualFold(upb.Spec.UserEmail, user.Spec.Email) {
			return true, nil
		}
	}

	if len(user.Spec.Groups) == 0 {
		return false, nil
	}

	gpbs := &kubermaticv1.GroupProjectBindingList{}
	if err := reader.List(ctx, gpbs); err != nil {
		return false, fmt.Errorf("failed to list GroupProjectBindings: %w", err)
	}

	userGroups := sets.New(user.Spec.Groups...)
	for _, gpb := range gpbs.Items {
		if gpb.DeletionTimestamp != nil {
			continue
		}
		if gpb.Spec.ProjectID == projectID && userGroups.Has(gpb.Spec.Group) {
			return true, nil
		}
	}

	return false, nil
}
