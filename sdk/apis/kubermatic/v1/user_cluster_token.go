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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// UserClusterTokenResourceName represents "Resource" defined in Kubernetes.
	UserClusterTokenResourceName = "userclustertokens"
	// UserClusterTokenKindName represents "Kind" defined in Kubernetes.
	UserClusterTokenKindName = "UserClusterToken"

	// UserClusterTokenIssuanceResourceName represents "Resource" defined in Kubernetes.
	UserClusterTokenIssuanceResourceName = "userclustertokenissuances"
	// UserClusterTokenIssuanceKindName represents "Kind" defined in Kubernetes.
	UserClusterTokenIssuanceKindName = "UserClusterTokenIssuance"

	// UserClusterAttributeResourceName represents "Resource" defined in Kubernetes.
	UserClusterAttributeResourceName = "userclusterattributes"
	// UserClusterAttributeKindName represents "Kind" defined in Kubernetes.
	UserClusterAttributeKindName = "UserClusterAttribute"

	// UserClusterTokenRevocationResourceName represents "Resource" defined in Kubernetes.
	UserClusterTokenRevocationResourceName = "userclustertokenrevocations"
	// UserClusterTokenRevocationKindName represents "Kind" defined in Kubernetes.
	UserClusterTokenRevocationKindName = "UserClusterTokenRevocation"

	// UserClusterTokenUserIDLabel is set on UserClusterTokenIssuances and UserClusterTokens
	// to the KKP User name of the token owner, so tokens can be listed per user.
	UserClusterTokenUserIDLabel = "kubermatic.k8c.io/user-id"
	// UserClusterTokenClusterIDLabel is set on UserClusterTokenIssuances and UserClusterTokens
	// to the cluster ID, so tokens can be listed per cluster.
	UserClusterTokenClusterIDLabel = "kubermatic.k8c.io/cluster-id"

	// UserClusterTokenPrefix starts every token value. The full format is
	// "kkp_<cluster-id>_<token-id>:<secret>". The prefix lets secret scanners recognize these tokens.
	UserClusterTokenPrefix = "kkp_"
)

// UserClusterTokenSpec describes one kubeconfig token for one user cluster. It never
// contains the token secret, only its SHA-256 hash. The token ID is the object name.
//
// All fields except label are immutable.
type UserClusterTokenSpec struct {
	// TokenHash is the lowercase hex SHA-256 hash of the secret part of the token
	// (the text after the colon).
	// +required
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="tokenHash is immutable"
	TokenHash string `json:"tokenHash"`

	// UserID is the name of the KKP User that owns this token.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="userID is immutable"
	UserID string `json:"userID"`

	// ClusterID is the name of the KKP Cluster this token is valid for.
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="clusterID is immutable"
	ClusterID string `json:"clusterID"`

	// ClusterUID is the UID of the KKP Cluster at issue time. A cluster that is deleted
	// and created again with the same name has another UID, and old tokens stop working.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="clusterUID is immutable"
	ClusterUID string `json:"clusterUID"`

	// SeedName is the name of the Seed that hosts the cluster. The master synchronizer
	// copies the token to this seed only.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="seedName is immutable"
	SeedName string `json:"seedName"`

	// IssueTime is when KKP issued the token. UserClusterTokenRevocations compare
	// against it.
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="issueTime is immutable"
	IssueTime metav1.Time `json:"issueTime"`

	// ExpirationTime is when the token stops working. KKP sets it from the token
	// lifetime settings at issue time.
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="expirationTime is immutable"
	ExpirationTime metav1.Time `json:"expirationTime"`

	// Label is a free text name the user gives the token, for example "laptop".
	// +optional
	// +kubebuilder:validation:MaxLength=128
	Label string `json:"label,omitempty"`

	// IssuanceRequestID is the ID of the export request that created the token. It links
	// the token to the issuance log entry of the KKP API.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="issuanceRequestID is immutable"
	IssuanceRequestID string `json:"issuanceRequestID,omitempty"`
}

// +kubebuilder:resource:scope=Cluster
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:JSONPath=".spec.clusterID",name="Cluster",type="string"
// +kubebuilder:printcolumn:JSONPath=".spec.userID",name="User",type="string"
// +kubebuilder:printcolumn:JSONPath=".spec.label",name="Label",type="string"
// +kubebuilder:printcolumn:JSONPath=".spec.expirationTime",name="Expires",type="string"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type="date"
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^[a-z0-9]{8,32}$')",message="name must be the token ID: 8 to 32 lowercase letters or digits"
// +kubebuilder:validation:XValidation:rule="self.spec.expirationTime > self.spec.issueTime",message="spec.expirationTime must be after spec.issueTime"

// UserClusterTokenIssuance is the authoritative record of one kubeconfig token. It lives on
// the master cluster. The KKP API creates it when a user exports a kubeconfig and deletes it
// when the token is revoked. A master controller copies it to a UserClusterToken in the
// cluster namespace on the seed, and deletes seed copies that have no issuance, so a restored
// seed backup cannot bring revoked tokens back.
//
// The object name is the token ID.
type UserClusterTokenIssuance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec UserClusterTokenSpec `json:"spec"`
}

// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true

// UserClusterTokenIssuanceList is a list of UserClusterTokenIssuances.
type UserClusterTokenIssuanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is the list of UserClusterTokenIssuances.
	Items []UserClusterTokenIssuance `json:"items"`
}

// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:JSONPath=".spec.userID",name="User",type="string"
// +kubebuilder:printcolumn:JSONPath=".spec.label",name="Label",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.state",name="State",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.reason",name="Reason",type="string"
// +kubebuilder:printcolumn:JSONPath=".spec.expirationTime",name="Expires",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.lastUsedTime",name="LastUsed",type="date"
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^[a-z0-9]{8,32}$')",message="name must be the token ID: 8 to 32 lowercase letters or digits"
// +kubebuilder:validation:XValidation:rule="self.spec.expirationTime > self.spec.issueTime",message="spec.expirationTime must be after spec.issueTime"

// UserClusterToken is the seed copy of a UserClusterTokenIssuance. It lives in the
// cluster-<id> namespace on the seed, where the token webhook of that cluster reads it.
// Only the master synchronizer creates and deletes these objects; the seed token controller
// writes the status.
//
// The status holds only what belongs to this one token. Who the owner is (username, groups,
// membership) is in the UserClusterAttribute named after spec.userID in the same namespace.
//
// The object name is the token ID.
type UserClusterToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec UserClusterTokenSpec `json:"spec"`

	// +optional
	Status UserClusterTokenStatus `json:"status,omitempty"`
}

// UserClusterTokenState says whether the token webhook may accept a token or a user.
// +kubebuilder:validation:Enum=Active;Disabled
type UserClusterTokenState string

const (
	// UserClusterTokenActive means the check passed.
	UserClusterTokenActive UserClusterTokenState = "Active"
	// UserClusterTokenDisabled means the webhook rejects the token. Reason says why.
	UserClusterTokenDisabled UserClusterTokenState = "Disabled"
)

// UserClusterTokenReason explains a Disabled UserClusterToken.
// +kubebuilder:validation:Enum=ClusterNotFound;ClusterUIDMismatch;ClusterDeleting;Expired
type UserClusterTokenReason string

const (
	// UserClusterTokenClusterNotFound means the Cluster does not exist.
	UserClusterTokenClusterNotFound UserClusterTokenReason = "ClusterNotFound"
	// UserClusterTokenClusterUIDMismatch means the Cluster was created again under the same name.
	UserClusterTokenClusterUIDMismatch UserClusterTokenReason = "ClusterUIDMismatch"
	// UserClusterTokenClusterDeleting means the Cluster is being deleted.
	UserClusterTokenClusterDeleting UserClusterTokenReason = "ClusterDeleting"
	// UserClusterTokenExpired means spec.expirationTime has passed.
	UserClusterTokenExpired UserClusterTokenReason = "Expired"
)

// UserClusterTokenStatus is written by the seed token controller, except lastUsedTime,
// which the token webhook writes.
//
// The token webhook must not accept a token whose status.state is empty or whose
// status.observedGeneration differs from metadata.generation; it answers HTTP 503 for it,
// so kube-apiserver does not cache a rejection while the controller catches up.
type UserClusterTokenStatus struct {
	// ObservedGeneration is the metadata.generation the controller last evaluated.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// State says whether the token itself is usable. The owner's UserClusterAttribute must
	// be Active as well.
	// +optional
	State UserClusterTokenState `json:"state,omitempty"`

	// Reason says why the token is Disabled. Empty when Active.
	// +optional
	Reason UserClusterTokenReason `json:"reason,omitempty"`

	// LastUsedTime is the last time the webhook accepted the token, written at most once
	// every few minutes per token.
	// +optional
	LastUsedTime *metav1.Time `json:"lastUsedTime,omitempty"`

	// LastEvaluationTime is when the controller last changed the status.
	// +optional
	LastEvaluationTime *metav1.Time `json:"lastEvaluationTime,omitempty"`
}

// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true

// UserClusterTokenList is a list of UserClusterTokens.
type UserClusterTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is the list of UserClusterTokens.
	Items []UserClusterToken `json:"items"`
}

// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:JSONPath=".status.username",name="Username",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.state",name="State",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.reason",name="Reason",type="string"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type="date"
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.userID",message="name must equal spec.userID"

// UserClusterAttribute holds what the token webhook of one cluster needs to know about one
// KKP user: whether the user may use the cluster, and the username and groups to return.
// It lives in the cluster-<id> namespace on the seed, one object per user that has tokens
// for the cluster. The seed token controller creates it when the first token of the user
// appears, deletes it when the last one is gone, and writes its status.
//
// Keeping the user data here instead of on every token means a user with many tokens and
// many groups costs one object per cluster.
//
// The object name is the KKP User name.
type UserClusterAttribute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec UserClusterAttributeSpec `json:"spec"`

	// +optional
	Status UserClusterAttributeStatus `json:"status,omitempty"`
}

// UserClusterAttributeSpec names the user.
type UserClusterAttributeSpec struct {
	// UserID is the name of the KKP User.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="userID is immutable"
	UserID string `json:"userID"`
}

// UserClusterAttributeReason explains a Disabled UserClusterAttribute.
// +kubebuilder:validation:Enum=UserNotFound;ServiceAccountUser;NotProjectMember;UserDisabled
type UserClusterAttributeReason string

const (
	// UserClusterAttributeUserNotFound means the KKP User does not exist or is being deleted.
	UserClusterAttributeUserNotFound UserClusterAttributeReason = "UserNotFound"
	// UserClusterAttributeServiceAccountUser means the user is a KKP project service
	// account, which must not hold kubeconfig tokens.
	UserClusterAttributeServiceAccountUser UserClusterAttributeReason = "ServiceAccountUser"
	// UserClusterAttributeNotProjectMember means the user is not bound to the cluster's
	// project, neither through a UserProjectBinding nor through a GroupProjectBinding.
	// When this lasts longer than a short grace period and the master confirms it, the
	// master synchronizer deletes the user's tokens for the cluster for good.
	UserClusterAttributeNotProjectMember UserClusterAttributeReason = "NotProjectMember"
	// UserClusterAttributeUserDisabled means the KKP User is disabled. Reserved for the
	// identity provider refresh (phase 2); KKP Users have no disabled state yet.
	UserClusterAttributeUserDisabled UserClusterAttributeReason = "UserDisabled"
)

// UserClusterAttributeStatus is written by the seed token controller.
//
// The token webhook must not accept tokens of a user whose attribute is missing, has an
// empty state, or has status.observedGeneration different from metadata.generation; it
// answers HTTP 503 for them.
type UserClusterAttributeStatus struct {
	// ObservedGeneration is the metadata.generation the controller last evaluated.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// State says whether the user may use the cluster.
	// +optional
	State UserClusterTokenState `json:"state,omitempty"`

	// Reason says why the user is Disabled. Empty when Active.
	// +optional
	Reason UserClusterAttributeReason `json:"reason,omitempty"`

	// LastTransitionTime is when state or reason last changed.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Username is the Kubernetes username the webhook returns: the user's email in
	// lowercase, copied from the KKP User.
	// +optional
	Username string `json:"username,omitempty"`

	// Groups are the user's identity provider groups, copied unchanged from the KKP User
	// (spec.groups, set at the last KKP login). The webhook adds the "oidc:" prefix and
	// drops groups it must not return. Empty when Disabled.
	// +optional
	// +listType=set
	Groups []string `json:"groups,omitempty"`

	// LastEvaluationTime is when the controller last changed the status.
	// +optional
	LastEvaluationTime *metav1.Time `json:"lastEvaluationTime,omitempty"`
}

// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true

// UserClusterAttributeList is a list of UserClusterAttributes.
type UserClusterAttributeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is the list of UserClusterAttributes.
	Items []UserClusterAttribute `json:"items"`
}

// +kubebuilder:resource:scope=Cluster
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:JSONPath=".spec.clusterID",name="Cluster",type="string"
// +kubebuilder:printcolumn:JSONPath=".spec.seedName",name="Seed",type="string"
// +kubebuilder:printcolumn:JSONPath=".spec.issuedBefore",name="IssuedBefore",type="date"
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type="date"

// UserClusterTokenRevocation revokes every token of one cluster, or of all clusters on one
// seed, that was issued before a given time. KKP admins create it on the master, for example
// after restoring a backup. It lives only on the master. The master synchronizer deletes
// the matching UserClusterTokenIssuances, and with them their seed copies.
type UserClusterTokenRevocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec UserClusterTokenRevocationSpec `json:"spec"`
}

// UserClusterTokenRevocationSpec selects the tokens to revoke. Exactly one of clusterID and
// seedName must be set.
// +kubebuilder:validation:XValidation:rule="has(self.clusterID) != has(self.seedName)",message="exactly one of clusterID and seedName must be set"
type UserClusterTokenRevocationSpec struct {
	// ClusterID selects the tokens of one cluster.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	ClusterID string `json:"clusterID,omitempty"`

	// SeedName selects the tokens of all clusters on one seed.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	SeedName string `json:"seedName,omitempty"`

	// IssuedBefore revokes tokens whose spec.issueTime is before this time.
	// +required
	IssuedBefore metav1.Time `json:"issuedBefore"`

	// Reason is a free text note for other admins, for example the incident or restore it
	// belongs to.
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Reason string `json:"reason,omitempty"`
}

// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true

// UserClusterTokenRevocationList is a list of UserClusterTokenRevocations.
type UserClusterTokenRevocationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is the list of UserClusterTokenRevocations.
	Items []UserClusterTokenRevocation `json:"items"`
}
