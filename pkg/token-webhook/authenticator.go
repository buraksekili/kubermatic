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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// CredentialIDExtraKey carries the token ID in the TokenReview response,
	// so an audit event maps to exactly one issued token.
	CredentialIDExtraKey = "kkp.k8c.io/credential-id"

	// AuthenticatedGroup is added to every authenticated user, like every
	// other Kubernetes authenticator does.
	AuthenticatedGroup = "system:authenticated"

	systemPrefix = "system:"
)

// kkpInternalGroupPrefixes are the group prefixes KKP generates RBAC for
// (pkg/controller/master-controller-manager/rbac): owners-, editors-,
// viewers- and projectmanagers-<project>. Identity provider groups with
// these names are never returned, no matter the configured group prefix.
var kkpInternalGroupPrefixes = []string{"owners", "editors", "viewers", "projectmanagers"}

// isKKPInternalGroup reports whether the group name is built like one of
// KKP's own project groups.
func isKKPInternalGroup(group string) bool {
	prefix, _, found := strings.Cut(group, "-")
	return found && slices.Contains(kkpInternalGroupPrefixes, prefix)
}

// Decision says how a TokenReview must be answered.
type Decision int

const (
	// DecisionReject answers HTTP 200 with authenticated: false. kube-apiserver
	// caches the rejection for the webhook cache TTL.
	DecisionReject Decision = iota
	// DecisionAllow answers HTTP 200 with the user.
	DecisionAllow
	// DecisionUnavailable answers HTTP 503. kube-apiserver treats it as a
	// failed webhook call and does not cache anything.
	DecisionUnavailable
)

// Result is the outcome of authenticating one token.
type Result struct {
	Decision Decision
	// Reason explains a reject or unavailable decision and is safe to log
	// and to send to kube-apiserver; it never contains token material.
	Reason string
	// User is set when Decision is DecisionAllow.
	User *authenticationv1.UserInfo
	// TokenID and UserID identify the record for logging.
	TokenID string
	UserID  string
}

// LastUsedWriter patches status.lastUsedTime on a UserClusterToken.
type LastUsedWriter interface {
	WriteLastUsed(ctx context.Context, namespace, tokenID string, t time.Time) error
}

// statusClient is the part of a controller-runtime client needed to patch a
// status subresource.
type statusClient interface {
	ctrlruntimeclient.Writer
	Status() ctrlruntimeclient.SubResourceWriter
}

// lastUsedPatchWriter merge-patches only the lastUsedTime field on the status
// subresource, so it never races the fields the seed token controller owns.
type lastUsedPatchWriter struct {
	writer statusClient
}

func NewLastUsedPatchWriter(writer statusClient) LastUsedWriter {
	return &lastUsedPatchWriter{writer: writer}
}

func (w *lastUsedPatchWriter) WriteLastUsed(ctx context.Context, namespace, tokenID string, t time.Time) error {
	payload, err := json.Marshal(map[string]any{
		"status": map[string]any{
			"lastUsedTime": t.UTC().Truncate(time.Second).Format(time.RFC3339),
		},
	})
	if err != nil {
		return fmt.Errorf("encoding lastUsedTime patch: %w", err)
	}

	token := &kubermaticv1.UserClusterToken{ObjectMeta: metav1.ObjectMeta{Name: tokenID, Namespace: namespace}}
	patch := ctrlruntimeclient.RawPatch(types.MergePatchType, payload)

	if err := w.writer.Status().Patch(ctx, token, patch); err != nil {
		return fmt.Errorf("patching lastUsedTime: %w", err)
	}
	return nil
}

// lastUsedTracker throttles the lastUsedTime writes to at most one per token
// per interval. Entries are never removed: a cluster has a bounded number of
// active tokens (default cap 10 per user and cluster) and the map holds only
// IDs and timestamps.
type lastUsedTracker struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[string]time.Time
}

func newLastUsedTracker(interval time.Duration) *lastUsedTracker {
	return &lastUsedTracker{interval: interval, last: map[string]time.Time{}}
}

// shouldUpdate records the use of a token and reports whether a write is due.
func (t *lastUsedTracker) shouldUpdate(tokenID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if last, ok := t.last[tokenID]; ok && now.Sub(last) < t.interval {
		return false
	}
	t.last[tokenID] = now
	return true
}

// AuthenticatorConfig collects the inputs of the authenticator.
type AuthenticatorConfig struct {
	// ClusterID and ClusterUID identify the cluster this webhook serves.
	ClusterID  string
	ClusterUID string
	// GroupPrefix is prepended to every identity provider group.
	GroupPrefix string
	// ClockSkew extends the validity of a token to tolerate clock skew
	// between the webhook and the issuer.
	ClockSkew time.Duration
	// IdleTimeout rejects tokens unused for longer; 0 disables the check.
	IdleTimeout time.Duration
	// MaxStaleness is how old the last confirmed seed API contact may be
	// before the webhook refuses to answer; 0 disables the check.
	MaxStaleness time.Duration
	// LastUsedInterval throttles the lastUsedTime writes per token.
	LastUsedInterval time.Duration

	Store   tokenSource
	Writer  LastUsedWriter
	Metrics *Metrics
	Log     *zap.SugaredLogger

	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time
}

// Authenticator decides whether a bearer token belongs to a user of this
// cluster. It is the whole webhook logic without the HTTP layer.
type Authenticator struct {
	cfg       AuthenticatorConfig
	lastUsed  *lastUsedTracker
	namespace string
}

func NewAuthenticator(namespace string, cfg AuthenticatorConfig) *Authenticator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = zap.NewNop().Sugar()
	}
	return &Authenticator{cfg: cfg, lastUsed: newLastUsedTracker(cfg.LastUsedInterval), namespace: namespace}
}

func reject(reason string) Result {
	return Result{Decision: DecisionReject, Reason: reason}
}

func unavailable(reason string) Result {
	return Result{Decision: DecisionUnavailable, Reason: reason}
}

// Authenticate verifies one bearer token. The token value is never put into
// the result, the metrics or a log line; only the token ID is.
func (a *Authenticator) Authenticate(ctx context.Context, token string) Result {
	parsed, err := ParseToken(token, a.cfg.ClusterID)
	if err != nil {
		return reject(err.Error())
	}

	now := a.cfg.Now()

	if !a.cfg.Store.HasSynced() {
		return unavailable("informer caches have not synced yet")
	}
	if a.cfg.MaxStaleness > 0 && now.Sub(a.cfg.Store.LastContact()) > a.cfg.MaxStaleness {
		return unavailable("informer caches are stale")
	}

	result, tokenObj := a.checkToken(ctx, parsed, now)
	if result.Decision != DecisionAllow {
		a.logDecision(result, parsed.TokenID)
		return result
	}

	result = a.checkUser(ctx, tokenObj, result)
	if result.Decision != DecisionAllow {
		a.logDecision(result, parsed.TokenID)
		return result
	}

	log := a.cfg.Log.With("tokenID", parsed.TokenID, "userID", result.UserID, "username", result.User.Username)
	log.Debugw("token accepted")

	if a.cfg.Writer != nil && a.lastUsed.shouldUpdate(parsed.TokenID, now) {
		a.writeLastUsed(parsed.TokenID, now)
	}

	return result
}

// checkToken runs every check that needs only the token record. A nil record
// means the token ID is unknown.
func (a *Authenticator) checkToken(ctx context.Context, parsed ParsedToken, now time.Time) (Result, *kubermaticv1.UserClusterToken) {
	token, err := a.cfg.Store.GetToken(ctx, parsed.TokenID)
	if err != nil {
		return unavailable(fmt.Sprintf("reading token from cache: %v", err)), nil
	}
	if token == nil {
		return reject("token not found"), nil
	}

	// an unevaluated record must not become a cached rejection: a token
	// exported seconds ago would fail for a full cache TTL
	if token.Status.State == "" || token.Status.ObservedGeneration != token.Generation {
		return unavailable("token status has not been evaluated yet"), token
	}
	if token.Status.State != kubermaticv1.UserClusterTokenActive {
		return reject(fmt.Sprintf("token is disabled (%s)", token.Status.Reason)), token
	}
	if token.Spec.ClusterID != a.cfg.ClusterID {
		return reject("token was issued for another cluster"), token
	}
	if token.Spec.ClusterUID != a.cfg.ClusterUID {
		return reject("token was issued for a previous incarnation of this cluster"), token
	}
	if now.After(token.Spec.ExpirationTime.Add(a.cfg.ClockSkew)) {
		return reject("token has expired"), token
	}

	sum := sha256.Sum256([]byte(parsed.Secret))
	hash := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(token.Spec.TokenHash), []byte(hash)) != 1 {
		return reject("token secret does not match"), token
	}

	if a.cfg.IdleTimeout > 0 {
		lastUse := token.Spec.IssueTime.Time
		if token.Status.LastUsedTime != nil {
			lastUse = token.Status.LastUsedTime.Time
		}
		if now.After(lastUse.Add(a.cfg.IdleTimeout)) {
			return reject("token has not been used recently enough"), token
		}
	}

	return Result{Decision: DecisionAllow, TokenID: parsed.TokenID, UserID: token.Spec.UserID}, token
}

// checkUser resolves the owner's UserClusterAttribute and builds the user the
// TokenReview response carries.
func (a *Authenticator) checkUser(ctx context.Context, token *kubermaticv1.UserClusterToken, result Result) Result {
	attribute, err := a.cfg.Store.GetAttribute(ctx, token.Spec.UserID)
	if err != nil {
		return unavailable(fmt.Sprintf("reading user attribute from cache: %v", err))
	}
	if attribute == nil {
		return unavailable("user attribute has not been created yet")
	}
	if attribute.Status.State == "" || attribute.Status.ObservedGeneration != attribute.Generation {
		return unavailable("user attribute has not been evaluated yet")
	}
	if attribute.Status.State != kubermaticv1.UserClusterTokenActive {
		return reject(fmt.Sprintf("user may not use this cluster (%s)", attribute.Status.Reason))
	}

	if attribute.Status.Username == "" {
		return reject("user has no username")
	}
	if strings.HasPrefix(attribute.Status.Username, systemPrefix) {
		return reject("username is reserved")
	}

	groups := make([]string, 0, len(attribute.Status.Groups)+1)
	for _, group := range attribute.Status.Groups {
		if strings.HasPrefix(group, systemPrefix) {
			return reject("group " + group + " is reserved")
		}
		if isKKPInternalGroup(group) {
			return reject("group " + group + " is reserved")
		}
		groups = append(groups, a.cfg.GroupPrefix+group)
	}
	groups = append(groups, AuthenticatedGroup)

	result.User = &authenticationv1.UserInfo{
		Username: attribute.Status.Username,
		UID:      token.Spec.UserID,
		Groups:   groups,
		Extra: map[string]authenticationv1.ExtraValue{
			CredentialIDExtraKey: {result.TokenID},
		},
	}

	return result
}

// logDecision writes a rejection at info level: these are policy decisions
// an operator wants to see. Malformed tokens are logged at debug level only,
// because a flood of random bearer tokens must not spam the log (S-01, S-11).
func (a *Authenticator) logDecision(result Result, tokenID string) {
	log := a.cfg.Log.With("tokenID", tokenID)
	if result.Reason == ErrMalformedToken.Error() || result.Reason == ErrWrongCluster.Error() || result.Reason == ErrInvalidTokenID.Error() || result.Reason == "token not found" {
		log.Debugw("token rejected", "reason", result.Reason)
		return
	}
	log.Infow("token rejected", "reason", result.Reason)
}

// writeLastUsed patches the lastUsedTime in the background; the answer to
// kube-apiserver must not wait for a seed API write.
func (a *Authenticator) writeLastUsed(tokenID string, now time.Time) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := a.cfg.Writer.WriteLastUsed(ctx, a.namespace, tokenID, now); err != nil {
			a.cfg.Log.Errorw("failed to write lastUsedTime", "tokenID", tokenID, zap.Error(err))
			return
		}
		a.cfg.Metrics.ObserveLastUsedPatch()
	}()
}
