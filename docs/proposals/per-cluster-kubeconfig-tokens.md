# Per-Cluster Kubeconfig Tokens

Author: Burak Sekili

Status: Draft proposal. A prototype exists on a feature branch and is under test. All code references in this document point to that branch. Measured values come from the test environments and are marked as such.

## Summary

A kubeconfig exported from the KKP dashboard today contains the user's OIDC ID token, a refresh token, and the shared issuer client secret. Every user cluster trusts the same issuer and audience. A kubeconfig exported for one cluster therefore also works on every other cluster the user can reach, and the refresh token keeps it valid without a time limit. Operators cannot scope the credential to one cluster, give it a per-cluster lifetime, or revoke it on its own.

This proposal replaces that credential with an opaque token that exactly one user cluster accepts. The user still logs in through the customer identity provider when exporting the kubeconfig. The kubeconfig works with plain kubectl and needs no plugin. kube-apiserver validates the token through Kubernetes webhook token authentication against a small KKP webhook that runs per user cluster on the seed. A token lasts 24 hours by default, and KKP revokes a token within about a minute.

The authoritative token record lives on the master cluster. The seed holds a copy that the webhook reads. That split is what keeps revoked tokens revoked when an operator restores a seed from a backup.

## Motivation and Background

Kubeconfig export today follows the design from the earlier proposal "User Cluster Authentication via Dex". The KKP API runs an OAuth flow against the identity provider and puts the resulting ID token, refresh token, issuer client ID and client secret into the kubeconfig. kube-apiserver of each user cluster accepts ID tokens from that issuer.

Two properties of that credential limit how precisely KKP can scope and end access. First, the audience is shared. Every user cluster is configured with the same issuer client ID, `kubermaticIssuer`, so an ID token minted for one cluster is a valid bearer token on every other cluster. KKP cannot reject it on the other clusters, because the token itself is a correct, signed JWT. Second, the kubeconfig contains the refresh token and the issuer client secret. kubectl uses them to renew the ID token, so an exported kubeconfig keeps working with no end date. The holder can also run the OAuth flow directly against the identity provider with the embedded client secret.

The test environment confirmed this behavior on a real v2.31.3 installation (test UP-12, 2026-11-03). A kubeconfig downloaded for cluster `ca` contained the user `alice@example.com`, an ID token with audience `kubermaticIssuer` expiring at 2026-11-04T09:21:10Z, a refresh token, and the issuer client secret. The same file authenticated with HTTP 200 on cluster `ca` and on cluster `cb`. Two related behaviors come from the same design: one user credential is accepted by every user cluster, and the web terminal leaves user credentials inside user clusters.

Revocation does not end access for an exported kubeconfig today. Deleting the user in KKP or removing them from the project changes nothing about a signed JWT inside its validity period. Waiting for the ID token to expire does not help either, because the holder renews it with the embedded refresh token and client secret. The remaining options are rotating the issuer client secret, which breaks every user at once, or revoking the user's refresh tokens at the identity provider, where the provider supports that. Dex, which KKP ships as the issuer, can also cap refresh tokens with `expiry.refreshTokens.absoluteLifetime`; the chart KKP ships sets no cap, so refresh tokens live forever. A cap would bound the credential's lifetime, but it would not fix the shared audience, and it would expire dashboard login sessions at the same rate.

A per-cluster credential solves these limits in one design. Each token is scoped to one user cluster. Each token has its own lifetime and can be revoked on its own. Each token carries an ID that appears in the audit log. The operator decides per cluster whether that cluster also accepts the legacy OIDC credential.

## Goals

1. A kubeconfig exported for one user cluster is rejected by every other user cluster and by the KKP API.
2. The kubeconfig works with plain kubectl. No exec plugin, no kubelogin, no KKP binary on user machines.
3. The customer identity provider (Dex, Entra ID, Keycloak, Okta) stays the source of login, MFA, identity and groups.
4. KKP creates no clients or app registrations inside customer identity providers.
5. The token store and the token validator sit outside the control of tenant admins of user clusters.
6. Revoking a token, removing a user from a project, or disabling a user ends access within minutes.
7. Audit logs in the user cluster show the person in `user.username`.
8. Works in offline installations with customer CA bundles.
9. A restore of a seed from backup does not bring revoked tokens back.

## Non-Goals

- Replacing the identity provider or the dashboard login.
- Imported (external) clusters. KKP does not run their apiserver, so webhook token authentication cannot be configured for them.
- The static admin kubeconfig. It stays a separate item; see Open Questions.

## Terms

| Term | Meaning |
|---|---|
| Master cluster | The cluster that runs the KKP dashboard and KKP API. It stores projects, users and memberships. |
| Seed cluster | A cluster that runs the control planes of user clusters. One installation can have several seeds. |
| User cluster | A customer Kubernetes cluster. Its kube-apiserver and etcd run as pods on a seed. |
| Cluster namespace | The namespace `cluster-<id>` on the seed that holds one user cluster's control plane pods. |
| Project | A KKP group of user clusters with its own members. |
| KKP User | A custom resource KKP creates for each person who logs in. Its name is a 64-character ID. |
| UserProjectBinding | A custom resource that makes one KKP User a member of one project. |
| GroupProjectBinding | A custom resource, Enterprise Edition, that makes every user of one identity provider group a member of one project. |
| Controller | A program that watches Kubernetes objects and changes other objects until they match. One pass is called a reconcile. |
| Feature gate | A boolean setting that turns a not-yet-default feature on. This feature uses the gate `UserClusterTokenWebhook`. |
| Opaque token | A random string that carries no identity itself. Only its issuer can say who owns it. |
| TokenReview | A Kubernetes API object, `authentication.k8s.io/v1`, that carries a token to a webhook and the verdict back. |
| Informer | A client-go mechanism that keeps an in-memory copy of watched objects and receives changes as events. |
| Uncached read | An API read that skips the informer copy and goes to the API server directly. |
| Level-triggered | A controller compares current state with wanted state on every pass, so a missed event is repaired on the next pass. |

## Proposal

### Webhook token authentication

This section is the prerequisite for everything that follows.

kube-apiserver tries several authenticators for each request: client certificates, the static token file, ServiceAccount tokens, OIDC JWTs, and, if configured, a token webhook. A JWT or a certificate carries its own identity and signature, so kube-apiserver can check it alone. An opaque token is a random string. Only its issuer knows who owns it.

With `--authentication-token-webhook-config-file`, kube-apiserver sends each bearer token that no other authenticator accepted to an HTTP endpoint, wrapped in a TokenReview:

```json
{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
 "spec": {"token": "kkp_ca_ec197a417cc98f0a:<secret>"}}
```

The webhook answers with the user, or with `authenticated: false`:

```json
{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
 "status": {"authenticated": true,
            "user": {"username": "alice@example.com",
                     "uid": "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976",
                     "groups": ["oidc:kkp-admins"],
                     "extra": {"kkp.k8c.io/credential-id": ["ec197a417cc98f0a"]}}}}
```

kube-apiserver caches each answer for `--authentication-token-webhook-cache-ttl` and then runs RBAC as the returned user. Accepted and rejected answers are cached; webhook errors are not. Webhook token authentication is a GA, documented Kubernetes feature: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication

Because the answer is cached, every revocation path in this proposal has the same floor on its delay: the cache TTL, 60 seconds by default.

### New objects

Four custom resources hold the token information. Three new controllers keep them correct.

| Plain name | Kind | Lives on | Purpose |
|---|---|---|---|
| Token record | `UserClusterTokenIssuance` | master | The official record that a token exists. Deleting it revokes the token. |
| Seed copy | `UserClusterToken` | seed, in the cluster namespace | A copy of the token record that the webhook reads locally. |
| Access record | `UserClusterAttribute` | seed, in the cluster namespace | One object per user and cluster: may the user still use the cluster, with which email and groups. |
| Bulk revocation | `UserClusterTokenRevocation` | master | An admin order to revoke every token of one cluster or one seed issued before a given time. |

### Token record

Why it exists: some component must decide whether a token is valid, and that decision must survive a seed restore. The master is the only place that knows projects, users and memberships across all seeds. The token record therefore lives on the master, and the master decides.

The KKP API creates one token record when a user exports a kubeconfig. The object name is the token ID, a random 16-character string. The record stores the SHA-256 hash of the token's secret part, never the secret itself, plus the owner, the cluster, the hosting seed, and the expiry time.

Every spec field except `label` is immutable. The API server rejects any change, also from a cluster-admin. A validation rule enforces this per field, and another rule pins the object name to the token ID format (`sdk/apis/kubermatic/v1/user_cluster_token.go:59-141`). Immutability matters because the hash decides which secret the webhook accepts. A changed hash would make the same token ID accept a different secret.

Real object from the test environment, created by an export at 19:07:48 UTC on 2026-11-02 (hash redacted):

```yaml
apiVersion: kubermatic.k8c.io/v1
kind: UserClusterTokenIssuance
metadata:
  name: ec197a417cc98f0a                  # token ID
  labels:
    kubermatic.k8c.io/cluster-id: ca
spec:
  tokenHash: <64 hex chars, redacted>     # SHA-256 of the secret part
  userID: ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976
  clusterID: ca
  clusterUID: 95ad6b91-b369-493c-8a13-19637f38c219
  seedName: kubermatic
  issueTime: "2026-11-02T19:07:48Z"
  expirationTime: "2026-11-03T19:07:48Z"  # default lifetime 24 h
  issuanceRequestID: EM7V3TXUNFDMKTZCUHR5CQZZ4C   # links to the KKP API log line
```

Three events delete a token record: a user or admin revokes the token; the token expired more than 24 hours ago; or a controller finds that the cluster is gone or the user lost membership. There is no "revoked" flag. Deletion is the only revocation mechanism, so a token either has a record or it does not.

### Seed copy

Why it exists: kube-apiserver calls the webhook for every request with an unknown token. The webhook runs on the seed and must not depend on the master for each request, because the master can be far away or down. Each seed therefore holds a copy of the token records of its own clusters, in each cluster's namespace.

The token synchronizer on the master creates and deletes these copies; see Controllers below. The webhook only reads them. Because each copy sits in its cluster namespace, the webhook of cluster `ca` gets read access to `cluster-ca` only and cannot read token hashes of any other cluster.

A seed controller writes a status on the copy: `state: Active`, or `state: Disabled` with a reason such as `Expired` or `ClusterUIDMismatch`. The webhook writes `lastUsedTime`, throttled to one write per token per 5 minutes. The idle timeout uses that time.

```yaml
apiVersion: kubermatic.k8c.io/v1
kind: UserClusterToken
metadata:
  name: ec197a417cc98f0a
  namespace: cluster-ca
spec:                                     # identical to the token record
  ...
status:
  state: Active
  observedGeneration: 1
  lastEvaluationTime: "2026-11-02T19:07:49Z"
```

### Access record

Why it exists: a token must stop working when its owner leaves the project, and the webhook must know the owner's current email and groups. That information lives in KKP Users and project bindings, which exist on the seed as cluster-scoped copies. The webhook could read them directly. Then every webhook pod would need read access to every user and every membership on the seed. That is far more data than a webhook for one cluster needs.

So a seed controller, the access controller, reads Users and bindings on the webhook's behalf and writes the verdict into one small object per user per cluster namespace. The webhook then reads only objects in its own namespace.

The access record holds a yes or no (`state`), the reason for a no (`NotProjectMember`, `UserNotFound`, `ServiceAccountUser`), the lowercased email, and the identity provider groups:

```yaml
apiVersion: kubermatic.k8c.io/v1
kind: UserClusterAttribute
metadata:
  name: ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976
  namespace: cluster-ca
spec:
  userID: ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976
status:
  state: Active
  username: alice@example.com
  groups: [kkp-admins]                   # webhook adds the "oidc:" prefix
  lastTransitionTime: "2026-11-02T17:57:03Z"
```

The access controller creates the record when the user's first token for the cluster appears and deletes it when the last one is gone (`pkg/controller/seed-controller-manager/user-cluster-token/attribute_controller.go:77`).

### Bulk revocation

Why it exists: suppose an operator restores both the master and a seed from a backup taken last week. The restored master no longer knows which tokens were revoked since the backup. A bulk revocation closes that gap. It orders the token synchronizer to delete every token record of one cluster, or of one seed, issued before a given time. The operator creates it with kubectl as one step of the restore runbook:

```yaml
apiVersion: kubermatic.k8c.io/v1
kind: UserClusterTokenRevocation
metadata:
  name: restore-2026-11-02
spec:
  seedName: kubermatic                    # or clusterID: ca; exactly one of both
  issuedBefore: "2026-11-02T12:00:00Z"
  reason: master and seed restored from the 2026-10-26 backup
```

Users who still need access export a new kubeconfig, which gets an issue time after the cut.

### Controllers

All three controllers run only with the feature gate on (`pkg/controller/seed-controller-manager/kubernetes/resources.go:241`).

The token synchronizer runs in the master-controller-manager as `kkp-user-cluster-token-synchronizer` (`pkg/controller/master-controller-manager/user-cluster-token-synchronizer/controller.go:63`). It watches token records and bulk revocations on the master, and copies, access records and clusters on each seed. Its reconcile is level-triggered, which repairs both directions of a lost event: a missing copy is created, an orphan copy without a token record is deleted. Before it deletes a copy, it confirms with an uncached master read that the record is really gone, so a stale cache never deletes the copy of a live token (controller.go:286, 313). It enforces two time constants: expired records are kept for 24 hours and then deleted (`DefaultExpiryGracePeriod`, controller.go:67), and a membership removal becomes permanent only after a 2-minute grace (`MembershipRemovalGracePeriod`, controller.go:73).

The token status controller runs in the seed-controller-manager. It evaluates each seed copy in a fixed order: expiry, cluster missing, cluster UID mismatch, cluster being deleted, else Active (`pkg/controller/seed-controller-manager/user-cluster-token/token_controller.go:105-114`). An Active token is requeued at its expiry time plus one second, because no watch event announces expiry (token_controller.go:99).

The access controller also runs in the seed-controller-manager. It evaluates membership with `pkg/controller/util/projectmember/projectmember.go:48-77`, a helper the master-side check uses too, so master and seed apply the identical rule. Member means: KKP admin, or a UserProjectBinding for the project, or a GroupProjectBinding whose group is in `User.spec.groups`. Any role counts, and bindings being deleted no longer count.

The webhook accepts a token only when the seed copy and the access record both say Active and the secret's hash matches. A no from either object rejects the request. That split lets each controller react to the events it watches without knowing about the others.

### The token webhook

The webhook is a small HTTPS service, one per user cluster, deployed as its own Deployment with two replicas (`pkg/resources/token-webhook/deployment.go:37`). It runs from a separate image, `quay.io/kubermatic/kkp-token-webhook`, versioned apart from KKP, so a webhook release does not roll kube-apiserver.

The token format is `kkp_<cluster-id>_<token-id>:<secret>` (`pkg/token-webhook/token.go:54-59`). The `kkp_` prefix lets secret scanners recognize these tokens in repositories and logs. The parser rejects a token whose cluster ID is not this webhook's cluster before any lookup.

Decision order per TokenReview (`pkg/token-webhook/authenticator.go:214-330`):

| Step | Check | Answer on failure |
|---|---|---|
| 1 | Request is a v1 TokenReview, strict decode, size limit | HTTP 400 |
| 2 | Token parses, cluster ID matches this webhook | reject, no lookup |
| 3 | Informers synced, last seed API contact within 2 minutes (`-max-staleness`, `cmd/kkp-token-webhook/main.go:83`) | 503 |
| 4 | Seed copy exists | reject |
| 5 | Seed copy evaluated | 503 |
| 6 | Copy Active, cluster ID and UID match, not expired, hash matches in constant time, used within the idle timeout | reject |
| 7 | Access record exists and is evaluated | 503 |
| 8 | Access record Active, username set, no `system:` or KKP-project-like group | reject |
| 9 | All passed | authenticated |

The 503 answers are deliberate. kube-apiserver caches a rejection for the full TTL but does not cache a webhook error. A 503 during a cold start poisons nothing; the next request after recovery succeeds.

Identity rules: the username is the lowercased email; groups get the `oidc:` prefix; every answer adds `system:authenticated`; the extra field `kkp.k8c.io/credential-id` carries the token ID (authenticator.go:43). The `oidc:` prefix means RBAC written for today's OIDC entry keeps matching.

### Exporting a kubeconfig

The export endpoint lives in the KKP API. It exists only when the gate is on and the dashboard logs in through its own OIDC client, separate from the issuer client. Otherwise it returns 404 and the legacy flow is unchanged (dashboard `modules/api/pkg/handler/v2/userclustertoken/export.go:117`).

1. The user clicks Export kubeconfig. The browser goes to `GET /api/v2/clusters/<id>/kubeconfig/token`. The KKP API sets an encrypted state cookie and redirects to the identity provider, with scopes `openid email groups` and no `offline_access`.
2. The user logs in with the customer's MFA and policies. The identity provider redirects back with an authorization code.
3. The KKP API exchanges the code and verifies the ID token: signature, issuer, audience of the login client, expiry, `email_verified`. Identity comes only from this token.
4. It finds the KKP User by email, refuses project ServiceAccounts, and checks project membership.
5. It applies the rate limit and the cap: 5 exports at once, then 1 per minute, and at most 10 unexpired tokens per user per cluster. At the cap it refuses and never revokes the oldest (export.go:343, 425-444).
6. It generates a 16-character token ID and a 256-bit secret, hashes the secret with SHA-256, and creates the token record (export.go:506-539). The secret is returned once, in the kubeconfig, and never stored.
7. Until the seed controllers have evaluated the new copy and the access record, the webhook answers 503. A token used in that first second is therefore not cached as rejected.

The identity provider must allow the callback for every cluster, `https://<domain>/api/v2/clusters/<cluster-id>/kubeconfig/token`. Dex has no wildcard redirects; Entra ID and Okta need registration. This is Open Question 1.

### Life of one token

This trace follows token `ec197a417cc98f0a` from export to revocation. Times are measured on the test environment unless noted.

1. Alice exports a kubeconfig for cluster `ca`. The KKP API creates the token record at 19:07:48.
2. The token synchronizer creates the seed copy in `cluster-ca`.
3. The token status controller writes `state: Active` at 19:07:49.
4. Alice runs kubectl. kube-apiserver sends a TokenReview to `https://kkp-token-webhook.cluster-ca.svc.cluster.local:443`. The webhook finds both objects Active and the hash matching, and returns alice. RBAC runs as `alice@example.com`.
5. Alice revokes the token in the dashboard. The KKP API deletes the token record, and the synchronizer deletes the seed copy within about a second. The token answers 200 until the kube-apiserver cache entry expires, then 401: measured 64 seconds after the DELETE (test R-01). An admin revoke through `/api/v2/admin/kubeconfig/tokens/<id>` behaves the same. A measured admin revoke of another user's token answered 401 at the first poll, 2 seconds later, on a replica with a cold cache (test D2-02).

A kubeconfig issued for cluster `ca` behaves as follows when it is presented elsewhere, measured on 2026-11-02 (tests C-02 to C-04):

| Used against | Result |
|---|---|
| Another user cluster | 401. The webhook of cluster `cb` rejects the cluster ID before any lookup. This held even after alice was made cluster-admin on `cb`, so the refusal comes from the token binding, not RBAC. |
| The KKP API | 401. The KKP API does not accept these tokens. |
| The own cluster | Works until revoked, expired, or idle for 24 h. |

### Seed restore

Why the record lives on the master: an earlier draft of this design stored the token record only on the seed. The counterfactual shows what happens when an operator restores a seed from a backup taken before alice revoked her token.

| | Record only on the seed | Record on master, copy on seed |
|---|---|---|
| After the restore, the seed holds | alice's token, state Active | alice's seed copy, state Active |
| Who notices the revocation | nobody; the seed has no other source | the synchronizer; the master has no record `ec197a417cc98f0a` |
| Result | the revoked token works until expiry, up to 7 days | the synchronizer deletes the copy on its next pass |

Both directions were verified with a real Velero restore on the test environment (2026-11-03). A restored seed copy without a token record was deleted about 300 milliseconds after the restore completed; the log line is `Deleting seed copy without issuance`. A restore that brought back both the record and the copy, under an existing bulk revocation, lost both again within 300 milliseconds. A poll that still answered 200 afterwards was traced to the 60-second cache on the second apiserver replica, not to the restored objects.

### Per-cluster switch

Turning the gate on adds the webhook but keeps the existing OIDC authenticator, so legacy kubeconfigs keep working. Closing the shared-audience problem needs the OIDC authenticator removed per cluster. The annotation `kubermatic.k8c.io/token-webhook-only: "true"` on a Cluster does that: KKP renders the apiserver AuthenticationConfiguration with an empty JWT list, so the shared `kubermaticIssuer` audience is gone from that cluster only (`pkg/resources/apiserver/authenticationconfiguration.go:49`). Deleting the annotation reverts it.

Consideration: the switch should become a Cluster spec field before the first release. The Kubernetes API conventions say new API fields must not ship as annotations: a field gets schema validation, appears in `kubectl explain`, and the Cluster validation webhook can check it against `spec.oidc` and a seed-level AuthenticationConfiguration, which today silently override or are dropped by the annotation. The conventions also advise a string policy over a bool, because a third mode is plausible (webhook only, webhook plus legacy OIDC, webhook plus the cluster's own `spec.oidc` issuer). A candidate is `spec.kubeconfigAuthentication: Legacy | TokenWebhookOnly`.

Measured on 2026-11-02 (test C-06): the annotation was set on cluster `cb` at 20:17:25. The apiserver rolled and was Ready after 28 seconds. A legacy OIDC kubeconfig for `cb` then answered 401; the AuthenticationConfiguration of `cb` had zero JWT entries.

### Settings

`KubermaticConfiguration.spec.userClusterTokens`, defaults applied in `pkg/defaulting/configuration.go:71-75,641`:

| Setting | Default | Effect |
|---|---|---|
| `defaultLifetime` | 24h | Lifetime when the user asks for nothing else |
| `maxLifetime` | 168h | Longest accepted lifetime; operators may lower it |
| `idleTimeout` | 24h | Passed to the webhook; changing it rolls only the webhook |
| `webhookCacheTTL` | 60s | The apiserver flag; changing it restarts kube-apiserver |
| `maxActivePerUserPerCluster` | 10 | Cap enforced by the export endpoint |

Fixed values: minimum lifetime 10 minutes; webhook max staleness 120 seconds; last-used write throttle 5 minutes; membership removal grace 2 minutes; expired record retention 24 hours. The 24-hour default matches the OpenShift default and the NIST SP 800-63B ceiling for reauthentication at authenticator assurance level 2 (prior-art review; not re-verified for this document).

### Audit logging

kube-apiserver authenticates a request first and writes the audit event afterwards, so the user the webhook returns is the user the audit event records. Measured on the test environment (test AU-01):

```json
"user": {"username": "alice@example.com",
         "uid": "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976",
         "groups": ["oidc:kkp-admins", "system:authenticated"],
         "extra": {"kkp.k8c.io/credential-id": ["ec197a417cc98f0a"]}}
```

Username and groups are unchanged from today's OIDC events, so existing SIEM rules keep matching. New are the uid and the credential ID, which links each audit event to the export log line of that token. No `impersonatedUser` field appears.

### Deployment shape

For every user cluster with the gate on, the seed-controller-manager renders the webhook Deployment, a Service, a PodDisruptionBudget, and the apiserver flags and kubeconfig Secret. The Deployment runs two replicas with rolling updates and `maxUnavailable: 0`. The Role grants `get, list, watch` on tokens and attributes in its own namespace, and `patch` on `userclustertokens/status` so the webhook can write `lastUsedTime`. It grants nothing else, no Secrets (`pkg/resources/token-webhook/rbac.go:39-58`). The webhook is a separate Deployment, not a sidecar in the apiserver pod, because a crashing sidecar would take every apiserver replica out of the Service. All new connections stay inside the seed, so offline installations need no new CA trust. Cost: two extra pods per user cluster on the seed.

### Known gap: user removal after a seed restore

KKP copies Users and project bindings to every seed, because seed-side MLA components need them. The copying only reacts to changes on the master. It never deletes a seed copy that has no master object.

The consequence: the master deletes a token record for a removed user only after the seed reports the user as no longer a member. A seed restore can bring the old binding copy back. The seed then keeps reporting the user as a member, so the master never deletes the tokens. A removed employee keeps cluster access until the token expires, at most 7 days, and nothing in the dashboard or logs shows it.

The decided fix: the token synchronizer will also watch Users and bindings on the master, re-check the affected user's tokens on every change, and re-check all tokens on a fixed interval, for example hourly. The seed-side access record stays as the fast path that blocks requests within seconds. This change is decided but not in the current prototype. Until it lands, the restore runbook tells operators to create a bulk revocation for every restored seed.

## Migration and Rollout

Prerequisites, shipped with this work:

1. A separate dashboard login client, so the export flow never handles the issuer client secret. With the gate on, validation rejects a configuration that reuses the issuer client.
2. Validation rules that reject `system:` usernames and groups on every JWT entry KKP renders.
3. An Enterprise Edition change to GroupProjectBinding creation: only owners and project managers may grant, and never a role higher than the requester's own.
4. Web terminal fixes, so the web terminal leaves no user credentials inside user clusters.

Rollout steps:

1. Upgrade KKP with the prerequisites.
2. Configure the separate login client and register the per-cluster export redirect URIs at the identity provider.
3. Turn on `UserClusterTokenWebhook`. Every user cluster apiserver restarts once, and legacy OIDC kubeconfigs keep working.
4. Users export new kubeconfigs from the dashboard.
5. Move the web terminal and the Kubernetes Dashboard proxy off Dex tokens. Not built yet.
6. Per cluster, set `kubermatic.k8c.io/token-webhook-only: "true"`. Legacy kubeconfigs, kubelogin, and until step 5 the web terminal stop working on that cluster.
7. After every cluster is switched, rotate the issuer client secret.
8. Phase 2: periodic identity provider refresh, so a user disabled at the provider loses tokens within about the refresh interval instead of at expiry.

Rollback: remove the annotation per cluster, or turn the gate off for the whole installation. Both re-enable the legacy OIDC authenticator and restart kube-apiserver once.

## Alternatives Considered

| Option | Idea | Why not chosen |
|---|---|---|
| Per-cluster audience at the identity provider | The issuer mints a token per cluster audience | KKP would manage clients inside every customer identity provider; one login per cluster |
| KKP-signed short-lived JWT | KKP signs a JWT with a per-cluster audience | Sound, but short tokens need a kubectl plugin; adds a signing key, rotation and distribution to every apiserver |
| Short-lived client certificates | Certificates through the cluster CSR API | etcd trusts the cluster CA; tenant admins control the in-cluster signer; against CIS 3.1.1 |
| Central kubectl proxy | One proxy impersonates the user to each cluster | New data path for every request; impersonation-header handling has needed repeated fixes in such proxies |
| Per-user ServiceAccount token | A ServiceAccount token with impersonation rights | Tenant admins can mint tokens for it; audit shows the ServiceAccount, not the person |
| Token record only on the seed | The KKP API writes the record straight to the seed | A seed restore brings revoked tokens back; see Seed restore |
| Webhook as apiserver sidecar | The webhook runs inside the apiserver pod | A crashing sidecar takes every apiserver replica out of the Service |

Precedent, checked against primary sources on 2026-11-03:

- Rancher's Authorized Cluster Endpoint is the closest match. A central Rancher server issues opaque `name:secret` tokens and syncs them to each downstream cluster as `ClusterAuthToken` objects with a salted SHA3-512 hash, plus one `ClusterUserAttribute` per user with the enabled state and groups. The `kube-api-auth` webhook on the control plane nodes validates them through `--authentication-token-webhook-config-file`. Kubeconfig tokens default to 30 days, with a 90-day maximum.
- OpenShift's built-in OAuth server issues opaque tokens, stores only their SHA-256 hash (`sha256~` prefix, since 4.6), and kube-apiserver validates them through a TokenReview webhook to oauth-apiserver. The default lifetime is 24 hours, with no inactivity timeout by default. Each cluster runs its own issuer, so there is no central issuer as in KKP. In HyperShift, oauth-apiserver runs in the hosted control plane namespace, the same layout as a KKP cluster namespace on the seed.
- EKS (aws-iam-authenticator) and OpenStack Keystone (`k8s-keystone-auth`) use the same webhook mechanism with other token types. EKS tokens are presigned STS requests bound to the cluster ID; nothing is stored. AKS appears to use it through Azure guard, which Microsoft documents only for Arc-enabled clusters.
- Gardener does not use it for user kubeconfigs. The `shoots/adminkubeconfig` subresource issues short-lived client certificates, and the gardenlogin plugin renews them.

Most published fixes in these projects concerned token storage and logging. OpenShift once wrote OAuth tokens in plaintext to apiserver audit logs, and once stored them unencrypted at rest, so etcd backups contained them. Rancher once kept credentials in cleartext on Kubernetes objects, and once wrote sensitive data to audit logs. One fix concerned the webhook itself. In aws-iam-authenticator v0.5.2 to v0.5.8, an allow-listed identity could change the AccessKeyID used to build its username, and so authenticate under a different username. The webhook's parsing and identity mapping code therefore needs the same care as storage and logging; see Considerations.

Sources: https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/manage-clusters/access-clusters/authorized-cluster-endpoint, https://github.com/rancher/kube-api-auth, https://ranchermanager.docs.rancher.com/api/api-tokens, https://docs.redhat.com/en/documentation/openshift_container_platform/4.14/html/authentication_and_authorization/configuring-internal-oauth, https://github.com/openshift/oauth-apiserver, https://github.com/openshift/hypershift (control-plane-operator/controllers/hostedcontrolplane/v2/kas/oauth.go), https://github.com/kubernetes-sigs/aws-iam-authenticator, https://gardener.cloud/docs/gardener/shoot/shoot_access/.

## Considerations

These came out of the 2026-11-03 review against the Kubernetes API conventions and the prior-art research. None is decided yet.

### Anyone who can create a token record can mint a token

The webhook accepts any token whose secret matches the `tokenHash` of a record, and whoever writes the record chooses that hash. Nothing ties a record to the KKP API, which should be the only issuer. So a principal with create access to `UserClusterTokenIssuance` on the master can mint a working kubeconfig for any user on any cluster, and audit logs show that user's username. That principal can be the KKP API ServiceAccount through a bug in the export or token API, a master admin, automation with broad RBAC on `kubermatic.k8c.io`, or someone who restores a hand-edited backup. On the seed, a principal that can create a `UserClusterToken` and patch its status gets a short window until the synchronizer deletes the orphan copy, plus the apiserver cache TTL. Many of these principals already have wide power, but the design turns write access to one CRD into a credential for any user, without a trace that the KKP API did not issue it.

Options:

1. Narrow RBAC on the token CRDs, alert on records not created by the KKP API ServiceAccount (managedFields, audit), and document the trust boundary. Cheap, no crypto.
2. HMAC-SHA-256 of the secret with a key outside etcd, shared by the KKP API and every webhook. The split-token guidance recommends this for the case where someone other than the issuer can write the store. Every seed then holds the key.
3. The KKP API signs the record fields (token ID, hash, user, cluster, cluster UID, seed, issue and expiry time) with a private key, and webhooks verify with the public key only. Write access on a seed then cannot produce valid records. This brings back a signing key and its rotation, but the key never leaves KKP and no apiserver needs it.

### Webhook input and identity mapping

The aws-iam-authenticator fix above shows that the webhook's own parsing decides which identity a request gets. The prototype already derives identity only from controller-written objects, never from the token; parses the token strictly and compares the cluster ID before any lookup; limits the request size and rejects unknown fields; matches emails case-insensitively everywhere; and rejects `system:` users and groups. Missing: fuzz tests for the token parser and the TokenReview handler; masking of internal reasons such as group names in the TokenReview `status.error`, as OpenShift's oauth-apiserver masks lookup errors; and a note in the trust model that the export trusts the identity provider's verified email claim, as the dashboard login does today, so a weaker Dex connector that vouches for another person's email maps to that person's KKP User.

### API shape

- Status uses a `state` and `reason` enum. The API conventions deprecate this `phase` pattern in favour of conditions with a summary `Ready` condition; CertificateSigningRequest shows conditions that cannot be removed once set, which fits Expired and ClusterUIDMismatch.
- `issuanceRequestID` is optional with a `self == oldSelf` rule. Kubernetes skips such transition rules when an update sets or unsets an optional field, so the field can be added or removed after creation.
- Token settings and list fields need bounds and cross-checks (lifetime ordering, non-negative durations, a maximum for `maxActivePerUserPerCluster`, `maxItems` on groups).

### Further ideas from the research

- A checksum suffix in the token, as GitHub tokens carry, so secret scanners can reject false positives offline.
- Documentation that tells operators to add the token CRDs to the apiserver encryption configuration on master and seeds. Nothing is encrypted at rest by default, and OpenShift once shipped OAuth tokens with exactly this gap.
- Plain SHA-256 of a 256-bit random secret is enough (NIST SP 800-63B, split-token guidance); Rancher's salted SHA3-512 adds nothing for random secrets.

## Open Questions

1. Redirect URIs: every new cluster needs its own redirect URI at the identity provider. Alternative under discussion: one fixed callback path with the cluster ID in the OAuth state.
2. Reserved groups: today a single `system:` group, or a group that looks like a KKP project group such as `viewers-finance`, rejects the whole token. Should the webhook drop only that group instead? A rejection fails closed but locks out users whose identity provider carries an unlucky group name.
3. Per-cluster switch rollout: switching a cluster breaks legacy kubeconfigs, kubelogin and the web terminal on it at once. Which order and communication does a customer need for step 6?
4. Clusters with custom username or group prefixes in `spec.oidc`: should the webhook follow the cluster's prefixes, or is the fixed email and `oidc:` mapping a documented change?
5. Configurable server URL and CA in exported kubeconfigs for clusters reached through a TLS-terminating proxy. Not implemented yet.
6. The static admin kubeconfig: an unexpiring credential downloadable by owners and editors, unchanged by this proposal. Interim: `DisableAdminKubeconfig`.
7. Kind names: `UserClusterTokenIssuance` and `UserClusterAttribute` are hard to understand without this document. Candidates: `UserClusterTokenRecord` and `UserClusterAccess`. A rename is cheap before the first release and expensive after it.
8. Access record or direct reads: the webhook could read Users and bindings itself, dropping one controller and one CRD. Decision waits for a memory measurement on a large seed.

## Task and Effort

Rough estimate from the design work, unverified: 13 to 18 person-weeks, of which the prototype covers the core. Remaining before release: the master-side membership re-check (the seed-restore gap), the web terminal and Dashboard proxy migration, monitoring for webhook 503s, and the open questions above.
