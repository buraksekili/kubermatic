//go:build e2e

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

package velerobackup

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/zapr"
	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/log"
	"k8c.io/kubermatic/v2/pkg/test/e2e/utils"
	"k8c.io/kubermatic/v2/pkg/util/wait"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
)

var logOptions = utils.DefaultLogOptions

const (
	veleroNamespace   = "velero"
	scheduleName      = "hourly-cluster"
	backupStorageName = "default"

	// tokenNamespace mirrors the "cluster-<id>" namespaces that hold the seed
	// copies of the per-cluster kubeconfig tokens. No controller watches these
	// objects while the UserClusterTokenWebhook feature gate is off, which is
	// how this environment runs, so they sit still for the backup.
	tokenNamespace = "cluster-velero-e2e"
	canaryName     = "velero-e2e-canary"
)

// tokenResourceKinds are the per-cluster kubeconfig token kinds, kept in sync
// with charts/backup/velero/values.yaml: the hourly-cluster schedule must
// exclude them, so a master/seed restore never resurrects a token.
var tokenResourceKinds = []string{
	"userclustertokenissuances.kubermatic.k8c.io",
	"userclustertokenrevocations.kubermatic.k8c.io",
	"userclustertokens.kubermatic.k8c.io",
	"userclusterattributes.kubermatic.k8c.io",
}

func init() {
	logOptions.AddFlags(flag.CommandLine)
}

// TestVeleroBackupExcludesTokens proves on a KKP-in-kind master/seed, with
// Velero installed from charts/backup/velero, that the chart's hourly-cluster
// schedule excludes the per-cluster kubeconfig token kinds: they exist in the
// cluster, they stay out of the backup's resource list, and a restore does not
// bring back objects deleted before the restore. A canary ConfigMap proves the
// backup and restore actually captured state.
func TestVeleroBackupExcludesTokens(t *testing.T) {
	ctx := context.Background()
	rawLogger := log.NewFromOptions(logOptions)
	logger := rawLogger.Sugar()

	ctrlruntimelog.SetLogger(zapr.NewLogger(rawLogger.WithOptions(zap.AddCallerSkip(1))))

	client, _, err := utils.GetClients()
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	if err := velerov1.AddToScheme(client.Scheme()); err != nil {
		t.Fatalf("Failed to register velero/v1 scheme: %v", err)
	}

	// the deployed schedule must carry the exclusions; this doubles as a check
	// that the chart that was installed is the one from this repository. The
	// chart prefixes the schedule name with the Helm release name, so find it
	// by suffix.
	schedules := &velerov1.ScheduleList{}
	if err := client.List(ctx, schedules, ctrlruntimeclient.InNamespace(veleroNamespace)); err != nil {
		t.Fatalf("Failed to list Schedules in %s (is charts/backup/velero installed?): %v", veleroNamespace, err)
	}

	var schedule *velerov1.Schedule
	for i := range schedules.Items {
		if strings.HasSuffix(schedules.Items[i].Name, "-"+scheduleName) {
			schedule = &schedules.Items[i]
			break
		}
	}

	if schedule == nil {
		t.Fatalf("No Schedule ending in -%s found in %s.", scheduleName, veleroNamespace)
	}

	for _, kind := range tokenResourceKinds {
		found := false
		for _, excluded := range schedule.Spec.Template.ExcludedResources {
			if excluded == kind {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Schedule %s/%s does not exclude %q.", veleroNamespace, scheduleName, kind)
		}
	}

	// create the token objects the backup has to keep out: the master kinds
	// (issuance, revocation) and the seed kinds (token, attribute) in a cluster
	// namespace
	tokenSpec := kubermaticv1.UserClusterTokenSpec{
		TokenHash:      strings.Repeat("ab", 32),
		UserID:         "e2e-token-user",
		ClusterID:      "veleroe2e",
		ClusterUID:     "e2e-cluster-uid",
		SeedName:       "kubermatic",
		IssueTime:      metav1.NewTime(time.Now().Add(-time.Hour)),
		ExpirationTime: metav1.NewTime(time.Now().Add(23 * time.Hour)),
		Label:          "velero e2e",
	}

	issuance := &kubermaticv1.UserClusterTokenIssuance{
		ObjectMeta: metav1.ObjectMeta{Name: "e2evelerotoken01"},
		Spec:       tokenSpec,
	}
	if err := client.Create(ctx, issuance); err != nil {
		t.Fatalf("Failed to create UserClusterTokenIssuance: %v", err)
	}
	defer func() {
		client.Delete(ctx, issuance)
	}()

	revocation := &kubermaticv1.UserClusterTokenRevocation{
		ObjectMeta: metav1.ObjectMeta{Name: "e2evelerorevoke1"},
		Spec: kubermaticv1.UserClusterTokenRevocationSpec{
			ClusterID:    "veleroe2e",
			IssuedBefore: metav1.NewTime(time.Now()),
			Reason:       "velero e2e",
		},
	}
	if err := client.Create(ctx, revocation); err != nil {
		t.Fatalf("Failed to create UserClusterTokenRevocation: %v", err)
	}
	defer func() {
		client.Delete(ctx, revocation)
	}()

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tokenNamespace}}
	if err := client.Create(ctx, namespace); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("Failed to create namespace %s: %v", tokenNamespace, err)
	}

	token := &kubermaticv1.UserClusterToken{
		ObjectMeta: metav1.ObjectMeta{Name: issuance.Name, Namespace: tokenNamespace},
		Spec:       tokenSpec,
	}
	if err := client.Create(ctx, token); err != nil {
		t.Fatalf("Failed to create UserClusterToken: %v", err)
	}
	defer func() {
		client.Delete(ctx, token)
	}()

	attribute := &kubermaticv1.UserClusterAttribute{
		ObjectMeta: metav1.ObjectMeta{Name: tokenSpec.UserID, Namespace: tokenNamespace},
		Spec:       kubermaticv1.UserClusterAttributeSpec{UserID: tokenSpec.UserID},
	}
	if err := client.Create(ctx, attribute); err != nil {
		t.Fatalf("Failed to create UserClusterAttribute: %v", err)
	}
	defer func() {
		client.Delete(ctx, attribute)
	}()

	// the canary proves that the backup captured state and the restore brought
	// it back; without it, an empty backup would pass the token assertions
	canary := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: canaryName, Namespace: tokenNamespace},
		Data:       map[string]string{"backups": "... are fun!"},
	}
	if err := client.Create(ctx, canary); err != nil {
		t.Fatalf("Failed to create canary: %v", err)
	}

	// run the backup with exactly the schedule's template, so the test checks
	// the same filters the hourly-cluster schedule uses in production
	backup := &velerov1.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "velero-e2e-token-exclusion", Namespace: veleroNamespace},
		Spec:       schedule.Spec.Template,
	}
	backup.Spec.StorageLocation = backupStorageName
	backup.Spec.TTL = metav1.Duration{Duration: 1 * time.Hour}

	if err := client.Create(ctx, backup); err != nil {
		t.Fatalf("Failed to create Backup: %v", err)
	}

	logger.Info("Waiting for backup to complete...")
	if err := wait.PollImmediateLog(ctx, logger, 10*time.Second, 15*time.Minute, func(ctx context.Context) (transient error, terminal error) {
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(backup), backup); err != nil {
			return err, nil
		}

		if phase := backup.Status.Phase; phase != velerov1.BackupPhaseCompleted {
			return fmt.Errorf("backup is still %v", phase), nil
		}

		return nil, nil
	}); err != nil {
		t.Fatalf("Backup never finished: %v", err)
	}

	logger.Info("Checking the backup's resource list...")
	resourceList := fetchBackupResourceList(ctx, t, logger, client, backup.Name)

	for resource := range resourceList {
		for _, kind := range tokenResourceKinds {
			if strings.Contains(resource, kind) {
				t.Errorf("Backup resource list contains token kind %q.", resource)
			}
		}
	}

	if !resourceListContains(resourceList, "configmaps", canaryName) {
		t.Errorf("Backup resource list does not contain the canary ConfigMap %s/%s, the backup captured nothing.", tokenNamespace, canaryName)
	}

	// a backup must never remove the live objects either
	assertTokenObjectsExist(ctx, t, client, issuance.Name, tokenSpec.UserID)

	// delete everything the restore could resurrect, then prove only the
	// canary comes back
	for _, object := range []ctrlruntimeclient.Object{issuance, revocation, token, attribute, canary} {
		if err := client.Delete(ctx, object); err != nil {
			t.Fatalf("Failed to delete %s: %v", object.GetName(), err)
		}
	}

	restore := &velerov1.Restore{
		ObjectMeta: metav1.ObjectMeta{Name: "velero-e2e-token-exclusion", Namespace: veleroNamespace},
		Spec:       velerov1.RestoreSpec{BackupName: backup.Name},
	}
	if err := client.Create(ctx, restore); err != nil {
		t.Fatalf("Failed to create Restore: %v", err)
	}

	logger.Info("Waiting for restore to complete...")
	if err := wait.PollImmediateLog(ctx, logger, 10*time.Second, 15*time.Minute, func(ctx context.Context) (transient error, terminal error) {
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(restore), restore); err != nil {
			return err, nil
		}

		if phase := restore.Status.Phase; phase != velerov1.RestorePhaseCompleted {
			return fmt.Errorf("restore is still %v", phase), nil
		}

		return nil, nil
	}); err != nil {
		t.Fatalf("Restore never finished: %v", err)
	}

	if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(canary), canary); err != nil {
		t.Errorf("Canary was not restored: %v", err)
	}

	assertTokenObjectsGone(ctx, t, client, issuance.Name, tokenSpec.UserID)
}

func assertTokenObjectsExist(ctx context.Context, t *testing.T, client ctrlruntimeclient.Client, tokenID, userID string) {
	t.Helper()

	objects := []ctrlruntimeclient.Object{
		&kubermaticv1.UserClusterTokenIssuance{ObjectMeta: metav1.ObjectMeta{Name: tokenID}},
		&kubermaticv1.UserClusterTokenRevocation{ObjectMeta: metav1.ObjectMeta{Name: "e2evelerorevoke1"}},
		&kubermaticv1.UserClusterToken{ObjectMeta: metav1.ObjectMeta{Name: tokenID, Namespace: tokenNamespace}},
		&kubermaticv1.UserClusterAttribute{ObjectMeta: metav1.ObjectMeta{Name: userID, Namespace: tokenNamespace}},
	}

	for _, object := range objects {
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(object), object); err != nil {
			t.Errorf("Token object %s disappeared during the backup: %v", object.GetName(), err)
		}
	}
}

func assertTokenObjectsGone(ctx context.Context, t *testing.T, client ctrlruntimeclient.Client, tokenID, userID string) {
	t.Helper()

	objects := []ctrlruntimeclient.Object{
		&kubermaticv1.UserClusterTokenIssuance{ObjectMeta: metav1.ObjectMeta{Name: tokenID}},
		&kubermaticv1.UserClusterTokenRevocation{ObjectMeta: metav1.ObjectMeta{Name: "e2evelerorevoke1"}},
		&kubermaticv1.UserClusterToken{ObjectMeta: metav1.ObjectMeta{Name: tokenID, Namespace: tokenNamespace}},
		&kubermaticv1.UserClusterAttribute{ObjectMeta: metav1.ObjectMeta{Name: userID, Namespace: tokenNamespace}},
	}

	for _, object := range objects {
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(object), object); !apierrors.IsNotFound(err) {
			t.Errorf("Token object %s was resurrected by the restore (err: %v).", object.GetName(), err)
		}
	}
}

// fetchBackupResourceList downloads the backup's resource list via a Velero
// DownloadRequest. The list maps "kind[.group]" to the backed-up item names.
func fetchBackupResourceList(ctx context.Context, t *testing.T, logger *zap.SugaredLogger, client ctrlruntimeclient.Client, backupName string) map[string]json.RawMessage {
	t.Helper()

	downloadRequest := &velerov1.DownloadRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "resource-list-" + backupName, Namespace: veleroNamespace},
		Spec: velerov1.DownloadRequestSpec{
			Target: velerov1.DownloadTarget{
				Kind: velerov1.DownloadTargetKindBackupResourceList,
				Name: backupName,
			},
		},
	}
	if err := client.Create(ctx, downloadRequest); err != nil {
		t.Fatalf("Failed to create DownloadRequest: %v", err)
	}

	if err := wait.PollImmediateLog(ctx, logger, 5*time.Second, 2*time.Minute, func(ctx context.Context) (transient error, terminal error) {
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(downloadRequest), downloadRequest); err != nil {
			return err, nil
		}

		if phase := downloadRequest.Status.Phase; phase != velerov1.DownloadRequestPhaseProcessed {
			return fmt.Errorf("download request is still %v", phase), nil
		}

		return nil, nil
	}); err != nil {
		t.Fatalf("DownloadRequest never finished: %v", err)
	}

	response, err := http.Get(downloadRequest.Status.DownloadURL) //nolint:gosec
	if err != nil {
		t.Fatalf("Failed to download resource list: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("Failed to read resource list: %v", err)
	}

	resourceList := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &resourceList); err != nil {
		t.Fatalf("Failed to parse resource list %q: %v", string(body), err)
	}

	return resourceList
}

func resourceListContains(resourceList map[string]json.RawMessage, resource, itemName string) bool {
	for key, items := range resourceList {
		if strings.Contains(key, resource) && strings.Contains(string(items), itemName) {
			return true
		}
	}

	return false
}
