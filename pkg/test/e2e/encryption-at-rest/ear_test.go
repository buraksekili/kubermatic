//go:build e2e

/*
Copyright 2025 The Kubermatic Kubernetes Platform contributors.

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

package encryptionatrest

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/log"
	"k8c.io/kubermatic/v2/pkg/resources"
	"k8c.io/kubermatic/v2/pkg/resources/encryption"
	"k8c.io/kubermatic/v2/pkg/test/e2e/jig"
	"k8c.io/kubermatic/v2/pkg/test/e2e/utils"
	"k8c.io/kubermatic/v2/pkg/util/podexec"
	"k8c.io/kubermatic/v2/pkg/util/wait"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	credentials jig.BYOCredentials
	logOptions  = utils.DefaultLogOptions
)

func init() {
	credentials.AddFlags(flag.CommandLine)
	jig.AddFlags(flag.CommandLine)
	logOptions.AddFlags(flag.CommandLine)
}

const (
	defaultTimeout         = 10 * time.Minute
	defaultInterval        = 5 * time.Second
	minioBackupDestination = "minio"
)

type runner struct {
	seedClient ctrlruntimeclient.Client
	userClient ctrlruntimeclient.Client
	config     *rest.Config
	logger     *zap.SugaredLogger
	testJig    *jig.TestJig
}

func ensureEtcdLauncher(ctx context.Context, log *zap.SugaredLogger, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster) error {
	log.Info("ensuring etcd-launcher is enabled...")
	if err := patchCluster(ctx, client, cluster, func(c *kubermaticv1.Cluster) error {
		if c.Spec.Features == nil {
			c.Spec.Features = map[string]bool{}
		}
		c.Spec.Features[kubermaticv1.ClusterFeatureEtcdLauncher] = true
		return nil
	}); err != nil {
		return fmt.Errorf("failed to enable etcd-launcher: %w", err)
	}

	if err := waitForClusterHealthy(ctx, log, client, cluster); err != nil {
		return fmt.Errorf("etcd cluster is not healthy: %w", err)
	}

	active, err := isEtcdLauncherActive(ctx, client, cluster)
	if err != nil {
		return fmt.Errorf("failed to check StatefulSet command: %w", err)
	}

	if !active {
		return errors.New("feature flag had no effect on the StatefulSet")
	}

	return nil
}

func isEtcdLauncherActive(ctx context.Context, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster) (bool, error) {
	etcdHealthy, err := isClusterEtcdHealthy(ctx, client, cluster)
	if err != nil {
		return false, fmt.Errorf("etcd health check failed: %w", err)
	}

	sts := &appsv1.StatefulSet{}
	if err := client.Get(ctx, types.NamespacedName{Name: "etcd", Namespace: clusterNamespace(cluster)}, sts); err != nil {
		return false, fmt.Errorf("failed to get StatefulSet: %w", err)
	}

	return etcdHealthy && sts.Spec.Template.Spec.Containers[0].Command[0] == "/opt/bin/etcd-launcher", nil
}

// isClusterEtcdHealthy checks whether the etcd status on the Cluster object
// is Healthy and the StatefulSet is fully rolled out.
func isClusterEtcdHealthy(ctx context.Context, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster) (bool, error) {
	// refresh cluster status
	if err := client.Get(ctx, types.NamespacedName{Name: cluster.Name}, cluster); err != nil {
		return false, fmt.Errorf("failed to get cluster: %w", err)
	}

	sts := &appsv1.StatefulSet{}
	if err := client.Get(ctx, types.NamespacedName{Name: "etcd", Namespace: clusterNamespace(cluster)}, sts); err != nil {
		return false, fmt.Errorf("failed to get StatefulSet: %w", err)
	}

	clusterSize := int32(3)
	if size := cluster.Spec.ComponentsOverride.Etcd.ClusterSize; size != nil {
		clusterSize = *size
	}

	return cluster.Status.ExtendedHealth.Etcd == kubermaticv1.HealthStatusUp &&
		clusterSize == sts.Status.ReadyReplicas, nil
}

func waitForClusterHealthy(ctx context.Context, log *zap.SugaredLogger, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster) error {
	before := time.Now()

	time.Sleep(10 * time.Second)

	if err := wait.PollImmediateLog(
		ctx, log, defaultInterval, defaultTimeout,
		func(ctx context.Context) (transient error, terminal error) {
			// refresh cluster object for updated health status
			if err := client.Get(ctx, types.NamespacedName{Name: cluster.Name}, cluster); err != nil {
				return fmt.Errorf("failed to get cluster: %w", err), nil
			}

			healthy, err := isClusterEtcdHealthy(ctx, client, cluster)
			if err != nil {
				log.Infof("failed to check cluster etcd health status: %v", err)
				return nil, nil
			}

			if !healthy {
				return fmt.Errorf("etcd cluster is not healthy"), nil
			}

			return nil, nil
		},
	); err != nil {
		return fmt.Errorf("failed to check etcd health status: %w", err)
	}

	log.Infof("etcd cluster became healthy after %v.", time.Since(before))

	return nil
}

func patchCluster(ctx context.Context, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster, patch func(cluster *kubermaticv1.Cluster) error) error {
	if err := client.Get(ctx, types.NamespacedName{Name: cluster.Name}, cluster); err != nil {
		return fmt.Errorf("failed to get cluster: %w", err)
	}

	oldCluster := cluster.DeepCopy()
	if err := patch(cluster); err != nil {
		return err
	}

	if err := client.Patch(ctx, cluster, ctrlruntimeclient.MergeFrom(oldCluster)); err != nil {
		return fmt.Errorf("failed to patch cluster: %w", err)
	}

	time.Sleep(10 * time.Second)

	return nil
}

func TestEncryptionAtRest(t *testing.T) {
	ctx := context.Background()
	rawLogger := log.NewFromOptions(logOptions)
	logger := rawLogger.Sugar()

	ctrlruntimelog.SetLogger(zapr.NewLogger(rawLogger.WithOptions(zap.AddCallerSkip(1))))

	if err := credentials.Parse(); err != nil {
		t.Fatalf("Failed to get credentials: %v", err)
	}

	seedClient, config, err := utils.GetClients()
	if err != nil {
		t.Fatalf("failed to get client for seed cluster: %v", err)
	}

	testJig := jig.NewBYOCluster(seedClient, logger, credentials)
	testJig.ClusterJig.WithTestName("encryption-at-rest").WithFeatures(map[string]bool{
		kubermaticv1.ClusterFeatureEtcdLauncher: true,
	})

	logger.Info("setting up the cluster")

	_, cluster, err := testJig.Setup(ctx, jig.WaitForReadyPods)
	defer testJig.Cleanup(ctx, t, true)
	if err != nil {
		t.Fatalf("failed to setup test environment: %v", err)
	}

	userClient, err := testJig.ClusterClient(ctx)
	if err != nil {
		t.Fatalf("failed to create user cluster client: %v", err)
	}

	logger.Info("creating a dummy secret for testing encryption-at-rest")
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "dummy-",
			Namespace:    "default",
		},
		Data: map[string][]byte{
			"dummy-key": []byte("dummy-value"),
		},
	}

	err = userClient.Create(ctx, &secret)
	if err != nil {
		t.Fatalf("failed to create secret: %v", err)
	}

	r := runner{
		seedClient: seedClient,
		userClient: userClient,
		config:     config,
		logger:     logger,
		testJig:    testJig,
	}

	// Test Case 1: Enable encryption at rest and verify it works
	logger.Info("Test Case 1 running...")
	err = r.enableEAR(ctx, cluster)
	if err != nil {
		t.Fatalf("failed to enable encryption-at-rest: %v", err)
	}

	err = ensureEtcdLauncher(ctx, logger, seedClient, cluster)
	if err != nil {
		t.Fatalf("failed to enable etcd-launcher: %v", err)
	}

	err = ensureAPIServerUpdated(ctx, logger, seedClient, cluster)
	if err != nil {
		t.Fatalf("User cluster API server does not contain configurations for encryption-at-rest")
	}

	err = encryptionJobFinishedSuccessfully(ctx, logger, seedClient)
	if err != nil {
		t.Fatalf("data-encryption Job failed to run, err: %v", err)
	}

	err = ensureDataEncryption(ctx, logger, cluster, secret, config, true, encKeyName)
	if err != nil {
		t.Fatalf("failed to ensure data encryption: %v", err)
	}

	// Test Case 2:
	// Create an etcd backup for testing. Then, create a new secret that is not going to be part of the backup.
	// Rotate the encryption key to a new one.
	// Verify that the new secret is not encrypted with the initial encryption key; instead it is encrypted with the new encryption key.
	logger.Info("Test Case 2 running...")
	if err := r.createEtcdBackup(ctx, cluster); err != nil {
		t.Fatalf("failed to create etcd backup: %v", err)
	}

	postBackupSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "post-backup-",
			Namespace:    "default",
		},
		Data: map[string][]byte{
			"post-backup-key": []byte("post-backup-value"),
		},
	}

	err = userClient.Create(ctx, &postBackupSecret)
	if err != nil {
		t.Fatalf("failed to create post-backup test secret: %v", err)
	}

	err = ensureDataEncryption(ctx, logger, cluster, postBackupSecret, config, true, encKeyName)
	if err != nil {
		t.Fatalf("failed to ensure post-backup secret encryption: %v", err)
	}

	if err := r.rotateEncryptionKey(ctx, cluster); err != nil {
		t.Fatalf("failed to rotate encryption key: %v", err)
	}

	err = ensureDataEncryption(ctx, logger, cluster, secret, config, true, rotatedKeyName)
	if err != nil {
		t.Fatalf("failed to ensure original secret encryption with rotated key: %v", err)
	}
	err = ensureDataEncryption(ctx, logger, cluster, postBackupSecret, config, true, rotatedKeyName)
	if err != nil {
		t.Fatalf("failed to ensure post-backup secret encryption with rotated key: %v", err)
	}

	// Test Case 3: Restore etcd backup created with previous key.
	// After restore, verify the original secret (included in backup) is accessible.
	// Verify that the original secret is still properly encrypted in etcd after restore.
	// Verify the post-backup secret is not present as it wasn't in the backup.
	logger.Info("Test Case 3 running...")
	if err := r.restoreEtcdBackup(ctx, cluster); err != nil {
		t.Fatalf("failed to restore etcd backup: %v", err)
	}

	err = ensureDataAccessible(ctx, logger, userClient, secret.Name, secret.Namespace)
	if err != nil {
		t.Fatalf("failed to access original secret after restore: %v", err)
	}

	err = ensureDataEncryption(ctx, logger, cluster, secret, config, true, encKeyName)
	if err != nil {
		t.Fatalf("original secret not properly encrypted after restore: %v", err)
	}

	err = verifySecretDoesNotExist(ctx, logger, userClient, postBackupSecret.Name, postBackupSecret.Namespace)
	if err != nil {
		t.Fatalf("post-backup secret unexpectedly exists after restore: %v", err)
	}

	// Test Case 4: After restoring, verify encryption still works for new secrets based on the initial encryption key.
	postRestoreSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "post-restore-",
			Namespace:    "default",
		},
		Data: map[string][]byte{
			"post-restore-key": []byte("post-restore-value"),
		},
	}

	err = userClient.Create(ctx, &postRestoreSecret)
	if err != nil {
		t.Fatalf("failed to create post-restore test secret: %v", err)
	}

	err = ensureDataEncryption(ctx, logger, cluster, postRestoreSecret, config, true, encKeyName)
	if err != nil {
		t.Fatalf("encryption not working for new secrets after restore: %v", err)
	}

	// Test Case 5: Disable encryption at rest and verify data is decrypted automatically.
	logger.Info("Test Case 5 running...")

	err = r.disableEAR(ctx, cluster)
	if err != nil {
		t.Fatalf("failed to disable encryption-at-rest: %v", err)
	}

	err = ensureDataEncryption(ctx, logger, cluster, secret, config, false, encKeyName)
	if err != nil {
		t.Fatalf("failed to verify original secret is no longer encrypted: %v", err)
	}
}

func ensureAPIServerUpdated(ctx context.Context, logger *zap.SugaredLogger, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster) error {
	logger.Info("waiting for ApiServer to contain configurations for encryption-at-rest")

	err := wait.PollImmediateLog(
		ctx, logger, defaultInterval, defaultTimeout,
		func(ctx context.Context) (transient error, terminal error) {
			updated, err := isApiserverUpdated(ctx, client, cluster)
			if err != nil {
				return fmt.Errorf("failed to check apiserver status, %w", err), nil
			}

			if updated {
				logger.Info("apiserver is updated")
				return nil, nil
			}

			logger.Info("apiserver is not updated, retrying...")
			return fmt.Errorf("apiserver is not updated"), nil
		},
	)

	return err
}

func isApiserverUpdated(ctx context.Context, client ctrlruntimeclient.Client, cluster *kubermaticv1.Cluster) (bool, error) {
	var secret corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{
		Name:      resources.EncryptionConfigurationSecretName,
		Namespace: cluster.Status.NamespaceName,
	}, &secret); err != nil {
		return false, ctrlruntimeclient.IgnoreNotFound(err)
	}

	spec, err := json.Marshal(cluster.Spec.EncryptionConfiguration)
	if err != nil {
		return false, err
	}

	hash := sha1.New()
	hash.Write(spec)

	val, ok := secret.ObjectMeta.Labels[encryption.ApiserverEncryptionHashLabelKey] //nolint
	if !ok || val != hex.EncodeToString(hash.Sum(nil)) {
		return false, nil
	}

	var podList corev1.PodList
	if err := client.List(ctx, &podList,
		ctrlruntimeclient.InNamespace(cluster.Status.NamespaceName),
		ctrlruntimeclient.MatchingLabels{resources.AppLabelKey: "apiserver"},
	); err != nil {
		return false, err
	}

	if len(podList.Items) == 0 {
		return false, nil
	}

	for _, pod := range podList.Items {
		if val, ok := pod.Labels[encryption.ApiserverEncryptionRevisionLabelKey]; !ok || val != secret.ResourceVersion {
			return false, nil
		}
	}

	return true, nil
}

func clusterNamespace(cluster *kubermaticv1.Cluster) string {
	return fmt.Sprintf("cluster-%s", cluster.Name)
}

func ensureDataEncryption(
	ctx context.Context,
	logger *zap.SugaredLogger,
	cluster *kubermaticv1.Cluster,
	secret corev1.Secret,
	config *rest.Config,
	shouldBeEncrypted bool,
	keyName string,
) error {
	// k8s:enc:secretbox:v1:encryption-key-2025-04
	regexPattern := fmt.Sprintf(`"Value"\s*:\s*"k8s:enc:secretbox:v1:%s:`, keyName)
	logger.Info(
		"waiting to see if the secret data is encrypted with specific key",
		"keyName", keyName,
		"secret", ctrlruntimeclient.ObjectKeyFromObject(&secret).String(),
	)

	r := regexp.MustCompile(regexPattern)

	err := wait.PollImmediateLog(
		ctx, logger, defaultInterval, defaultTimeout*2,
		func(ctx context.Context) (transient error, terminal error) {
			stdout, stderr, err := podexec.ExecuteCommand(
				ctx,
				config,
				types.NamespacedName{
					Namespace: clusterNamespace(cluster),
					Name:      "etcd-0",
				},
				"etcd",
				"etcdctl",
				"get",
				fmt.Sprintf("/registry/secrets/%s/%s", secret.Namespace, secret.Name),
				"-w", "fields",
			)
			if err != nil {
				return fmt.Errorf("failed to get data from etcd (stdout=%s, stderr=%s): %w", stdout, stderr, err), nil
			}
			if stderr != "" {
				return fmt.Errorf("failed to get data from etcd (stdout=%s, stderr=%s)", stdout, stderr), nil
			}

			logger.Info("stdout from etcdctl", "stdout", stdout)

			encrypted := r.MatchString(stdout)
			if encrypted == shouldBeEncrypted {
				return nil, nil
			}

			return fmt.Errorf("etcd encryption at rest is not working as expected, got %v, expected %v", encrypted, shouldBeEncrypted), nil
		},
	)
	return err
}

const (
	encKeyVal  = "usPvwsI/cx3EHynJAeX5WZFfUYE84LckhiOBvnnZASo="
	encKeyName = "encryption-key-2025-04"

	rotatedKeyVal  = "F7THAMOu8QCRl2R7JHyS83lMVLwSf8zdBAVzv2p+22k="
	rotatedKeyName = "encryption-key-2025-05"
)

func (r *runner) enableEAR(ctx context.Context, cluster *kubermaticv1.Cluster) error {
	r.logger.Info("enabling encryption-at-rest")

	cc := cluster.DeepCopy()
	cluster.Spec.Features[kubermaticv1.ClusterFeatureEncryptionAtRest] = true
	cluster.Spec.EncryptionConfiguration = &kubermaticv1.EncryptionConfiguration{
		Enabled:   true,
		Resources: []string{"secrets"},
		Secretbox: &kubermaticv1.SecretboxEncryptionConfiguration{
			Keys: []kubermaticv1.SecretboxKey{
				{
					Name:  encKeyName,
					Value: encKeyVal,
				},
			},
		},
	}

	err := r.seedClient.Patch(ctx, cluster, ctrlruntimeclient.MergeFrom(cc))
	if err != nil {
		return fmt.Errorf("failed to patch cluster: %w", err)
	}

	r.logger.Info("Waiting for cluster to healthy after enabling encryption-at-rest")
	if err := r.testJig.WaitForHealthyControlPlane(ctx, defaultTimeout); err != nil {
		return fmt.Errorf("Cluster did not get healthy after enabling encryption-at-rest: %w", err)
	}

	// wait for cluster.status.encryption.phase to be active and status.condition contains
	// condition EncryptionControllerReconciledSuccessfully with status true, and
	// condition EncryptionInitialized with status true.
	r.logger.Info("waiting for cluster status to be updated after enabling encryption-at-rest")

	err = wait.PollImmediateLog(
		ctx, r.logger, defaultInterval, defaultTimeout,
		func(ctx context.Context) (transient error, terminal error) {
			c := cluster.DeepCopy()
			if err := r.seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(c), c); err != nil {
				return fmt.Errorf("failed to get cluster: %w", err), nil
			}

			if c.Status.Encryption == nil {
				r.logger.Info("cluster.status.encryption is still nil, retrying...")

				return fmt.Errorf("cluster.status.encryption is nil"), nil
			}

			if c.Status.Encryption.Phase != kubermaticv1.ClusterEncryptionPhaseActive {
				r.logger.Info("cluster.status.encryption.phase is not active, retrying...")

				return fmt.Errorf("cluster.status.encryption.phase is not active"), nil
			}

			if !c.Status.HasConditionValue(kubermaticv1.ClusterConditionEncryptionControllerReconcilingSuccess, corev1.ConditionTrue) {
				r.logger.Info("condition %s is not set yet, retrying...", kubermaticv1.ClusterConditionEncryptionControllerReconcilingSuccess)

				return fmt.Errorf("condition %s is not set yet", kubermaticv1.ClusterConditionEncryptionControllerReconcilingSuccess), nil
			}

			if !c.Status.HasConditionValue(kubermaticv1.ClusterConditionEncryptionInitialized, corev1.ConditionTrue) {
				r.logger.Info("condition %s is not set yet, retrying...", kubermaticv1.ClusterConditionEncryptionInitialized)

				return fmt.Errorf("condition %s is not set yet", kubermaticv1.ClusterConditionEncryptionInitialized), nil
			}

			r.logger.Info("cluster status is updated as expected after enabling encryption-at-rest")
			return nil, nil
		},
	)
	return err
}

func (r *runner) disableEAR(ctx context.Context, cluster *kubermaticv1.Cluster) error {
	r.logger.Info("disabling encryption-at-rest")

	cc := cluster.DeepCopy()
	cluster.Spec.Features[kubermaticv1.ClusterFeatureEncryptionAtRest] = false
	cluster.Spec.EncryptionConfiguration = nil

	err := r.seedClient.Patch(ctx, cluster, ctrlruntimeclient.MergeFrom(cc))
	if err != nil {
		return fmt.Errorf("failed to patch cluster: %w", err)
	}

	r.logger.Info("Waiting for cluster to healthy after disabling encryption-at-rest")
	if err := r.testJig.WaitForHealthyControlPlane(ctx, defaultTimeout); err != nil {
		return fmt.Errorf("Cluster did not get healthy after disabling encryption-at-rest: %w", err)
	}

	// wait for cluster.status.encryption is nil and status.condition contains
	// condition EncryptionControllerReconciledSuccessfully with status true, and
	// condition EncryptionInitialized with status 'false'.
	r.logger.Info("waiting for cluster status to be updated after disabling encryption-at-rest")

	err = wait.PollImmediateLog(
		ctx, r.logger, defaultInterval, defaultTimeout,
		func(ctx context.Context) (transient error, terminal error) {
			c := cluster.DeepCopy()
			if err := r.seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(c), c); err != nil {
				return fmt.Errorf("failed to get cluster: %w", err), nil
			}

			if c.Status.Encryption != nil {
				return fmt.Errorf("cluster.status.encryption is not nil"), nil
			}

			if !c.Status.HasConditionValue(kubermaticv1.ClusterConditionEncryptionControllerReconcilingSuccess, corev1.ConditionTrue) {
				return fmt.Errorf("condition %s is not set to true", kubermaticv1.ClusterConditionEncryptionControllerReconcilingSuccess), nil
			}

			if !c.Status.HasConditionValue(kubermaticv1.ClusterConditionEncryptionInitialized, corev1.ConditionFalse) {
				return fmt.Errorf("condition %s is not set to false", kubermaticv1.ClusterConditionEncryptionInitialized), nil
			}

			return nil, nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed to wait for cluster to healthy after disabling encryption-at-rest: %w", err)
	}

	return nil
}

func encryptionJobFinishedSuccessfully(ctx context.Context, logger *zap.SugaredLogger, c ctrlruntimeclient.Client) error {
	logger.Info("waiting for the data-encryption job to finish successfully")
	err := wait.PollImmediateLog(
		ctx, logger, defaultInterval, defaultTimeout,
		func(ctx context.Context) (transient error, terminal error) {
			jobList := &batchv1.JobList{}
			err := c.List(ctx, jobList, ctrlruntimeclient.MatchingLabels{
				resources.AppLabelKey: encryption.AppLabelValue,
			})
			if err != nil {
				return fmt.Errorf("failed to list jobs: %w", err), nil
			}

			if len(jobList.Items) == 0 {
				return fmt.Errorf(
					"no jobs found with label '%s: %s'", resources.AppLabelKey, encryption.AppLabelValue,
				), nil
			}

			job := jobList.Items[0]
			if len(job.Status.Conditions) == 0 {
				return fmt.Errorf("job status is not updated yet"), nil
			}

			expectedCompletions := int32(1)
			if job.Spec.Completions != nil {
				expectedCompletions = *job.Spec.Completions
			}

			if job.Status.Succeeded < expectedCompletions {
				return fmt.Errorf(
					"job pod is not succeeded yet, conditions: %+v", job.Status.Conditions,
				), nil
			}

			return nil, nil
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *runner) rotateEncryptionKey(ctx context.Context, cluster *kubermaticv1.Cluster) error {
	r.logger.Info("rotating encryption key by adding a new key as secondary key (step 1 of rotation)")

	// Get fresh cluster object before making changes
	currentCluster := &kubermaticv1.Cluster{}
	if err := r.seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(currentCluster), currentCluster); err != nil {
		return fmt.Errorf("failed to get current cluster state: %w", err)
	}

	cc := currentCluster.DeepCopy()

	// Step 1: Add the new key as a SECONDARY key (at the end of the keys list)
	currentCluster.Spec.EncryptionConfiguration.Secretbox.Keys = []kubermaticv1.SecretboxKey{
		{
			Name:  encKeyName,
			Value: encKeyVal,
		},
		{
			Name:  rotatedKeyName,
			Value: rotatedKeyVal,
		},
	}

	err := r.seedClient.Patch(ctx, currentCluster, ctrlruntimeclient.MergeFrom(cc))
	if err != nil {
		return fmt.Errorf("failed to patch cluster to add secondary key: %w", err)
	}

	r.logger.Info("Waiting for control plane components to be rotated with new secondary key")
	if err := r.testJig.WaitForHealthyControlPlane(ctx, defaultTimeout); err != nil {
		return fmt.Errorf("Cluster did not get healthy after adding new encryption key: %w", err)
	}

	// Step 2: Move the new key to the PRIMARY position (at the beginning of the keys list)
	r.logger.Info("Moving new key to primary position (step 2 of rotation)")

	// Get fresh cluster object before making changes
	if err := r.seedClient.Get(ctx, types.NamespacedName{
		Name:      cluster.Name,
		Namespace: cluster.Namespace,
	}, currentCluster); err != nil {
		return fmt.Errorf("failed to get current cluster state: %w", err)
	}

	cc = currentCluster.DeepCopy()
	currentCluster.Spec.EncryptionConfiguration.Secretbox.Keys = []kubermaticv1.SecretboxKey{
		{
			Name:  rotatedKeyName,
			Value: rotatedKeyVal,
		},
		{
			Name:  encKeyName,
			Value: encKeyVal,
		},
	}

	err = r.seedClient.Patch(ctx, currentCluster, ctrlruntimeclient.MergeFrom(cc))
	if err != nil {
		return fmt.Errorf("failed to patch cluster to set new key as primary: %w", err)
	}

	r.logger.Info("Waiting for control plane components to be rotated with new primary key and for data re-encryption")
	if err := r.testJig.WaitForHealthyControlPlane(ctx, defaultTimeout); err != nil {
		return fmt.Errorf("Cluster did not get healthy after setting new primary key: %w", err)
	}

	// Wait for re-encryption with new key to complete (cluster's encryption phase to be Active)
	err = wait.PollImmediateLog(
		ctx, r.logger, defaultInterval, defaultTimeout*2,
		func(ctx context.Context) (transient error, terminal error) {
			c := &kubermaticv1.Cluster{}
			if err := r.seedClient.Get(ctx, types.NamespacedName{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			}, c); err != nil {
				return fmt.Errorf("failed to get cluster: %w", err), nil
			}

			if c.Status.Encryption == nil {
				return fmt.Errorf("cluster.status.encryption is nil"), nil
			}

			if c.Status.Encryption.Phase != kubermaticv1.ClusterEncryptionPhaseActive {
				return fmt.Errorf("cluster.status.encryption.phase is not active, currently: %s", c.Status.Encryption.Phase), nil
			}

			r.logger.Info("Data re-encryption completed with new primary key")
			return nil, nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed to wait for re-encryption with new key: %w", err)
	}

	// Step 3: Remove the old key after re-encryption is complete
	r.logger.Info("Removing old encryption key (step 3 of rotation)")

	// Get fresh cluster object before making changes
	if err := r.seedClient.Get(ctx, types.NamespacedName{
		Name:      cluster.Name,
		Namespace: cluster.Namespace,
	}, currentCluster); err != nil {
		return fmt.Errorf("failed to get current cluster state: %w", err)
	}

	cc = currentCluster.DeepCopy()
	currentCluster.Spec.EncryptionConfiguration.Secretbox.Keys = []kubermaticv1.SecretboxKey{
		{
			Name:  rotatedKeyName,
			Value: rotatedKeyVal,
		},
	}

	err = r.seedClient.Patch(ctx, currentCluster, ctrlruntimeclient.MergeFrom(cc))
	if err != nil {
		return fmt.Errorf("failed to patch cluster to remove old key: %w", err)
	}

	r.logger.Info("Waiting for cluster to be healthy after removing old encryption key")
	if err := r.testJig.WaitForHealthyControlPlane(ctx, defaultTimeout); err != nil {
		return fmt.Errorf("Cluster did not get healthy after removing old encryption key: %w", err)
	}

	err = ensureAPIServerUpdated(ctx, r.logger, r.seedClient, cluster)
	if err != nil {
		return fmt.Errorf("User cluster API server does not contain configurations for new encryption key: %w", err)
	}

	return nil
}

func (r *runner) createEtcdBackup(ctx context.Context, cluster *kubermaticv1.Cluster) error {
	r.logger.Info("creating one-time etcd backup")

	backupConfig := kubermaticv1.EtcdBackupConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ear-test-backup",
			Namespace: cluster.Status.NamespaceName,
		},
		Spec: kubermaticv1.EtcdBackupConfigSpec{
			Cluster: corev1.ObjectReference{
				Kind:            cluster.Kind,
				Name:            cluster.Name,
				Namespace:       cluster.Namespace,
				UID:             cluster.UID,
				APIVersion:      cluster.APIVersion,
				ResourceVersion: cluster.ResourceVersion,
			},
			Destination: minioBackupDestination,
		},
	}

	err := r.seedClient.Create(ctx, &backupConfig)
	if err != nil {
		return fmt.Errorf("failed to create etcd backup config: %w", err)
	}

	r.logger.Info("waiting for backup to be completed")
	err = wait.PollImmediateLog(
		ctx, r.logger, defaultInterval, defaultTimeout*2,
		func(ctx context.Context) (transient error, terminal error) {
			if err := r.seedClient.Get(ctx, types.NamespacedName{
				Name:      backupConfig.Name,
				Namespace: backupConfig.Namespace,
			}, &backupConfig); err != nil {
				return fmt.Errorf("failed to get backup config: %w", err), nil
			}

			if len(backupConfig.Status.CurrentBackups) == 0 {
				return fmt.Errorf("no backups listed in status yet"), nil
			}

			for _, backup := range backupConfig.Status.CurrentBackups {
				if backup.BackupPhase == kubermaticv1.BackupStatusPhaseCompleted {
					r.logger.Info("backup completed successfully")
					return nil, nil
				}

				r.logger.Infof("backup not completed yet, backupName: %s, backupPhase: %s", backup.BackupName, backup.BackupPhase)
			}

			r.logger.Infof("backupConfig.Status %+v", backupConfig.Status)

			return fmt.Errorf("backup not completed yet"), nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed to wait for backup completion: %w", err)
	}

	r.logger.Info("etcd backup created successfully")
	return nil
}

func (r *runner) restoreEtcdBackup(ctx context.Context, cluster *kubermaticv1.Cluster) error {
	r.logger.Info("restoring etcd from backup")

	// Find the backup name from EtcdBackupConfig status
	var backupConfig kubermaticv1.EtcdBackupConfig
	if err := r.seedClient.Get(ctx, types.NamespacedName{
		Name:      "ear-test-backup",
		Namespace: cluster.Status.NamespaceName,
	}, &backupConfig); err != nil {
		return fmt.Errorf("failed to get backup config: %w", err)
	}

	if len(backupConfig.Status.CurrentBackups) == 0 {
		return fmt.Errorf("no backups found in backup config status")
	}

	// Find the most recent completed backup
	var latestBackupName string
	var latestBackupTime time.Time
	for _, backup := range backupConfig.Status.CurrentBackups {
		if backup.BackupPhase == kubermaticv1.BackupStatusPhaseCompleted {
			// ScheduledTime is already a metav1.Time object
			if latestBackupName == "" || backup.ScheduledTime.After(latestBackupTime) {
				latestBackupName = backup.BackupName
				latestBackupTime = backup.ScheduledTime.Time
			}
		}
	}

	if latestBackupName == "" {
		return fmt.Errorf("no completed backups found for restoration")
	}

	r.logger.Info("found backup for restoration", "backupName", latestBackupName)

	// Create EtcdRestore object
	restore := &kubermaticv1.EtcdRestore{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ear-test-restore",
			Namespace: cluster.Status.NamespaceName,
		},
		Spec: kubermaticv1.EtcdRestoreSpec{
			Cluster: corev1.ObjectReference{
				Name:       cluster.Name,
				APIVersion: cluster.APIVersion,
				Kind:       cluster.Kind,
			},
			BackupName:  latestBackupName,
			Destination: minioBackupDestination,
		},
	}

	err := r.seedClient.Create(ctx, restore)
	if err != nil {
		return fmt.Errorf("failed to create etcd restore: %w", err)
	}

	// Wait for restoration to complete
	r.logger.Info("waiting for etcd restore to complete")
	err = wait.PollImmediateLog(
		ctx, r.logger, defaultInterval, defaultTimeout*3,
		func(ctx context.Context) (transient error, terminal error) {
			var currentRestore kubermaticv1.EtcdRestore
			if err := r.seedClient.Get(ctx, types.NamespacedName{
				Name:      restore.Name,
				Namespace: restore.Namespace,
			}, &currentRestore); err != nil {
				return fmt.Errorf("failed to get restore status: %w", err), nil
			}

			phase := currentRestore.Status.Phase
			r.logger.Info("current restore phase", "phase", phase)

			if phase == kubermaticv1.EtcdRestorePhaseCompleted {
				r.logger.Info("etcd restore completed successfully")
				return nil, nil
			}

			return fmt.Errorf("restore in progress, current phase: %s", phase), nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed waiting for etcd restore: %w", err)
	}

	r.logger.Info("waiting for cluster to become healthy after restore")
	if err := r.testJig.WaitForHealthyControlPlane(ctx, defaultTimeout); err != nil {
		return fmt.Errorf("cluster did not become healthy after restore: %w", err)
	}

	return nil
}

func ensureDataAccessible(ctx context.Context, logger *zap.SugaredLogger, client ctrlruntimeclient.Client, secretName, namespace string) error {
	logger.Info("verifying data is accessible after restore")

	err := wait.PollImmediateLog(
		ctx, logger, defaultInterval, defaultTimeout,
		func(ctx context.Context) (transient error, terminal error) {
			var secret corev1.Secret
			if err := client.Get(ctx, types.NamespacedName{
				Name:      secretName,
				Namespace: namespace,
			}, &secret); err != nil {
				return fmt.Errorf("failed to get secret: %w", err), nil
			}

			logger.Info("secret successfully retrieved after restore")
			return nil, nil
		},
	)

	return err
}

func verifySecretDoesNotExist(ctx context.Context, logger *zap.SugaredLogger, client ctrlruntimeclient.Client, secretName, namespace string) error {
	logger.Info("verifying secret does not exist", "name", secretName, "namespace", namespace)

	var secret corev1.Secret
	err := client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: namespace,
	}, &secret)

	if err == nil {
		return fmt.Errorf("secret still exists when it shouldn't")
	}

	if ctrlruntimeclient.IgnoreNotFound(err) != nil {
		return fmt.Errorf("error checking if secret exists: %w", err)
	}

	logger.Info("confirmed secret does not exist", "name", secretName)
	return nil
}
