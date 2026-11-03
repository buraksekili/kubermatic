#!/usr/bin/env bash

# Copyright 2026 The Kubermatic Kubernetes Platform contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

### Runs the master/seed Velero backup e2e test on a KKP-in-kind cluster:
### installs Velero from charts/backup/velero against the CI minio and checks
### that the hourly-cluster schedule keeps the per-cluster kubeconfig token
### CRDs out of backups and restores.

set -euo pipefail

cd $(dirname $0)/../..
source hack/lib.sh

TEST_NAME="Pre-warm Go build cache"
echodate "Attempting to pre-warm Go build cache"

beforeGocache=$(nowms)
make download-gocache
pushElapsed gocache_download_duration_milliseconds $beforeGocache

export KIND_CLUSTER_NAME="${SEED_NAME:-kubermatic}"

source hack/ci/setup-kind-cluster.sh

# gather the logs of all things in the Kubermatic namespace
protokol --kubeconfig "$KUBECONFIG" --flat --output "$ARTIFACTS/logs/kubermatic" --namespace kubermatic > /dev/null 2>&1 &

# installs KKP, the minio used as backup destination, the kkpbackupe2e bucket
# and the kube-system/backup-s3 credentials; also exports CUSTOM_CA_CERT, the
# CA that signed the minio TLS certificate
source hack/ci/setup-kubermatic-backups-in-kind.sh

echodate "Installing Velero from charts/backup/velero..."

kubectl create namespace velero

kubectl create secret generic velero-minio-ca --from-file=ca.crt="$CUSTOM_CA_CERT" --namespace velero

# the minio access keys are the ones configured for the CI minio in
# setup-kubermatic-backups-in-kind.sh (also in hack/ci/testdata/backup_s3_creds.yaml)
VELERO_VALUES="$(mktemp)"
cat << EOF > $VELERO_VALUES
velero:
  backupsEnabled: true
  initContainers:
    - name: velero-plugin-for-aws
      image: quay.io/kubermatic-mirror/images/velero-plugin-for-aws:v1.13.2
      volumeMounts:
        - mountPath: /target
          name: plugins
  credentials:
    secretContents:
      cloud: |
        [default]
        aws_access_key_id=FXcD7s0tFOPuTv6jaZARJDouc2Hal8E0
        aws_secret_access_key=wdEZGTnhkgBDTDetaHFuizs3pwXHvWTs
  configuration:
    backupStorageLocation:
      - name: default
        provider: aws
        bucket: kkpbackupe2e
        prefix: velero-e2e
        config:
          region: minio
          s3ForcePathStyle: "true"
          s3Url: https://minio.minio.svc.cluster.local:9000
    extraEnvVars:
      - name: SSL_CERT_FILE
        value: /etc/velero-minio-ca/ca.crt
  extraVolumes:
    - name: minio-ca
      secret:
        secretName: velero-minio-ca
  extraVolumeMounts:
    - name: minio-ca
      mountPath: /etc/velero-minio-ca
      readOnly: true
EOF

helm --namespace velero upgrade --install --wait --values "$VELERO_VALUES" velero charts/backup/velero/

echodate "Waiting for Velero to become available..."
retry 10 kubectl wait --for=condition=available --namespace velero deployment/velero --timeout=60s

echodate "Waiting for BackupStorageLocation to be available..."
retry 10 kubectl get backupstoragelocation default --namespace velero -o jsonpath='{.status.phase}' | grep -q Available

echodate "Running Velero backup e2e tests..."

go_test velero_backup_e2e -timeout 60m -tags e2e -v ./pkg/test/e2e/velero-backup \
  -kubeconfig "$KUBECONFIG"

echodate "Tests completed successfully!"
