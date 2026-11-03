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

set -euo pipefail

# The per-cluster kubeconfig token CRDs must never be part of the default
# hourly-cluster backup. Restoring a backup that contains them resurrects
# tokens that were revoked after the backup was taken (the revocation objects
# are rolled back with everything else). If this test fails, re-add the
# missing kinds to velero.schedules.hourly-cluster.template.excludedResources
# in values.yaml.

cd "$(dirname "$0")/.."

required=(
  userclustertokenissuances.kubermatic.k8c.io
  userclustertokenrevocations.kubermatic.k8c.io
  userclustertokens.kubermatic.k8c.io
  userclusterattributes.kubermatic.k8c.io
)

failed=0
for kind in "${required[@]}"; do
  if ! KIND="${kind}" yq -e '.velero.schedules["hourly-cluster"].template.excludedResources | contains([env(KIND)])' values.yaml > /dev/null; then
    echo "FAIL: ${kind} is missing from the hourly-cluster schedule's excludedResources." >&2
    failed=1
  fi
done

if [ ${failed} -ne 0 ]; then
  echo "Per-cluster kubeconfig tokens must not be backed up; see the comment above excludedResources in charts/backup/velero/values.yaml." >&2
  exit 1
fi

echo "PASS: hourly-cluster schedule excludes all per-cluster token kinds."
