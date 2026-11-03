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
	"fmt"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	"k8s.io/client-go/tools/cache"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimecluster "sigs.k8s.io/controller-runtime/pkg/cluster"

	"go.uber.org/zap"
)

// NewInformerStore builds the CacheStore on the informers of a controller-
// runtime cluster. The cluster options must restrict the cache to namespace
// (DefaultNamespaces), because the webhook ServiceAccount may only read its
// own cluster namespace.
//
// The informers are created before the cache starts, so starting the cache
// afterwards syncs exactly these two types. Every watch event marks contact
// with the seed API, which keeps the staleness window short while the watch
// is delivering events.
func NewInformerStore(ctx context.Context, namespace string, cluster ctrlruntimecluster.Cluster, log *zap.SugaredLogger) (*CacheStore, error) {
	store := &CacheStore{namespace: namespace, reader: cluster.GetClient()}

	for _, watch := range []struct {
		name     string
		obj      ctrlruntimeclient.Object
		informer *informerState
	}{
		{"UserClusterToken", &kubermaticv1.UserClusterToken{}, &store.tokenInformer},
		{"UserClusterAttribute", &kubermaticv1.UserClusterAttribute{}, &store.attributeInformer},
	} {
		informer, err := cluster.GetCache().GetInformer(ctx, watch.obj)
		if err != nil {
			return nil, fmt.Errorf("getting %s informer: %w", watch.name, err)
		}

		_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { store.MarkContact(time.Now()) },
			UpdateFunc: func(_, _ any) { store.MarkContact(time.Now()) },
			DeleteFunc: func(obj any) { store.MarkContact(time.Now()) },
		})
		if err != nil {
			return nil, fmt.Errorf("registering %s event handler: %w", watch.name, err)
		}

		*watch.informer = informer
	}

	log.Debugw("token informers registered", "namespace", namespace)

	return store, nil
}

// StartProber lists one token straight from the seed API through the uncached
// reader every interval. A successful list proves the API is reachable and
// marks contact on the store; a namespace with no events at all would
// otherwise look stale even with a healthy watch. The cache size gauges are
// refreshed on the same loop. It blocks until ctx is done.
func StartProber(ctx context.Context, interval, timeout time.Duration, reader ctrlruntimeclient.Reader, store *CacheStore, metrics *Metrics, log *zap.SugaredLogger) {
	onSuccess := func() {
		now := time.Now()
		store.MarkContact(now)

		tokens, attributes := store.CacheSizes()
		metrics.ObserveCacheSize("userclustertokens", tokens)
		metrics.ObserveCacheSize("userclusterattributes", attributes)
	}

	listOne := func(ctx context.Context) error {
		tokens := &kubermaticv1.UserClusterTokenList{}
		return reader.List(ctx, tokens, ctrlruntimeclient.InNamespace(store.namespace), ctrlruntimeclient.Limit(1))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// an immediate first probe shortens the not-ready window at startup
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	if err := listOne(probeCtx); err != nil {
		log.Warnw("seed API probe failed", zap.Error(err))
	} else {
		onSuccess()
	}
	cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			err := listOne(probeCtx)
			cancel()
			if err != nil {
				log.Warnw("seed API probe failed", zap.Error(err))
				continue
			}
			onSuccess()
		}
	}
}
