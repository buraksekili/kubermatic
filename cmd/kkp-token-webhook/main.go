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

// kkp-token-webhook answers TokenReview requests for the bearer tokens of
// exported kubeconfigs of exactly one user cluster. It runs in the cluster
// namespace on the seed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/zapr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.uber.org/zap"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	kubermaticlog "k8c.io/kubermatic/v2/pkg/log"
	"k8c.io/kubermatic/v2/pkg/token-webhook"
	"k8c.io/kubermatic/v2/pkg/version/kubermatic"

	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlruntimecluster "sigs.k8s.io/controller-runtime/pkg/cluster"
	ctrlruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"golang.org/x/sync/errgroup"
)

type options struct {
	clusterID        string
	clusterUID       string
	namespace        string
	listenAddress    string
	healthAddress    string
	tlsCertFile      string
	tlsKeyFile       string
	clientCAFile     string
	clientCommonName string
	groupPrefix      string
	clockSkew        time.Duration
	maxStaleness     time.Duration
	idleTimeout      time.Duration
	lastUsedInterval time.Duration
	kubeconfig       string

	log kubermaticlog.Options
}

func (o *options) addFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.clusterID, "cluster-id", "", "name of the cluster this webhook serves; tokens of other clusters are rejected")
	fs.StringVar(&o.clusterUID, "cluster-uid", "", "UID of the cluster; tokens issued for a previous cluster with the same name are rejected")
	fs.StringVar(&o.namespace, "namespace", "", "the cluster namespace to read UserClusterTokens and UserClusterAttributes from")
	fs.StringVar(&o.listenAddress, "listen-address", ":8443", "HTTPS address the TokenReview endpoint listens on")
	fs.StringVar(&o.healthAddress, "health-address", ":8080", "plain HTTP address for /healthz, /readyz and /metrics")
	fs.StringVar(&o.tlsCertFile, "tls-cert-file", "", "path to the serving certificate")
	fs.StringVar(&o.tlsKeyFile, "tls-key-file", "", "path to the serving key")
	fs.StringVar(&o.clientCAFile, "client-ca-file", "", "path to the CA that signs the kube-apiserver client certificate")
	fs.StringVar(&o.clientCommonName, "client-common-name", "kkp-token-webhook-client", "required CN of the kube-apiserver client certificate")
	fs.StringVar(&o.groupPrefix, "group-prefix", "oidc:", "prefix added to every identity provider group")
	fs.DurationVar(&o.clockSkew, "clock-skew", 30*time.Second, "how far past its expiration a token is still accepted, to tolerate clock skew")
	fs.DurationVar(&o.maxStaleness, "max-staleness", 2*time.Minute, "how old the last confirmed seed API contact may be before the webhook answers 503")
	fs.DurationVar(&o.idleTimeout, "idle-timeout", 24*time.Hour, "reject tokens not used for this long; 0 disables the check")
	fs.DurationVar(&o.lastUsedInterval, "last-used-update-interval", 5*time.Minute, "throttle for status.lastUsedTime writes per token")
	fs.StringVar(&o.kubeconfig, "kubeconfig", "", "path to a kubeconfig for the seed API; empty means in-cluster")

	o.log = kubermaticlog.NewDefaultOptions()
	o.log.AddFlags(fs)
}

func (o *options) validate() error {
	if o.clusterID == "" {
		return errors.New("-cluster-id must be set")
	}
	if !tokenwebhook.ClusterIDRegexp.MatchString(o.clusterID) {
		return fmt.Errorf("-cluster-id %q is not a valid cluster name", o.clusterID)
	}
	if o.clusterUID == "" {
		return errors.New("-cluster-uid must be set")
	}
	if o.namespace == "" {
		return errors.New("-namespace must be set")
	}
	for name, path := range map[string]string{
		"-tls-cert-file":  o.tlsCertFile,
		"-tls-key-file":   o.tlsKeyFile,
		"-client-ca-file": o.clientCAFile,
	} {
		if path == "" {
			return fmt.Errorf("-%s must be set", name)
		}
	}
	if o.maxStaleness <= 0 {
		return errors.New("-max-staleness must be positive")
	}
	return o.log.Validate()
}

func main() {
	opts := options{}
	opts.addFlags(flag.CommandLine)
	flag.Parse()

	if err := opts.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid flags: %v\n", err)
		os.Exit(1)
	}

	rawLog := kubermaticlog.NewFromOptions(opts.log)
	log := rawLog.Sugar()

	// set the logger used by sigs.k8s.io/controller-runtime
	ctrlruntimelog.SetLogger(zapr.NewLogger(rawLog.WithOptions(zap.AddCallerSkip(1))))

	if err := run(signals.SetupSignalHandler(), opts, log); err != nil {
		log.Errorw("shutting down", zap.Error(err))
		_ = rawLog.Sync()
		os.Exit(1)
	}
}

// run wires the stores, both HTTP servers and the prober, and blocks until
// ctx is done. It is split from main so the integration test can drive the
// real wiring against envtest.
func run(ctx context.Context, opts options, log *zap.SugaredLogger) error {
	restConfig, err := clientcmd.BuildConfigFromFlags("", opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("getting seed kubeconfig: %w", err)
	}

	if err := kubermaticv1.AddToScheme(scheme.Scheme); err != nil {
		return fmt.Errorf("registering kubermatic scheme: %w", err)
	}

	cluster, err := ctrlruntimecluster.New(restConfig, func(o *ctrlruntimecluster.Options) {
		o.Scheme = scheme.Scheme
		// the webhook ServiceAccount may read only its own cluster namespace,
		// so the caches must not try to list cluster-wide
		o.Cache.DefaultNamespaces = map[string]cache.Config{opts.namespace: {}}
	})
	if err != nil {
		return fmt.Errorf("creating cluster object: %w", err)
	}

	store, err := tokenwebhook.NewInformerStore(ctx, opts.namespace, cluster, log)
	if err != nil {
		return fmt.Errorf("setting up informer store: %w", err)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	metrics := tokenwebhook.NewMetrics(registry)

	authenticator := tokenwebhook.NewAuthenticator(opts.namespace, tokenwebhook.AuthenticatorConfig{
		ClusterID:        opts.clusterID,
		ClusterUID:       opts.clusterUID,
		GroupPrefix:      opts.groupPrefix,
		ClockSkew:        opts.clockSkew,
		IdleTimeout:      opts.idleTimeout,
		MaxStaleness:     opts.maxStaleness,
		LastUsedInterval: opts.lastUsedInterval,
		Store:            store,
		Writer:           tokenwebhook.NewLastUsedPatchWriter(cluster.GetClient()),
		Metrics:          metrics,
		Log:              log,
	})

	server := &tokenwebhook.Server{
		Authenticator: authenticator,
		Metrics:       metrics,
		Log:           log,
		Ready: func() bool {
			return store.HasSynced() && time.Since(store.LastContact()) <= opts.maxStaleness
		},
	}

	tlsConfig, err := tokenwebhook.NewTLSConfig(opts.tlsCertFile, opts.tlsKeyFile, opts.clientCAFile, opts.clientCommonName)
	if err != nil {
		return fmt.Errorf("setting up TLS: %w", err)
	}

	reviewMux := http.NewServeMux()
	server.RegisterTokenReview(reviewMux)
	reviewServer := &http.Server{
		Addr:              opts.listenAddress,
		Handler:           reviewMux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	healthMux := http.NewServeMux()
	server.RegisterHealth(healthMux, registry)
	healthServer := &http.Server{
		Addr:              opts.healthAddress,
		Handler:           healthMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// probe the seed API at a quarter of the staleness window, clamped to a
	// sane range, so a healthy webhook refreshes its contact several times
	// before the window closes
	probeInterval := opts.maxStaleness / 4
	probeInterval = min(max(probeInterval, 10*time.Second), 60*time.Second)

	versions := kubermatic.GetVersions()
	log.With(
		"cluster", opts.clusterID,
		"namespace", opts.namespace,
		"listenAddress", opts.listenAddress,
		"healthAddress", opts.healthAddress,
		"version", versions.GitVersion,
	).Info("starting kkp-token-webhook")

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := cluster.GetCache().Start(ctx); err != nil {
			return fmt.Errorf("starting cache: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		tokenwebhook.StartProber(ctx, probeInterval, 10*time.Second, cluster.GetAPIReader(), store, metrics, log)
		return nil
	})
	g.Go(func() error {
		if !cluster.GetCache().WaitForCacheSync(ctx) {
			// a canceled context is a normal shutdown, not a cache failure
			return ctx.Err()
		}
		log.Info("informer caches synced")
		return nil
	})
	g.Go(func() error {
		if err := reviewServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("token review server: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("health server: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = reviewServer.Shutdown(shutdownCtx)
		_ = healthServer.Shutdown(shutdownCtx)

		return nil
	})

	return g.Wait()
}
