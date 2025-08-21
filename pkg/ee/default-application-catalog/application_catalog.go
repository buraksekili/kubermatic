/*
                  Kubermatic Enterprise Read-Only License
                         Version 1.0 ("KERO-1.0”)
                     Copyright © 2023 Kubermatic GmbH

   1.	You may only view, read and display for studying purposes the source
      code of the software licensed under this license, and, to the extent
      explicitly provided under this license, the binary code.
   2.	Any use of the software which exceeds the foregoing right, including,
      without limitation, its execution, compilation, copying, modification
      and distribution, is expressly prohibited.
   3.	THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
      EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
      MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
      IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
      CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
      TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
      SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

   END OF TERMS AND CONDITIONS
*/

package applicationcatalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"go.uber.org/zap"
	"io"
	appskubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/apps.kubermatic/v1"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/applications/providers/util"
	"k8c.io/kubermatic/v2/pkg/features"
	"k8c.io/kubermatic/v2/pkg/kubernetes"
	kkpreconciling "k8c.io/kubermatic/v2/pkg/resources/reconciling"
	"k8c.io/kubermatic/v2/pkg/resources/registry"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

func DefaultApplicationCatalogReconcilerFactories(
	logger *zap.SugaredLogger,
	config *kubermaticv1.KubermaticConfiguration,
	mirror bool,
) ([]kkpreconciling.NamedApplicationDefinitionReconcilerFactory, error) {
	if !config.Spec.Applications.DefaultApplicationCatalog.Enable {
		logger.Info("Default application catalog is disabled, skipping deployment of default application definitions.")
		return nil, nil
	}

	appDefFiles, err := GetAppDefFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ApplicationDefinitions: %w", err)
	}

	filterApps := len(config.Spec.Applications.DefaultApplicationCatalog.Applications) > 0
	requestedApps := make(map[string]struct{})
	if filterApps {
		for _, appName := range config.Spec.Applications.DefaultApplicationCatalog.Applications {
			requestedApps[appName] = struct{}{}
		}

		logger.Debugf("Installing only specified system applications: %+v", config.Spec.Applications.DefaultApplicationCatalog.Applications)
	}

	creators := make([]kkpreconciling.NamedApplicationDefinitionReconcilerFactory, 0, len(appDefFiles))
	for _, file := range appDefFiles {
		b, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read ApplicationDefinition: %w", err)
		}

		appDef := &appskubermaticv1.ApplicationDefinition{}
		err = yaml.Unmarshal(b, appDef)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ApplicationDefinition: %w", err)
		}

		if filterApps {
			if _, ok := requestedApps[appDef.Name]; !ok {
				logger.Debugf("Skipping application %q as it's not in the requested list", appDef.Name)
				continue
			}
		}
		creators = append(creators, applicationDefinitionReconcilerFactory(appDef, config, mirror))
	}
	return creators, nil
}

func applicationDefinitionReconcilerFactory(appDef *appskubermaticv1.ApplicationDefinition, config *kubermaticv1.KubermaticConfiguration, mirror bool) kkpreconciling.NamedApplicationDefinitionReconcilerFactory {
	return func() (string, kkpreconciling.ApplicationDefinitionReconciler) {
		return appDef.Name, func(a *appskubermaticv1.ApplicationDefinition) (*appskubermaticv1.ApplicationDefinition, error) {
			// Labels and annotations specified in the ApplicationDefinition installed on the cluster are merged with the ones specified in the ApplicationDefinition
			// that is generated from the default application catalog.
			kubernetes.EnsureLabels(a, appDef.Labels)
			kubernetes.EnsureAnnotations(a, appDef.Annotations)

			// State of the following fields in the cluster has a higher precedence than the one coming from the default application catalog.
			if a.Spec.Enforced {
				appDef.Spec.Enforced = true
			}

			if a.Spec.Default {
				appDef.Spec.Default = true
			}

			if a.Spec.Selector.Datacenters != nil {
				appDef.Spec.Selector.Datacenters = a.Spec.Selector.Datacenters
			}

			// Update the application definition (fileAppDef) based on the KubermaticConfiguration.
			// If the KubermaticConfiguration includes HelmRegistryConfigFile, update the application
			// definition to incorporate the Helm credentials provided by the user in the cluster.
			//
			// When running mirror-images, leave the application definition unchanged. This ensures
			// that charts are downloaded from the default upstream repositories used by KKP,
			// preserving the original image references for discovery.
			if !mirror {
				updateApplicationDefinition(appDef, config)
			}

			a.Spec = appDef.Spec
			return a, nil
		}
	}
}

func updateApplicationDefinition(appDef *appskubermaticv1.ApplicationDefinition, config *kubermaticv1.KubermaticConfiguration) {
	if config == nil || appDef == nil {
		return
	}

	var credentials *appskubermaticv1.HelmCredentials
	appConfig := config.Spec.Applications.DefaultApplicationCatalog
	if appConfig.HelmRegistryConfigFile != nil {
		credentials = &appskubermaticv1.HelmCredentials{
			RegistryConfigFile: appConfig.HelmRegistryConfigFile,
		}
	}

	for i := range appDef.Spec.Versions {
		if appConfig.HelmRepository != "" {
			appDef.Spec.Versions[i].Template.Source.Helm.URL = registry.ToOCIURL(appConfig.HelmRepository)
		}

		if credentials != nil {
			appDef.Spec.Versions[i].Template.Source.Helm.Credentials = credentials
		}
	}
}

func ApplicationCatalogFromExternalManager(
	ctx context.Context,
	logger *zap.SugaredLogger,
	client ctrlruntimeclient.Client,
	config *kubermaticv1.KubermaticConfiguration,
	mirror bool,
) ([]kkpreconciling.NamedApplicationDefinitionReconcilerFactory, error) {
	if !config.Spec.FeatureGates[features.ExternalApplicationDefinitionManager] {
		return nil, fmt.Errorf("ApplicationDefinition is not managed by external application catalog manager")
	}

	registrySettings := config.Spec.Applications.Manager.RegistrySettings
	if registrySettings.RegistryURL == "" {
		return nil, fmt.Errorf("registry URL is not defined, its required while using external application catalog manager")
	}

	to := 2 * time.Minute

	ociCtx, ociCtxCancel := context.WithTimeout(ctx, to)
	defer ociCtxCancel()

	repo, err := remote.NewRepository(registrySettings.RegistryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create ORAS repository: %w", err)
	}

	if isInternalRegistry(registrySettings.RegistryURL) {
		repo.PlainHTTP = true
	}

	credentials, err := OrasAuth(
		ctx,
		client,
		"kubermatic",
		registrySettings.Credentials,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ORAS registry client: %w", err)
	}

	repo.Client = &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Registry, *credentials),
	}

	memStore := memory.New()

	manifest, err := oras.Copy(ociCtx, repo, registrySettings.RegistryURL, memStore, registrySettings.Tag, oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{
			PreCopy: func(ctx context.Context, desc ocispec.Descriptor) error {
				if desc.MediaType == ocispec.MediaTypeImageLayerGzip || desc.MediaType == ocispec.MediaTypeImageManifest {
					return nil
				}

				return oras.SkipNode
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to copy OCI artifact: %w", err)
	}

	manifestBlob, err := content.FetchAll(ociCtx, memStore, manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCI artifact manifest: %w", err)
	}

	var manifestJSON ocispec.Manifest
	err = json.Unmarshal(manifestBlob, &manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OCI artifact manifest: %w", err)
	}

	found := false
	var applicationsDirLayer *ocispec.Descriptor
	for _, layer := range manifestJSON.Layers {
		if layer.MediaType == ocispec.MediaTypeImageLayerGzip &&
			layer.Annotations["org.opencontainers.image.title"] == "applications" {
			if found {
				return nil, fmt.Errorf("multiple OCI artifacts found")
			}

			found = true
			applicationsDirLayer = &layer
		}
	}
	if applicationsDirLayer == nil {
		return nil, fmt.Errorf("no applications found in OCI artifact manifest")
	}

	applicationTar, err := content.FetchAll(ociCtx, memStore, *applicationsDirLayer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCI artifact manifest: %w", err)
	}

	applicationTarReader, err := gzip.NewReader(bytes.NewReader(applicationTar))
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip application artifact: %w", err)
	}

	defer func() {
		if readerErr := applicationTarReader.Close(); readerErr != nil {
			logger.Warn("failed to close application artifact gzip reader", zap.Error(readerErr))
		}
	}()
	tarReader := tar.NewReader(applicationTarReader)

	apps := make(map[string]appskubermaticv1.ApplicationDefinition)
	tiers := make(map[string]string)

	var errs []error
	for {
		header, err := tarReader.Next()
		if err == io.EOF { //nolint:errorlint
			break
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read tar header: %w", err))
			break
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		parts := strings.Split(header.Name, "/")
		if len(parts) != 3 || parts[0] != "applications" {
			continue
		}

		appName := parts[1]
		fileName := parts[2]

		contentBytes, err := io.ReadAll(tarReader)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if fileName == "application.yaml" {
			appDefFromOCI := appskubermaticv1.ApplicationDefinition{}
			err = yaml.Unmarshal(contentBytes, &appDefFromOCI)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to parse application.yaml: %w", err))
				continue
			}

			apps[appName] = appDefFromOCI
		} else if fileName == "metadata.yaml" {
			md := struct {
				Tier string `json:"tier"`
			}{}

			err = yaml.Unmarshal(contentBytes, &md)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to parse metadata.yaml: %w", err))
				continue
			}

			tiers[appName] = md.Tier
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("failed to read application definition manifests: %w", kerrors.NewAggregate(errs))
	}

	filteringOpts := config.Spec.Applications.Manager.ApplicationFiltering.FromRegistry

	creators := make([]kkpreconciling.NamedApplicationDefinitionReconcilerFactory, 0)

	hasNameFilter := len(filteringOpts.NameSelector) > 0
	hasTierFilter := len(filteringOpts.MetadataSelector.Tiers) > 0

	desiredAppsMap := make(map[string]struct{})
	if hasNameFilter {
		for _, name := range filteringOpts.NameSelector {
			desiredAppsMap[name] = struct{}{}
		}

		logger.Debugf("Name filter active: %v", filteringOpts.NameSelector)
	}

	expectedTiersSet := make(map[string]struct{})
	if hasTierFilter {
		for _, tier := range filteringOpts.MetadataSelector.Tiers {
			expectedTiersSet[tier] = struct{}{}
		}

		logger.Debugf("Tier filter active: %v", filteringOpts.MetadataSelector.Tiers)
	}

	includedCount := 0
	for appName, appDef := range apps {
		includeApp := true

		if hasNameFilter {
			if _, nameMatches := desiredAppsMap[appName]; !nameMatches {
				includeApp = false
				logger.Debugf("Application %q excluded by name filter", appName)
			}
		}

		if includeApp && hasTierFilter {
			appTier := tiers[appName]
			if _, tierMatches := expectedTiersSet[appTier]; !tierMatches {
				includeApp = false
				logger.Debugf("Application %q (tier: %s) excluded by tier filter", appName, appTier)
			}
		}

		if includeApp {
			includedCount++
			logger.Debugf("Including application %q (tier: %s)", appName, tiers[appName])
			appDefCopy := appDef
			creators = append(creators, applicationDefinitionReconcilerFactory(&appDefCopy, config, mirror))
		}
	}

	if hasNameFilter || hasTierFilter {
		logger.Infof("Filtering complete: %d/%d applications included", includedCount, len(apps))
	} else {
		logger.Infof("No filters configured: including all %d applications", len(apps))
	}

	return creators, nil
}

func OrasAuth(
	ctx context.Context,
	client ctrlruntimeclient.Client,
	s string,
	credentials *kubermaticv1.RegistryCredentials,
) (*auth.Credential, error) {
	if credentials == nil {
		return &auth.EmptyCredential, nil
	}

	var username, password string
	var err error

	if credentials.Username != nil {
		username, err = util.GetCredentialFromSecret(ctx, client, s, credentials.Username.Name, credentials.Username.Key)
		if err != nil {
			return nil, err
		}
	}

	if credentials.Password != nil {
		password, err = util.GetCredentialFromSecret(ctx, client, s, credentials.Password.Name, credentials.Password.Key)
		if err != nil {
			return nil, err
		}
	}

	return &auth.Credential{
		Username: username,
		Password: password,
	}, nil

}

func isInternalRegistry(url string) bool {
	return false
}
