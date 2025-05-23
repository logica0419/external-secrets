/*
Copyright © 2022 ESO Maintainer Team

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

package controller

import (
	"os"
	"time"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
	"github.com/external-secrets/external-secrets/pkg/controllers/clusterexternalsecret"
	"github.com/external-secrets/external-secrets/pkg/controllers/clusterexternalsecret/cesmetrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/clusterpushsecret"
	"github.com/external-secrets/external-secrets/pkg/controllers/clusterpushsecret/cpsmetrics"
	ctrlcommon "github.com/external-secrets/external-secrets/pkg/controllers/common"
	"github.com/external-secrets/external-secrets/pkg/controllers/externalsecret"
	"github.com/external-secrets/external-secrets/pkg/controllers/externalsecret/esmetrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/generatorstate"
	ctrlmetrics "github.com/external-secrets/external-secrets/pkg/controllers/metrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/pushsecret"
	"github.com/external-secrets/external-secrets/pkg/controllers/pushsecret/psmetrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore"
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore/cssmetrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore/ssmetrics"
	"github.com/external-secrets/external-secrets/pkg/feature"

	// To allow using gcp auth.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var (
	scheme                                = runtime.NewScheme()
	setupLog                              = ctrl.Log.WithName("setup")
	dnsName                               string
	certDir                               string
	metricsAddr                           string
	healthzAddr                           string
	controllerClass                       string
	enableLeaderElection                  bool
	enableSecretsCache                    bool
	enableConfigMapsCache                 bool
	enableManagedSecretsCache             bool
	enablePartialCache                    bool
	concurrent                            int
	port                                  int
	clientQPS                             float32
	clientBurst                           int
	loglevel                              string
	zapTimeEncoding                       string
	namespace                             string
	enableClusterStoreReconciler          bool
	enableClusterExternalSecretReconciler bool
	enableClusterPushSecretReconciler     bool
	enablePushSecretReconciler            bool
	enableFloodGate                       bool
	enableGeneratorState                  bool
	enableExtendedMetricLabels            bool
	storeRequeueInterval                  time.Duration
	serviceName, serviceNamespace         string
	secretName, secretNamespace           string
	crdNames                              []string
	crdRequeueInterval                    time.Duration
	certCheckInterval                     time.Duration
	certLookaheadInterval                 time.Duration
	tlsCiphers                            string
	tlsMinVersion                         string
)

const (
	errCreateController = "unable to create controller"
)

func init() {
	// kubernetes schemes
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))

	// external-secrets schemes
	utilruntime.Must(esv1.AddToScheme(scheme))
	utilruntime.Must(esv1alpha1.AddToScheme(scheme))
	utilruntime.Must(genv1alpha1.AddToScheme(scheme))
}

var rootCmd = &cobra.Command{
	Use:   "external-secrets",
	Short: "operator that reconciles ExternalSecrets and SecretStores",
	Long:  `For more information visit https://external-secrets.io`,
	Run: func(cmd *cobra.Command, args []string) {
		setupLogger()

		ctrlmetrics.SetUpLabelNames(enableExtendedMetricLabels)
		esmetrics.SetUpMetrics()
		config := ctrl.GetConfigOrDie()
		config.QPS = clientQPS
		config.Burst = clientBurst

		// the client creates a ListWatch for resources that are requested with .Get() or .List()
		// some users might want to completely disable caching of Secrets and ConfigMaps
		// to decrease memory usage at the expense of high Kubernetes API usage
		// see: https://github.com/external-secrets/external-secrets/issues/721
		clientCacheDisableFor := make([]client.Object, 0)
		if !enableSecretsCache {
			// dont cache any secrets
			clientCacheDisableFor = append(clientCacheDisableFor, &v1.Secret{})
		}
		if !enableConfigMapsCache {
			// dont cache any configmaps
			clientCacheDisableFor = append(clientCacheDisableFor, &v1.ConfigMap{})
		}

		mgrOpts := ctrl.Options{
			Scheme: scheme,
			Metrics: server.Options{
				BindAddress: metricsAddr,
			},
			WebhookServer: webhook.NewServer(webhook.Options{
				Port: 9443,
			}),
			Client: client.Options{
				Cache: &client.CacheOptions{
					DisableFor: clientCacheDisableFor,
				},
			},
			LeaderElection:   enableLeaderElection,
			LeaderElectionID: "external-secrets-controller",
		}
		if namespace != "" {
			mgrOpts.Cache.DefaultNamespaces = map[string]cache.Config{
				namespace: {},
			}
		}
		mgr, err := ctrl.NewManager(config, mgrOpts)
		if err != nil {
			setupLog.Error(err, "unable to start manager")
			os.Exit(1)
		}

		// we create a special client for accessing secrets in the ExternalSecret reconcile loop.
		// by default, it is the same as the normal client, but if `--enable-managed-secrets-caching`
		// is set, we use a special client that only caches secrets managed by an ExternalSecret.
		// if we are already caching all secrets, we don't need to use the special client.
		secretClient := mgr.GetClient()
		if enableManagedSecretsCache && !enableSecretsCache {
			secretClient, err = ctrlcommon.BuildManagedSecretClient(mgr, namespace)
			if err != nil {
				setupLog.Error(err, "unable to create managed secret client")
				os.Exit(1)
			}
		}

		ssmetrics.SetUpMetrics()
		if err = (&secretstore.StoreReconciler{
			Client:          mgr.GetClient(),
			Log:             ctrl.Log.WithName("controllers").WithName("SecretStore"),
			Scheme:          mgr.GetScheme(),
			ControllerClass: controllerClass,
			RequeueInterval: storeRequeueInterval,
		}).SetupWithManager(mgr, controller.Options{
			MaxConcurrentReconciles: concurrent,
			RateLimiter:             ctrlcommon.BuildRateLimiter(),
		}); err != nil {
			setupLog.Error(err, errCreateController, "controller", "SecretStore")
			os.Exit(1)
		}
		if enableClusterStoreReconciler {
			cssmetrics.SetUpMetrics()
			if err = (&secretstore.ClusterStoreReconciler{
				Client:          mgr.GetClient(),
				Log:             ctrl.Log.WithName("controllers").WithName("ClusterSecretStore"),
				Scheme:          mgr.GetScheme(),
				ControllerClass: controllerClass,
				RequeueInterval: storeRequeueInterval,
			}).SetupWithManager(mgr, controller.Options{
				MaxConcurrentReconciles: concurrent,
				RateLimiter:             ctrlcommon.BuildRateLimiter(),
			}); err != nil {
				setupLog.Error(err, errCreateController, "controller", "ClusterSecretStore")
				os.Exit(1)
			}
		}
		if err = (&generatorstate.Reconciler{
			Client:     mgr.GetClient(),
			Log:        ctrl.Log.WithName("controllers").WithName("GeneratorState"),
			Scheme:     mgr.GetScheme(),
			RestConfig: mgr.GetConfig(),
		}).SetupWithManager(mgr, controller.Options{
			MaxConcurrentReconciles: concurrent,
			RateLimiter:             ctrlcommon.BuildRateLimiter(),
		}); err != nil {
			setupLog.Error(err, errCreateController, "controller", "GeneratorState")
			os.Exit(1)
		}
		if err = (&externalsecret.Reconciler{
			Client:                    mgr.GetClient(),
			SecretClient:              secretClient,
			Log:                       ctrl.Log.WithName("controllers").WithName("ExternalSecret"),
			Scheme:                    mgr.GetScheme(),
			RestConfig:                mgr.GetConfig(),
			ControllerClass:           controllerClass,
			RequeueInterval:           time.Hour,
			ClusterSecretStoreEnabled: enableClusterStoreReconciler,
			EnableFloodGate:           enableFloodGate,
			EnableGeneratorState:      enableGeneratorState,
		}).SetupWithManager(mgr, controller.Options{
			MaxConcurrentReconciles: concurrent,
			RateLimiter:             ctrlcommon.BuildRateLimiter(),
		}); err != nil {
			setupLog.Error(err, errCreateController, "controller", "ExternalSecret")
			os.Exit(1)
		}
		if enablePushSecretReconciler {
			psmetrics.SetUpMetrics()
			if err = (&pushsecret.Reconciler{
				Client:          mgr.GetClient(),
				Log:             ctrl.Log.WithName("controllers").WithName("PushSecret"),
				Scheme:          mgr.GetScheme(),
				ControllerClass: controllerClass,
				RestConfig:      mgr.GetConfig(),
				RequeueInterval: time.Hour,
			}).SetupWithManager(mgr, controller.Options{
				MaxConcurrentReconciles: concurrent,
				RateLimiter:             ctrlcommon.BuildRateLimiter(),
			}); err != nil {
				setupLog.Error(err, errCreateController, "controller", "PushSecret")
				os.Exit(1)
			}
		}
		if enableClusterExternalSecretReconciler {
			cesmetrics.SetUpMetrics()

			if err = (&clusterexternalsecret.Reconciler{
				Client:          mgr.GetClient(),
				Log:             ctrl.Log.WithName("controllers").WithName("ClusterExternalSecret"),
				Scheme:          mgr.GetScheme(),
				RequeueInterval: time.Hour,
			}).SetupWithManager(mgr, controller.Options{
				MaxConcurrentReconciles: concurrent,
				RateLimiter:             ctrlcommon.BuildRateLimiter(),
			}); err != nil {
				setupLog.Error(err, errCreateController, "controller", "ClusterExternalSecret")
				os.Exit(1)
			}
		}

		if enableClusterPushSecretReconciler {
			cpsmetrics.SetUpMetrics()

			if err = (&clusterpushsecret.Reconciler{
				Client:          mgr.GetClient(),
				Log:             ctrl.Log.WithName("controllers").WithName("ClusterPushSecret"),
				Scheme:          mgr.GetScheme(),
				RequeueInterval: time.Hour,
				Recorder:        mgr.GetEventRecorderFor("external-secrets-controller"),
			}).SetupWithManager(mgr, controller.Options{
				MaxConcurrentReconciles: concurrent,
			}); err != nil {
				setupLog.Error(err, errCreateController, "controller", "ClusterPushSecret")
				os.Exit(1)
			}
		}

		fs := feature.Features()
		for _, f := range fs {
			if f.Initialize == nil {
				continue
			}
			f.Initialize()
		}
		setupLog.Info("starting manager")
		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	rootCmd.Flags().StringVar(&controllerClass, "controller-class", "default", "The controller is instantiated with a specific controller name and filters ES based on this property")
	rootCmd.Flags().BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	rootCmd.Flags().IntVar(&concurrent, "concurrent", 1, "The number of concurrent reconciles.")
	rootCmd.Flags().Float32Var(&clientQPS, "client-qps", 50, "QPS configuration to be passed to rest.Client")
	rootCmd.Flags().IntVar(&clientBurst, "client-burst", 100, "Maximum Burst allowed to be passed to rest.Client")
	rootCmd.Flags().StringVar(&loglevel, "loglevel", "info", "loglevel to use, one of: debug, info, warn, error, dpanic, panic, fatal")
	rootCmd.Flags().StringVar(&zapTimeEncoding, "zap-time-encoding", "epoch", "Zap time encoding (one of 'epoch', 'millis', 'nano', 'iso8601', 'rfc3339' or 'rfc3339nano')")
	rootCmd.Flags().StringVar(&namespace, "namespace", "", "watch external secrets scoped in the provided namespace only. ClusterSecretStore can be used but only work if it doesn't reference resources from other namespaces")
	rootCmd.Flags().BoolVar(&enableClusterStoreReconciler, "enable-cluster-store-reconciler", true, "Enable cluster store reconciler.")
	rootCmd.Flags().BoolVar(&enableClusterExternalSecretReconciler, "enable-cluster-external-secret-reconciler", true, "Enable cluster external secret reconciler.")
	rootCmd.Flags().BoolVar(&enableClusterPushSecretReconciler, "enable-cluster-push-secret-reconciler", true, "Enable cluster push secret reconciler.")
	rootCmd.Flags().BoolVar(&enablePushSecretReconciler, "enable-push-secret-reconciler", true, "Enable push secret reconciler.")
	rootCmd.Flags().BoolVar(&enableSecretsCache, "enable-secrets-caching", false, "Enable secrets caching for ALL secrets in the cluster (WARNING: can increase memory usage).")
	rootCmd.Flags().BoolVar(&enableConfigMapsCache, "enable-configmaps-caching", false, "Enable configmaps caching for ALL configmaps in the cluster (WARNING: can increase memory usage).")
	rootCmd.Flags().BoolVar(&enableManagedSecretsCache, "enable-managed-secrets-caching", true, "Enable secrets caching for secrets managed by an ExternalSecret")
	rootCmd.Flags().DurationVar(&storeRequeueInterval, "store-requeue-interval", time.Minute*5, "Default Time duration between reconciling (Cluster)SecretStores")
	rootCmd.Flags().BoolVar(&enableFloodGate, "enable-flood-gate", true, "Enable flood gate. External secret will be reconciled only if the ClusterStore or Store have an healthy or unknown state.")
	rootCmd.Flags().BoolVar(&enableGeneratorState, "enable-generator-state", true, "Whether the Controller should manage GeneratorState")
	rootCmd.Flags().BoolVar(&enableExtendedMetricLabels, "enable-extended-metric-labels", false, "Enable recommended kubernetes annotations as labels in metrics.")
	fs := feature.Features()
	for _, f := range fs {
		rootCmd.Flags().AddFlagSet(f.Flags)
	}
}
