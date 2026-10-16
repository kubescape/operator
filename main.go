package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/probes"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/otelsetup"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/cloudmetadata"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/watcher/dynamicwatcher"
	admissioncel "github.com/kubescape/operator/admission/cel"
	exporters "github.com/kubescape/operator/admission/exporter"
	rulebindingcachev1 "github.com/kubescape/operator/admission/rulebinding/cache"
	celrules "github.com/kubescape/operator/admission/rules/cel"
	"github.com/kubescape/operator/admission/rulesupdate"
	"github.com/kubescape/operator/admission/ruleswatcher"
	"github.com/kubescape/operator/admission/webhook"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler"
	"github.com/kubescape/operator/nodeagentautoscaler"
	"github.com/kubescape/operator/objectcache"
	"github.com/kubescape/operator/restapihandler"
	"github.com/kubescape/operator/servicehandler"
	"github.com/kubescape/operator/telemetry"
	"github.com/kubescape/operator/utils"
	"github.com/kubescape/operator/watcher"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
)

//go:generate swagger generate spec -o ./docs/swagger.yaml
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	flag.Parse()

	isReadinessReady := false
	go probes.InitReadinessV1(&isReadinessReady)

	clusterConfig, err := config.LoadClusterConfig()
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load clusterData error", helpers.Error(err))
	}

	components, err := config.LoadCapabilitiesConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load components error", helpers.Error(err))
	}

	var credentials *beUtils.Credentials
	if credentials, err = beUtils.LoadCredentialsFromFile("/etc/credentials"); err != nil {
		// Missing credentials are reported after provider and logger initialization.
		credentials = &beUtils.Credentials{}
	}

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	// wrapper for all configs
	operatorConfig, err := config.NewOperatorConfig(components, clusterConfig, credentials, cfg)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("initialize operator config error", helpers.Error(err))
	}
	validationErr := config.ValidateConfig(operatorConfig)

	apiURL := components.Configurations.Server.DiscoveryURL
	if value, ok := os.LookupEnv("API_URL"); ok {
		apiURL = value
	}
	enabled, discoveryErr := telemetry.ConfigureEndpoint(ctx, apiURL)
	shutdown, telemetryErr := telemetry.Init(ctx, otelsetup.ProviderConfig{
		ServiceName: "operator", ServiceVersion: os.Getenv("RELEASE"),
		AccountID: operatorConfig.AccountID(), AccessKey: operatorConfig.AccessKey(),
		ClusterName: operatorConfig.ClusterName(), Namespace: operatorConfig.Namespace(),
		NodeName: os.Getenv("NODE_NAME"), PodName: os.Getenv("POD_NAME"),
	}, enabled)
	logger.InitDefaultLogger()
	if validationErr != nil {
		logger.L().Ctx(ctx).Error("validate config error", helpers.Error(validationErr))
	}
	if credentials.AccessKey == "" {
		logger.L().Warning("operational telemetry has no access key; authenticated backends may reject export")
	}
	if discoveryErr != nil {
		logger.L().Warning("operational telemetry discovery unavailable; continuing")
	}
	if telemetryErr != nil {
		logger.L().Warning("operational telemetry initialization failed; continuing")
	}
	if shutdown != nil {
		defer func() {
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdown(flushCtx)
		}()
	}

	displayBuildTag()
	initHttpHandlers(operatorConfig)
	k8sApi := k8sinterface.NewKubernetesApi()
	restclient.SetDefaultWarningHandler(restclient.NoWarnings{})
	if cfg.NamespaceFilterConfigMapName != "" {
		filterWatcher, err := watcher.NewNamespaceFilterWatcher(k8sApi.KubernetesClient, operatorConfig, cfg.NamespaceFilterConfigMapName)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("initialize namespace filter watcher", helpers.Error(err))
		}
		watcherDone := make(chan struct{})
		go func() { defer close(watcherDone); filterWatcher.Run(ctx) }()
		defer func() { stop(); <-watcherDone }()
		if err := filterWatcher.WaitForReady(ctx); err != nil {
			return
		}
	}
	k8sConfig := k8sApi.K8SConfig
	// force GRPC
	k8sConfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf"
	k8sConfig.ContentType = "application/vnd.kubernetes.protobuf"
	ksStorageClient, err := kssc.NewForConfig(k8sConfig)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("unable to initialize the storage client", helpers.Error(err))
	}

	kubernetesCache := objectcache.NewKubernetesCache(k8sApi)

	// Creating the ObjectCache using KubernetesCache
	objectCache := objectcache.NewObjectCache(kubernetesCache)

	if components.ServiceScanConfig.Enabled {
		logger.L().Info("service discovery enabled and started with interval: ", helpers.String("interval", components.ServiceScanConfig.Interval.String()))
		go servicehandler.DiscoveryServiceHandler(ctx, k8sApi, components.ServiceScanConfig.Interval)
	}

	if cfg.RulesUpdateConfig.Enabled {
		rulesUpdater := rulesupdate.NewRulesUpdator(ctx, k8sApi, cfg.RulesUpdateConfig)
		rulesUpdater.Start()
	}

	var cloudMetadata *armotypes.CloudMetadata
	nodeName := os.Getenv("NODE_NAME")
	cloudMetadata, err = cloudmetadata.GetCloudMetadata(ctx, k8sApi, nodeName)
	if err != nil {
		logger.L().Ctx(ctx).Error("error getting cloud metadata", helpers.Error(err))
	} else {
		logger.L().Ctx(ctx).Info("cloud metadata retrieved successfully", helpers.Interface("cloudMetadata", cloudMetadata))
	}

	clusterUID := utils.GetClusterUID(k8sApi.GetKubernetesClient())

	var exporter exporters.Exporter
	if exporterConfig := operatorConfig.HttpExporterConfig(); exporterConfig != nil {
		exporter, err = exporters.InitHTTPExporter(*exporterConfig, operatorConfig.ClusterName(), cloudMetadata, clusterUID)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("failed to initialize HTTP exporter", helpers.Error(err))
		}
	} else {
		exporter = exporters.MockExporter{}
	}

	// setup main handler
	mainHandler := mainhandler.NewMainHandler(operatorConfig, k8sApi, exporter, ksStorageClient)

	go func() { // open a REST API connection listener
		restAPIHandler := restapihandler.NewHTTPHandler(mainHandler.EventWorkerPool(), operatorConfig)
		if err := restAPIHandler.SetupHTTPListener(cfg.RestAPIBindAddress, cfg.RestAPIPort); err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
	}()

	if components.Components.ServiceDiscovery.Enabled {
		logger.L().Info("triggering a full kubescapeScan on startup",
			helpers.Interface("defaultFrameworks", operatorConfig.DefaultFrameworks()),
			helpers.Interface("effectiveFrameworks", utils.FrameworksOrDefault(operatorConfig.DefaultFrameworks(), utils.NativeDefaultFrameworks)),
		)
		go mainHandler.StartupTriggerActions(ctx, mainhandler.GetStartupActions(operatorConfig))
	}

	// When continuous scanning is disabled, publish readiness now. When it is
	// enabled, delay readiness until SetupContinuousScanning succeeds so a pod
	// with invalid matching rules cannot report ready while terminating.
	if !operatorConfig.ContinuousScanEnabled() {
		isReadinessReady = true
	}

	// wait for requests to come from the websocket or from the REST API
	go mainHandler.HandleCommandResponse(ctx)
	mainHandler.HandleWatchers(ctx)

	if operatorConfig.ContinuousScanEnabled() {
		err := mainHandler.SetupContinuousScanning(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
		logger.L().Info("set up cont scanning service")
		isReadinessReady = true
	}

	// Start node agent autoscaler if enabled
	autoscalerConfig := operatorConfig.NodeAgentAutoscalerConfig()
	if autoscalerConfig.Enabled {
		// Get operator deployment name from config, fall back to "operator" if empty
		operatorDeploymentName := autoscalerConfig.OperatorDeploymentName
		if operatorDeploymentName == "" {
			operatorDeploymentName = "operator"
		}
		autoscaler, err := nodeagentautoscaler.NewAutoscaler(
			k8sApi.KubernetesClient,
			autoscalerConfig,
			operatorConfig.Namespace(),
			operatorDeploymentName,
		)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("failed to initialize node agent autoscaler", helpers.Error(err))
		}
		go autoscaler.Start(ctx)
	}

	if operatorConfig.AdmissionControllerEnabled() {
		serverContext, serverCancel := context.WithCancel(ctx)

		addr := ":8443"

		// CEL engine for admission rule evaluation
		celEngine, err := admissioncel.NewAdmissionCEL()
		if err != nil {
			logger.L().Ctx(ctx).Fatal("failed to create admission CEL engine", helpers.Error(err))
		}

		// CRD-backed rule creator (replaces hardcoded R2000/R2001)
		celRuleCreator := celrules.NewCelRuleCreator(celEngine)

		// Create watchers
		dWatcher := dynamicwatcher.NewWatchHandler(k8sApi, ksStorageClient.SpdxV1beta1(), operatorConfig.SkipNamespace)

		// create ruleBinding cache with injected rule creator
		ruleBindingCache := rulebindingcachev1.NewCache(k8sApi, celRuleCreator, operatorConfig.RulesUpdateEnabled())
		dWatcher.AddAdaptor(ruleBindingCache)

		// Rules watcher — syncs k8s-admission rules from CRDs to the creator
		rulesWatcher := ruleswatcher.NewRulesWatcher(k8sApi, celRuleCreator, ruleBindingCache)
		dWatcher.AddAdaptor(rulesWatcher)

		ruleBindingNotify := make(chan rulebindingmanager.RuleBindingNotify, 100)
		ruleBindingCache.AddNotifier(&ruleBindingNotify)

		admissionValidator := webhook.NewAdmissionValidator(k8sApi, objectCache, exporter, ruleBindingCache)
		admissionValidator.SetKindAcceptor(celRuleCreator)
		admissionValidator.Start(serverContext)

		admissionController := webhook.New(addr, "/etc/certs/tls.crt", "/etc/certs/tls.key", runtime.NewScheme(), admissionValidator, ruleBindingCache)
		go func() {
			defer func() {
				serverCancel()
			}()
			err := admissionController.Run(serverContext)
			handleAdmissionExit(serverContext, err, stop)
		}()

		dWatcher.Start(ctx)
		defer dWatcher.Stop(ctx)
	}

	if logger.L().GetLevel() == helpers.DebugLevel.String() {
		go func() {
			// start pprof server -> https://pkg.go.dev/net/http/pprof
			logger.L().Info("starting pprof server", helpers.String("port", "6060"))
			logger.L().Error(http.ListenAndServe(":6060", nil).Error())
		}()
	}

	// send reports every 24 hours
	go mainHandler.SendReports(ctx, 24*time.Hour)

	// Wait for shutdown signal
	<-ctx.Done()
}

// displayBuildTag logs the running image version from the RELEASE environment variable.
func displayBuildTag() {
	logger.L().Info(fmt.Sprintf("Image version: %s", os.Getenv("RELEASE")))
}

func initHttpHandlers(config config.IConfig) {
	mainhandler.KubescapeHttpClient = utils.InitHttpClient(config.KubescapeURL())
	mainhandler.VulnScanHttpClient = utils.InitHttpClient(config.KubevulnURL())
}

// Runtime server failure cancels main so deferred provider flushing can run.
// Cancellation and normal HTTP close are expected shutdown outcomes.
func handleAdmissionExit(ctx context.Context, err error, stop func()) {
	if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
		return
	}
	logger.L().Ctx(ctx).Error("admission server stopped", helpers.Error(err))
	stop()
}
