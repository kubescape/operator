package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/probes"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/cloudmetadata"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/watcher/dynamicwatcher"
	exporters "github.com/kubescape/operator/admission/exporter"
	rulebindingcachev1 "github.com/kubescape/operator/admission/rulebinding/cache"
	"github.com/kubescape/operator/admission/rulesupdate"
	"github.com/kubescape/operator/admission/webhook"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler"
	"github.com/kubescape/operator/objectcache"
	"github.com/kubescape/operator/restapihandler"
	"github.com/kubescape/operator/servicehandler"
	"github.com/kubescape/operator/utils"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
)

//go:generate swagger generate spec -o ./docs/swagger.yaml
func main() {
	ctx := context.Background()
	flag.Parse()

	isReadinessReady := false
	go probes.InitReadinessV1(&isReadinessReady)

	displayBuildTag()

	clusterConfig, err := config.LoadClusterConfig()
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load clusterData error", helpers.Error(err))
	}

	components, err := config.LoadCapabilitiesConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load components error", helpers.Error(err))
	}
	logger.L().Debug("loaded config for components", helpers.Interface("components", components))

	var credentials *beUtils.Credentials
	if credentials, err = beUtils.LoadCredentialsFromFile("/etc/credentials"); err != nil {
		logger.L().Ctx(ctx).Error("failed to load credentials", helpers.Error(err))
		credentials = &beUtils.Credentials{}
	} else {
		logger.L().Info("credentials loaded",
			helpers.Int("accessKeyLength", len(credentials.AccessKey)),
			helpers.Int("accountLength", len(credentials.Account)))
	}

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	// wrapper for all configs
	operatorConfig := config.NewOperatorConfig(components, clusterConfig, credentials, cfg)
	if err := config.ValidateConfig(operatorConfig); err != nil {
		logger.L().Ctx(ctx).Error("validate config error", helpers.Error(err))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present && components.Components.OtelCollector.Enabled {
		ctx = logger.InitOtel("operator",
			os.Getenv("RELEASE"),
			operatorConfig.AccountID(),
			operatorConfig.ClusterName(),
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	initHttpHandlers(operatorConfig)
	k8sApi := k8sinterface.NewKubernetesApi()
	restclient.SetDefaultWarningHandler(restclient.NoWarnings{})
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

	var exporter exporters.Exporter
	if exporterConfig := operatorConfig.HttpExporterConfig(); exporterConfig != nil {
		exporter, err = exporters.InitHTTPExporter(*exporterConfig, operatorConfig.ClusterName(), cloudMetadata)
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
		if err := restAPIHandler.SetupHTTPListener(cfg.RestAPIPort); err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
	}()

	if components.Components.ServiceDiscovery.Enabled {
		logger.L().Debug("triggering a full kubescapeScan on startup")
		go mainHandler.StartupTriggerActions(ctx, mainhandler.GetStartupActions(operatorConfig))
	}

	isReadinessReady = true

	// wait for requests to come from the websocket or from the REST API
	go mainHandler.HandleCommandResponse(ctx)
	mainHandler.HandleWatchers(ctx)

	if operatorConfig.ContinuousScanEnabled() {
		go func(mh *mainhandler.MainHandler) {
			err := mh.SetupContinuousScanning(ctx)
			logger.L().Info("set up cont scanning service")
			if err != nil {
				logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
			}
		}(mainHandler)
	}

	if operatorConfig.AdmissionControllerEnabled() {
		serverContext, serverCancel := context.WithCancel(ctx)

		addr := ":8443"

		// Create watchers
		dWatcher := dynamicwatcher.NewWatchHandler(k8sApi, ksStorageClient.SpdxV1beta1(), operatorConfig.SkipNamespace)

		// create ruleBinding cache (when rules update is enabled we ignore bindings and run all rules)
		ruleBindingCache := rulebindingcachev1.NewCache(k8sApi, operatorConfig.RulesUpdateEnabled())
		dWatcher.AddAdaptor(ruleBindingCache)

		ruleBindingNotify := make(chan rulebindingmanager.RuleBindingNotify, 100)
		ruleBindingCache.AddNotifier(&ruleBindingNotify)

		admissionController := webhook.New(addr, "/etc/certs/tls.crt", "/etc/certs/tls.key", runtime.NewScheme(), webhook.NewAdmissionValidator(k8sApi, objectCache, exporter, ruleBindingCache), ruleBindingCache)
		// Start HTTP REST server for webhook
		go func() {
			defer func() {
				// Cancel the server context to stop other workers
				serverCancel()
			}()

			err := admissionController.Run(serverContext)
			logger.L().Ctx(ctx).Fatal("server stopped", helpers.Error(err))
		}()

		// start watching
		dWatcher.Start(ctx)
		defer dWatcher.Stop(ctx)
	}

	if logger.L().GetLevel() == helpers.DebugLevel.String() {
		go func() {
			logger.L().Info("starting pprof server", helpers.String("port", "6060"))
			logger.L().Error(http.ListenAndServe(":6060", nil).Error())
		}()
	}

	// send reports every 24 hours
	go mainHandler.SendReports(ctx, 24*time.Hour)

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown
	<-ctx.Done()
}

func displayBuildTag() {
	logger.L().Info(fmt.Sprintf("Image version: %s", os.Getenv("RELEASE")))
}

func initHttpHandlers(config config.IConfig) {
	mainhandler.KubescapeHttpClient = utils.InitHttpClient(config.KubescapeURL())
	mainhandler.VulnScanHttpClient = utils.InitHttpClient(config.KubevulnURL())
}
