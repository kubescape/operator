package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler"
	"github.com/kubescape/operator/notificationhandler"
	"github.com/kubescape/operator/restapihandler"
	"github.com/kubescape/operator/utils"
	restclient "k8s.io/client-go/rest"

	"github.com/armosec/utils-k8s-go/probes"
	logger "github.com/kubescape/go-logger"
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

	var eventReceiverRestURL string
	if components.Components.ServiceDiscovery.Enabled {
		services, err := config.GetServiceURLs("/etc/config/services.json")
		if err != nil {
			logger.L().Ctx(ctx).Fatal("failed discovering urls", helpers.Error(err))
		}

		eventReceiverRestURL := services.GetReportReceiverHttpUrl()
		logger.L().Debug("setting eventReceiverRestURL", helpers.String("url", eventReceiverRestURL))
	}

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present && components.Components.OtelCollector.Enabled {
		ctx = logger.InitOtel("operator",
			os.Getenv("RELEASE"),
			clusterConfig.AccountID,
			clusterConfig.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	initHttpHandlers(clusterConfig, eventReceiverRestURL)
	k8sApi := k8sinterface.NewKubernetesApi()
	restclient.SetDefaultWarningHandler(restclient.NoWarnings{})

	// setup main handler
	mainHandler := mainhandler.NewMainHandler(clusterConfig, cfg, components.Components, k8sApi, eventReceiverRestURL)

	if components.Components.Gateway.Enabled {
		go func() { // open websocket connection to notification server
			notificationHandler := notificationhandler.NewNotificationHandler(mainHandler.EventWorkerPool(), clusterConfig, eventReceiverRestURL)
			if err := notificationHandler.WebsocketConnection(ctx); err != nil {
				logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
			}
		}()
	}

	go func() { // open a REST API connection listener
		restAPIHandler := restapihandler.NewHTTPHandler(mainHandler.EventWorkerPool(), clusterConfig, eventReceiverRestURL)
		if err := restAPIHandler.SetupHTTPListener(cfg.RestAPIPort); err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
	}()

	if components.Components.Gateway.Enabled {
		// trigger a full scan on startup
		go mainHandler.StartupTriggerActions(ctx, mainhandler.GetStartupActions(clusterConfig))
	}

	isReadinessReady = true

	// wait for requests to come from the websocket or from the REST API
	go mainHandler.HandleCommandResponse(ctx)
	if components.Components.Kubevuln.Enabled {
		mainHandler.HandleWatchers(ctx)
	}

	if components.Capabilities.ContinuousScan == "enable" {
		go func(mh *mainhandler.MainHandler) {
			err := mh.SetupContinuousScanning(ctx)
			logger.L().Ctx(ctx).Info("set up cont scanning service")
			if err != nil {
				logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
			}
		}(mainHandler)
	}

	<-ctx.Done()
}

func displayBuildTag() {
	logger.L().Info(fmt.Sprintf("Image version: %s", os.Getenv("RELEASE")))
}

func initHttpHandlers(clusterConfig utilsmetadata.ClusterConfig, eventReceiverRestURL string) {
	mainhandler.KubescapeHttpClient = utils.InitHttpClient(clusterConfig.KubescapeURL)
	mainhandler.VulnScanHttpClient = utils.InitHttpClient(clusterConfig.KubevulnURL)
	utils.ReporterHttpClient = utils.InitHttpClient(eventReceiverRestURL)
}
