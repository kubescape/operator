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

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("operator",
			os.Getenv("RELEASE"),
			clusterConfig.AccountID,
			clusterConfig.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	initHttpHandlers(clusterConfig)
	k8sApi := k8sinterface.NewKubernetesApi()
	restclient.SetDefaultWarningHandler(restclient.NoWarnings{})

	// setup main handler
	mainHandler := mainhandler.NewMainHandler(clusterConfig, cfg, k8sApi)

	go func() { // open websocket connection to notification server
		notificationHandler := notificationhandler.NewNotificationHandler(mainHandler.EventWorkerPool(), clusterConfig)
		if err := notificationHandler.WebsocketConnection(ctx); err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
	}()

	go func() { // open a REST API connection listener
		restAPIHandler := restapihandler.NewHTTPHandler(mainHandler.EventWorkerPool(), clusterConfig)
		if err := restAPIHandler.SetupHTTPListener(cfg.RestAPIPort); err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
	}()

	go mainHandler.StartupTriggerActions(ctx, mainhandler.GetStartupActions(clusterConfig))

	isReadinessReady = true

	// wait for requests to come from the websocket or from the REST API
	go mainHandler.HandleCommandResponse(ctx)
	mainHandler.HandleWatchers(ctx)

	if enabled, ok := os.LookupEnv("KUBESCAPE_FEAT_CONTINUOUS_SCAN"); ok && enabled == "true" {
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

func initHttpHandlers(clusterConfig utilsmetadata.ClusterConfig) {
	mainhandler.KubescapeHttpClient = utils.InitHttpClient(clusterConfig.KubescapeURL)
	mainhandler.VulnScanHttpClient = utils.InitHttpClient(clusterConfig.KubevulnURL)
	utils.ReporterHttpClient = utils.InitHttpClient(clusterConfig.EventReceiverRestURL)
}
