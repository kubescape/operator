package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
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

	if err := utils.LoadEnvironmentVariables(ctx); err != nil {
		logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
		return
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("operator",
			os.Getenv(utils.ReleaseBuildTagEnvironmentVariable),
			utils.ClusterConfig.AccountID,
			utils.ClusterConfig.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	initHttpHandlers()

	sessionObj := make(chan utils.SessionObj, 50)
	k8sApi := k8sinterface.NewKubernetesApi()
	restclient.SetDefaultWarningHandler(restclient.NoWarnings{})

	go func() { // open websocket connection to notification server
		notificationHandler := notificationhandler.NewNotificationHandler(&sessionObj)
		if err := notificationHandler.WebsocketConnection(ctx); err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
	}()

	go func() { // open a REST API connection listener
		restAPIHandler := restapihandler.NewHTTPHandler(&sessionObj)
		if err := restAPIHandler.SetupHTTPListener(); err != nil {
			logger.L().Ctx(ctx).Fatal(err.Error(), helpers.Error(err))
		}
	}()

	// setup main handler
	mainHandler := mainhandler.NewMainHandler(&sessionObj, k8sApi)
	go mainHandler.StartupTriggerActions(ctx, mainhandler.GetStartupActions())

	isReadinessReady = true

	// wait for requests to come from the websocket or from the REST API
	go mainHandler.HandleCommandResponse(ctx)
	mainHandler.HandleWatchers(ctx)

}

func displayBuildTag() {
	logger.L().Info(fmt.Sprintf("Image version: %s", os.Getenv(utils.ReleaseBuildTagEnvironmentVariable)))
}

func initHttpHandlers() {
	mainhandler.KubescapeHttpClient = utils.InitKubescapeHttpClient()
	mainhandler.VulnScanHttpClient = utils.InitVulnScanHttpClient()
	utils.ReporterHttpClient = utils.InitReporterHttpClient()
}
