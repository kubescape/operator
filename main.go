package main

import (
	"flag"
	"os"

	"github.com/kubescape/kontroller/mainhandler"
	"github.com/kubescape/kontroller/notificationhandler"
	"github.com/kubescape/kontroller/restapihandler"
	"github.com/kubescape/kontroller/utils"

	"github.com/kubescape/k8s-interface/k8sinterface"
	restclient "k8s.io/client-go/rest"

	"github.com/armosec/utils-k8s-go/probes"
	"github.com/golang/glog"
)

//go:generate swagger generate spec -o ./docs/swagger.yaml
func main() {
	flag.Parse()

	isReadinessReady := false
	go probes.InitReadinessV1(&isReadinessReady)

	displayBuildTag()

	if err := utils.LoadEnvironmentVariables(); err != nil {
		glog.Error(err)
		return
	}

	initHttpHandlers()

	sessionObj := make(chan utils.SessionObj)
	k8sApi := k8sinterface.NewKubernetesApi()
	restclient.SetDefaultWarningHandler(restclient.NoWarnings{})

	go func() { // open websocket connection to notification server
		notificationHandler := notificationhandler.NewNotificationHandler(&sessionObj)
		if err := notificationHandler.WebsocketConnection(); err != nil {
			glog.Fatal(err)
		}
	}()

	go func() { // open a REST API connection listener
		restAPIHandler := restapihandler.NewHTTPHandler(&sessionObj)
		glog.Fatal(restAPIHandler.SetupHTTPListener())
	}()

	// setup main handler
	mainHandler := mainhandler.NewMainHandler(&sessionObj, k8sApi)
	go mainHandler.StartupTriggerActions(mainhandler.GetStartupActions())

	isReadinessReady = true

	// wait for requests to come from the websocket or from the REST API
	mainHandler.HandleRequest()

}

func displayBuildTag() {
	glog.Infof("Image version: %s", os.Getenv(utils.ReleaseBuildTagEnvironmentVariable))
}

func initHttpHandlers() {
	mainhandler.KubescapeHttpClient = utils.InitKubescapeHttpClient()
	mainhandler.VulnScanHttpClient = utils.InitVulnScanHttpClient()
	utils.ReporterHttpClient = utils.InitReporterHttpClient()
}
