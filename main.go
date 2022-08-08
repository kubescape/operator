package main

import (
	"flag"
	"k8s-ca-websocket/mainhandler"
	"k8s-ca-websocket/notificationhandler"
	"k8s-ca-websocket/restapihandler"
	"k8s-ca-websocket/utils"
	"os"

	"github.com/armosec/k8s-interface/k8sinterface"
	restclient "k8s.io/client-go/rest"

	"github.com/armosec/utils-k8s-go/probes"
	"github.com/golang/glog"
)

// main function
func main() {
	flag.Parse()

	isReadinessReady := false
	go probes.InitReadinessV1(&isReadinessReady)

	displayBuildTag()

	if err := utils.LoadEnvironmentVariables(); err != nil {
		glog.Error(err)
		return
	}

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
