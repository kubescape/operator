package main

import (
	"flag"
	"k8s-ca-websocket/mainhandler"
	"k8s-ca-websocket/notificationhandler"
	"k8s-ca-websocket/restapihandler"
	"k8s-ca-websocket/utils"
	"k8s-ca-websocket/websocket"
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

	// Open Websocket with cloud
	go func() {
		websocketHandler := websocket.NewWebsocketHandler(&sessionObj)
		glog.Fatal(websocketHandler.Websocket(&isReadinessReady))
	}()

	// Open Websocket with cloud
	go func() { // should be deprecated
		notificationHandler := notificationhandler.NewNotificationHandler(&sessionObj)
		if err := notificationHandler.WebsocketConnection(); err != nil {
			glog.Fatal(err)
		}
	}()

	go func() {
		triggerNotificationHandler := notificationhandler.NewTriggerHandlerNotificationHandler(&sessionObj)
		if err := triggerNotificationHandler.WebsocketConnection(); err != nil {
			glog.Fatal(err)
		}
	}()

	// http listener
	go func() {
		restAPIHandler := restapihandler.NewHTTPHandler(&sessionObj)
		glog.Fatal(restAPIHandler.SetupHTTPListener())
	}()

	mainHandler := mainhandler.NewMainHandler(&sessionObj, k8sApi)
	go mainHandler.StartupTriggerActions(mainhandler.GetStartupActions())

	mainHandler.HandleRequest()

}

func displayBuildTag() {
	glog.Infof("Image version: %s", os.Getenv(utils.ReleaseBuildTagEnvironmentVariable))
}
