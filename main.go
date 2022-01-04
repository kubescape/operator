package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/mainhandler"
	"k8s-ca-websocket/notificationhandler"
	"k8s-ca-websocket/notificationhandler/safemode"
	"k8s-ca-websocket/restapihandler"
	"k8s-ca-websocket/websocket"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/k8s-interface/k8sinterface"

	"github.com/armosec/utils-k8s-go/probes"
	"github.com/golang/glog"
)

// main function
func main() {
	flag.Parse()

	isReadinessReady := false
	go probes.InitReadinessV1(&isReadinessReady)

	displayBuildTag()

	if err := cautils.LoadEnvironmentVaribles(); err != nil {
		glog.Error(err)
		return
	}

	sessionObj := make(chan cautils.SessionObj)
	safeModeObj := make(chan apis.SafeMode)
	k8sApi := k8sinterface.NewKubernetesApi()

	// Websocket
	go func() {
		websocketHandler := websocket.NewWebsocketHandler(&sessionObj)
		glog.Fatal(websocketHandler.Websocket(&isReadinessReady))
	}()

	// notification websocket setup
	go func() {
		notificationHandler := notificationhandler.NewNotificationHandler(&sessionObj, &safeModeObj)
		if err := notificationHandler.WebsocketConnection(); err != nil {
			glog.Fatal(err)
		}
	}()

	// safe mode handler setup
	go func() {
		safeModeHandler := safemode.NewSafeModeHandler(&sessionObj, &safeModeObj, k8sApi)
		if err := safeModeHandler.InitSafeModeHandler(); err != nil {
			glog.Errorf("failed to initialize safeMode, reason: %s", err.Error())
			return
		}
		safeModeHandler.HandlerSafeModeNotification()
	}()

	// http listener
	go func() {
		restAPIHandler := restapihandler.NewHTTPHandler(&sessionObj)
		glog.Fatal(restAPIHandler.SetupHTTPListener())
	}()

	mainHandler := mainhandler.NewMainHandler(&sessionObj, cautils.NewCacliObj(cautils.SystemMode), k8sApi)
	go mainHandler.StartupTriggerActions(cautils.GetStartupActins())

	mainHandler.HandleRequest()

}

func displayBuildTag() {
	imageVersion := "local build"
	dat, err := ioutil.ReadFile("./build_number.txt")
	if err == nil {
		imageVersion = string(dat)
	} else {
		dat, err = ioutil.ReadFile("./build_date.txt")
		if err == nil {
			imageVersion = fmt.Sprintf("%s, date: %s", imageVersion, string(dat))
		}
	}
	glog.Infof("Image version: %s", imageVersion)
}
