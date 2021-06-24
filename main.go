package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/cronjobs"
	"k8s-ca-websocket/k8sworkloads"
	"k8s-ca-websocket/mainhandler"
	"k8s-ca-websocket/restapihandler"
	"k8s-ca-websocket/safemode"
	"k8s-ca-websocket/websocket"

	"github.com/armosec/capacketsgo/k8sshared/probes"
	"github.com/golang/glog"
)

// main function
func main() {
	flag.Parse()

	isReadinessReady := false
	go probes.InitReadinessV1(&isReadinessReady)

	displayBuildTag()
	if err := k8sworkloads.SetupKubernetesClient(); err != nil {
		glog.Error(err)
		return
	}

	if err := cautils.LoadEnvironmentVaribles(); err != nil {
		glog.Error(err)
		return
	}

	sessionObj := make(chan cautils.SessionObj)

	// Websocket
	go func() {
		websocketHandler := websocket.NewWebsocketHandler(&sessionObj)
		glog.Fatal(websocketHandler.Websocket())
	}()

	// Websocket setup
	go func() {
		safemode := safemode.NewSafeModeHandler(&sessionObj)
		glog.Fatal(safemode.WebsocketConnection())
	}()

	// http listener
	go func() {
		restAPIHandler := restapihandler.NewHTTPHandler(&sessionObj)
		glog.Fatal(restAPIHandler.SetupHTTPListener())
	}()

	isReadinessReady = true

	mainHandler := mainhandler.NewMainHandler(&sessionObj)

	//cronjobs - add these so websocket can trigger various jobs
	go func() {
		cronjobs.StartCronJob()
	}()

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
