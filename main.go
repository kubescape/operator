package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cacli"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"
	"k8s-ca-websocket/websocket"

	"asterix.cyberarmor.io/cyberarmor/capacketsgo/k8sshared/probes"

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

	if err := cacli.LoginCacli(); err != nil {
		glog.Error(err)
		return
	}

	// Websocket
	websocketHandler := websocket.CreateWebSocketHandler()

	isReadinessReady = true
	glog.Error(websocketHandler.Websocket())

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
