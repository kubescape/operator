package main

import (
	"flag"
	"io/ioutil"
	"k8s-ca-websocket/cacli"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/websocket"
	"time"

	"github.com/golang/glog"
)

// main function
func main() {
	flag.Parse()

	displayBuildTag()

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
	glog.Error(websocketHandler.WebSokcet())

}

func displayBuildTag() {
	imageVersion := "UNKNOWN"
	dat, err := ioutil.ReadFile("./build_number.txt")
	if err == nil {
		imageVersion = string(dat)
	}
	glog.Infof("Image version: %s. date: %s (UTC)", imageVersion, time.Now().UTC().String())
}
