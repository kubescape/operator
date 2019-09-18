package main

import (
	"flag"
	"io/ioutil"
	"k8s-ca-websocket/cautils"

	"github.com/golang/glog"
)

// main function
func main() {
	cautils.ReadEnvironmentVaribles()
	flag.Parse()

	displayBuildTag()

	// Websocket
	websocketHandler := CreateWebSocketHandler()
	glog.Fatal(websocketHandler.WebSokcet())

}

func displayBuildTag() {
	imageVersion := "UNKNOWN"
	dat, err := ioutil.ReadFile("./build_number.txt")
	if err == nil {
		imageVersion = string(dat)
	}
	glog.Infof("Image version: %s", imageVersion)
}
