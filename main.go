package main

import (
	"flag"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/seal"

	"github.com/golang/glog"
)

// main function
func main() {
	cautils.LoadEnvironmentVaribles()
	flag.Parse()

	displayBuildTag()

	// login cacli
	if err := seal.CacliLogin(); err != nil {
		glog.Errorf("Fail to login to cyberArmor backend")
		return
	}

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
