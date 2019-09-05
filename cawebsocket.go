package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	clientcmd "k8s.io/client-go/tools/clientcmd"
)

type ReqType int

type WebSocketURL struct {
	Scheme     string `json:"Scheme"`
	Host       string `json:"Host"`
	Path       string `json:"Path"`
	ForceQuery bool   `json:"ForceQuery"`
}

type DataSocket struct {
	message string
	RType   ReqType
}

type WebSocketHandler struct {
	data         chan DataSocket
	webSocketURL WebSocketURL
	kubeconfig   *restclient.Config
}

// CreateWebSocketHandler Create ws-handler obj
func CreateWebSocketHandler() *WebSocketHandler {
	customerGUID := os.Getenv("CA_CUSTOMER_GUID")
	clusterName := os.Getenv("CA_CLUSTER_NAME")
	var websocketURL WebSocketURL

	websocketURL.Scheme = "wss"
	websocketURL.Host = os.Getenv("CA_POSTMAN")
	websocketURL.Path = fmt.Sprintf("waitfornotification/%s-%s", customerGUID, clusterName)
	websocketURL.ForceQuery = false

	return &WebSocketHandler{data: make(chan DataSocket), webSocketURL: websocketURL, kubeconfig: loadConfig()}
}

// WebSokcet CAWebSokcet
func (wsh *WebSocketHandler) WebSokcet() {

	if err := createSignignProfilesDir(); err != nil {
		glog.Errorf("Error creating signing profile dir\nMessage %#v", err)
		return
	}

	conn, err := wsh.dialWebSocket()
	if err != nil {
		return
	}

	defer conn.Close()

	go func() {
		for {
			time.Sleep(5 * time.Second)
			if err = conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				conn, err = wsh.dialWebSocket()
				if err != nil {
					return
				}
			}
		}
	}()
	for {
		messageType, bytes, err := conn.ReadMessage()
		if err != nil {
			glog.Errorf("WebSocket closed.")
			return
		}

		switch messageType {
		case websocket.TextMessage:
			go wsh.HandlePostmanRequest(bytes)
		case websocket.CloseMessage:
			return
		default:
			log.Println("Unrecognized message received.")
		}
	}
}

func loadConfig() *restclient.Config {
	kubeconfigpath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	kubeconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigpath)
	if err != nil {
		kubeconfig, err = rest.InClusterConfig()
		if err != nil {
			panic("Cant load config kubernetes (check config path)")
		}
	}
	return kubeconfig
}

// main function
func main() {
	testEnvironmentVaribles()
	flag.Parse()

	displayBuildTag()

	// Websocket
	websocketHandler := CreateWebSocketHandler()
	websocketHandler.WebSokcet()

}

func (wsh *WebSocketHandler) dialWebSocket() (conn *websocket.Conn, err error) {
	u := url.URL{Scheme: wsh.webSocketURL.Scheme, Host: wsh.webSocketURL.Host, Path: wsh.webSocketURL.Path, ForceQuery: wsh.webSocketURL.ForceQuery}
	log.Printf("Connecting to %s", u.String())

	conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		glog.Errorf("Error connecting to postman. url: %s\nMessage %#v", u.String(), err)
		return conn, err
	}
	return conn, err
}

func testEnvironmentVaribles() {
	testEnvironmentVarible("CA_NAMESPACE")
	testEnvironmentVarible("CA_SERVICE_NAME")
	testEnvironmentVarible("CA_SERVICE_PORT")
	testEnvironmentVarible("CA_PORATL_BACKEND")
	testEnvironmentVarible("CA_CLUSTER_NAME")
	testEnvironmentVarible("CA_POSTMAN")
	testEnvironmentVarible("CA_CUSTOMER_GUID")

}
func testEnvironmentVarible(key string) {
	if _, ok := os.LookupEnv(key); !ok {
		panic(fmt.Sprintf("Missing environment variable %s", key))
	}
}

func createSignignProfilesDir() error {
	return os.MkdirAll(SIGNINGPROFILEPATH, 777)
}

func displayBuildTag() {
	imageVersion := "UNKNOWN"
	dat, err := ioutil.ReadFile("./build_tag.txt")
	if err == nil {
		imageVersion = string(dat)
	}
	glog.Infof("Image version: %s", imageVersion)
}
