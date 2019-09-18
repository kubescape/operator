package main

import (
	"fmt"
	"k8s-ca-websocket/cautils"
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
	var websocketURL WebSocketURL

	websocketURL.Scheme = "wss"
	websocketURL.Host = cautils.CA_POSTMAN
	websocketURL.Path = fmt.Sprintf("waitfornotification/%s-%s", cautils.CA_CUSTOMER_GUID, cautils.CA_CLUSTER_NAME)
	websocketURL.ForceQuery = false

	return &WebSocketHandler{data: make(chan DataSocket), webSocketURL: websocketURL, kubeconfig: loadConfig()}
}

// WebSokcet CAWebSokcet
func (wsh *WebSocketHandler) WebSokcet() error {

	if err := createSignignProfilesDir(); err != nil {
		return fmt.Errorf("Error creating signing profile dir\nMessage %#v", err)
	}

	conn, err := wsh.dialWebSocket()
	if err != nil {
		return err
	}

	defer conn.Close()

	go func() {
		for {
			time.Sleep(5 * time.Second)
			if err = conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				return
			}
		}
	}()
	for {
		messageType, bytes, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("webSocket closed")
		}

		switch messageType {
		case websocket.TextMessage:
			wsh.HandlePostmanRequest(bytes)
		case websocket.CloseMessage:
			return fmt.Errorf("webSocket closed")
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

func (wsh *WebSocketHandler) dialWebSocket() (conn *websocket.Conn, err error) {
	u := url.URL{Scheme: wsh.webSocketURL.Scheme, Host: wsh.webSocketURL.Host, Path: wsh.webSocketURL.Path, ForceQuery: wsh.webSocketURL.ForceQuery}
	glog.Infof("Connecting to %s", u.String())

	conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		glog.Errorf("Error connecting to postman. url: %s\nMessage %#v", u.String(), err)
		return conn, err
	}
	return conn, err
}

func createSignignProfilesDir() error {
	return os.MkdirAll(SIGNINGPROFILEPATH, 777)
}
