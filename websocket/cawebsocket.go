package websocket

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/url"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
)

type ReqType int

type WebSocketURL struct {
	Scheme     string `json:"Scheme"`
	Host       string `json:"Host"`
	Path       string `json:"Path"`
	ForceQuery bool   `json:"ForceQuery"`
}

// DataSocket-
type DataSocket struct {
	message string
	RType   ReqType
}

// WebSocketHandler -
type WebSocketHandler struct {
	data         chan DataSocket
	webSocketURL WebSocketURL
}

// CreateWebSocketHandler Create ws-handler obj
func CreateWebSocketHandler() *WebSocketHandler {
	var websocketURL WebSocketURL

	websocketURL.Scheme = "wss"
	websocketURL.Host = cautils.CA_POSTMAN
	websocketURL.Path = fmt.Sprintf("waitfornotification/%s-%s", cautils.CA_CUSTOMER_GUID, cautils.CA_CLUSTER_NAME)
	websocketURL.ForceQuery = false

	return &WebSocketHandler{data: make(chan DataSocket), webSocketURL: websocketURL}
}

// WebSokcet CAWebSokcet
func (wsh *WebSocketHandler) WebSokcet() error {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("RECOVER WebSokcet %v", err)
		}
	}()

	conn, err := wsh.ConnectToWebsocket()
	if err != nil {
		return err
	}

	defer conn.Close()

	go func() {
		for {
			time.Sleep(30 * time.Second)
			if err = conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				glog.Errorf("PING, %s", err.Error())
				c, err := wsh.ConnectToWebsocket()
				if err != nil {
					panic("connection closed, restart websocket")
				}
				conn = c
			}
		}
	}()
	for {
		messageType, bytes, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("error receiving data from websocket. message: %s", err.Error())
		}
		switch messageType {
		case websocket.TextMessage:
			wsh.HandlePostmanRequest(bytes)
		case websocket.CloseMessage:
			return fmt.Errorf("websocket closed by server, message: %s", string(bytes))
		default:
			glog.Infof("Unrecognized message received. received: %d", messageType)
		}
	}
}

// ConnectToWebsocket Connect To Websocket with reties
func (wsh *WebSocketHandler) ConnectToWebsocket() (*websocket.Conn, error) {
	i := 0
	for {
		conn, err := wsh.dialWebSocket()
		if err == nil {
			return conn, err
		}
		i++
		if i == 3 {
			return conn, fmt.Errorf("failed connecting to websocket after %d tries. error message: %v", 3, err)
		}
		time.Sleep(time.Second * 2)
	}
}

func (wsh *WebSocketHandler) dialWebSocket() (conn *websocket.Conn, err error) {
	u := url.URL{Scheme: wsh.webSocketURL.Scheme, Host: wsh.webSocketURL.Host, Path: wsh.webSocketURL.Path, ForceQuery: wsh.webSocketURL.ForceQuery}
	glog.Infof("Connecting to %s", u.String())
	conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		glog.Errorf("Error connecting to postman. url: %s\nMessage %#v", u.String(), err)
		return conn, err
	}
	glog.Infof("Successfully connected")
	return conn, err
}
