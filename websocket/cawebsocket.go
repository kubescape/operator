package websocket

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/url"
	"strings"
	"time"

	"github.com/armosec/capacketsgo/apis"
	"github.com/golang/glog"
	"github.com/gorilla/websocket"
)

// WebsocketHandler -
type WebsocketHandler struct {
	sessionObj   *chan cautils.SessionObj
	webSocketURL url.URL
}

// CreateWebSocketHandler Create ws-handler obj
func NewWebsocketHandler(sessionObj *chan cautils.SessionObj) *WebsocketHandler {
	urlObj := initPostmanURL()

	return &WebsocketHandler{
		webSocketURL: urlObj,
		sessionObj:   sessionObj,
	}
}
func initPostmanURL() url.URL {
	urlObj := url.URL{}
	host := cautils.CA_POSTMAN

	scheme := "wss"

	if strings.HasPrefix(host, "ws://") {
		host = strings.TrimPrefix(host, "ws://")
		scheme = "ws"
	} else if strings.HasPrefix(host, "wss://") {
		host = strings.TrimPrefix(host, "wss://")
		scheme = "wss"
	}

	urlObj.Scheme = scheme
	urlObj.Host = host
	urlObj.Path = fmt.Sprintf("waitfornotification/%s-%s", cautils.CA_CUSTOMER_GUID, cautils.CA_CLUSTER_NAME)
	urlObj.ForceQuery = false

	return urlObj
}

// Websocket main function
func (wsh *WebsocketHandler) Websocket(isReadinessReady *bool) error {

	for {
		conn, err := wsh.ConnectToWebsocket()
		if err != nil {
			glog.Errorf("failed to open websocket with Armo backend, reason: %s", err.Error())
			time.Sleep(3 * time.Second)
			continue

		}
		*isReadinessReady = true

		go func() {
			for {
				time.Sleep(30 * time.Second)
				if err = conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
					glog.Errorf("PING, %s", err.Error())
					*isReadinessReady = false
					conn.Close()
					return
				}
			}
		}()
		for {
			messageType, bytes, err := conn.ReadMessage()
			if err != nil {
				glog.Errorf("error receiving data from websocket. message: %s", err.Error())
				break
			}
			switch messageType {
			case websocket.TextMessage:
				wsh.HandlePostmanRequest(bytes)
			case websocket.CloseMessage:
				break
			default:
				glog.Infof("Unrecognized message received. received: %d", messageType)
			}
		}
		*isReadinessReady = false
		conn.Close()
	}
}

// ConnectToWebsocket Connect To Websocket with reties
func (wsh *WebsocketHandler) ConnectToWebsocket() (*websocket.Conn, error) {
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("RECOVER ConnectToWebsocket %v", err)
		}
	}()
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

func (wsh *WebsocketHandler) dialWebSocket() (conn *websocket.Conn, err error) {
	glog.Infof("Connecting to %s", wsh.webSocketURL.String())

	if cautils.CA_IGNORE_VERIFY_CACLI {
		websocket.DefaultDialer.TLSClientConfig.InsecureSkipVerify = true
	}
	conn, _, err = websocket.DefaultDialer.Dial(wsh.webSocketURL.String(), nil)
	if err != nil {
		glog.Errorf("Error connecting to postman. url: %s\nMessage %#v", wsh.webSocketURL.String(), err)
		return conn, err
	}
	glog.Infof("Successfully connected")
	return conn, err
}

// HandlePostmanRequest Parse received commands and run the command
func (wsh *WebsocketHandler) HandlePostmanRequest(receivedCommands []byte) {
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("RECOVER HandlePostmanRequest %v", err)
		}
	}()

	commands := apis.Commands{}
	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
	}
	glog.Infof("receivedCommands: %s", receivedCommands)
	for _, c := range commands.Commands {
		sessionObj := cautils.NewSessionObj(&c, "Websocket", c.JobTracking.ParentID, c.JobTracking.JobID, c.JobTracking.LastActionNumber+1)

		if c.CommandName == "" {
			err := fmt.Errorf("command not found. id: %s", c.GetID())
			glog.Error(err)
			sessionObj.Reporter.SendError(err, true, true)
			continue
		}

		*wsh.sessionObj <- *sessionObj

		// This is a workaround
		if c.WildWlid != "" {
			// add log
			break
		}
	}
}
