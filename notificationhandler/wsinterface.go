package notificationhandler

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/kubescape/go-logger"
)

// IWebsocketActions -
type IWebsocketActions interface {
	ReadMessage() (int, []byte, error)
	Close() error
	WritePingMessage() error
	DefaultDialer(requestHeader http.Header) (*http.Response, error)
}

// WebsocketActions -
type WebsocketActions struct {
	host  string
	conn  *websocket.Conn
	mutex *sync.Mutex
}

// NewWebsocketActions -
func NewWebsocketActions(host string) *WebsocketActions {
	return &WebsocketActions{
		host:  host,
		mutex: &sync.Mutex{},
	}
}

// Close -
func (wa *WebsocketActions) Close() error {
	wa.mutex.Lock()
	defer wa.mutex.Unlock()
	return wa.conn.Close()
}

// ReadMessage -
func (wa *WebsocketActions) ReadMessage() (int, []byte, error) {
	messageType, p, err := wa.conn.ReadMessage()
	return messageType, p, err
}

// DefaultDialer -
func (wa *WebsocketActions) DefaultDialer(requestHeader http.Header) (*http.Response, error) {
	logger.L().Info("Connecting websocket to " + wa.host)
	wa.mutex.Lock()
	defer wa.mutex.Unlock()
	conn, res, err := websocket.DefaultDialer.Dial(wa.host, nil)
	if err != nil {
		if strings.Contains(err.Error(), "bad handshake") {
			if strings.HasPrefix(wa.host, "ws://") {
				wa.host = strings.Replace(wa.host, "ws://", "wss://", 1)
			} else if strings.HasPrefix(wa.host, "wss://") {
				wa.host = strings.Replace(wa.host, "wss://", "ws://", 1)
			}
			conn, res, err = websocket.DefaultDialer.Dial(wa.host, nil)
		}
	}
	if err == nil {
		wa.conn = conn
		logger.L().Info("Successfully connected websocket to " + wa.host)
	} else {
		err = fmt.Errorf("failed dialing to: '%s', reason: '%s'", wa.host, err.Error())
	}
	return res, err
}

// WritePingMessage -
func (wa *WebsocketActions) WritePingMessage() error {
	wa.mutex.Lock()
	defer wa.mutex.Unlock()
	err := wa.conn.WriteMessage(websocket.PingMessage, []byte{})
	return err
}
