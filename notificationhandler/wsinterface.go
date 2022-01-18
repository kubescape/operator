package notificationhandler

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
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
	glog.Infof("Connecting websocket to '%s'", wa.host)
	wa.mutex.Lock()
	defer wa.mutex.Unlock()
	conn, res, err := websocket.DefaultDialer.Dial(wa.host, nil)
	if err != nil {
		err = fmt.Errorf("failed dialing to: '%s', reason: '%s'", wa.host, err.Error())
	} else {
		wa.conn = conn
		glog.Infof("Successfully connected websocket to '%s'", wa.host)
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
