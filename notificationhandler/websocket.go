package notificationhandler

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"time"

	"github.com/armosec/capacketsgo/apis"
	"github.com/armosec/capacketsgo/k8sinterface"
	"github.com/golang/glog"
	"github.com/gorilla/websocket"
)

type NotificationHandler struct {
	connector   IWebsocketActions
	sessionObj  *chan cautils.SessionObj
	safeModeObj *chan apis.SafeMode
	k8sApi      *k8sinterface.KubernetesApi
}

func NewNotificationHandler(sessionObj *chan cautils.SessionObj, safeModeObj *chan apis.SafeMode) *NotificationHandler {
	urlStr := initNotificationServerURL()

	return &NotificationHandler{
		connector:   NewWebsocketActions(urlStr),
		sessionObj:  sessionObj,
		safeModeObj: safeModeObj,
	}
}

func (notification *NotificationHandler) WebsocketConnection() error {
	if cautils.NotificationServerURL == "" {
		return nil
	}
	retries := 0
	for {
		if err := notification.SetupWebsocket(); err != nil {
			retries += 1
			time.Sleep(time.Duration(retries*2) * time.Second)
			glog.Errorf("In WebsocketConnection, error: %s, retry: %d", err.Error(), retries)
		} else {
			retries = 0
		}
	}
}

// Websocket main function
func (notification *NotificationHandler) SetupWebsocket() error {
	errs := make(chan error)
	_, err := notification.connector.DefaultDialer(nil)
	if err != nil {
		glog.Errorf("In SetupWebsocket: %v", err)
		return err
	}
	defer notification.connector.Close()
	go func() {
		if err := notification.websocketPingMessage(); err != nil {
			glog.Error(err)
			errs <- err
		}
	}()
	go func() {
		glog.Infof("Waiting for websocket to receive notifications")
		if err := notification.websocketReceiveNotification(); err != nil {
			glog.Error(err)
			errs <- err
		}
	}()

	return <-errs
}
func (notification *NotificationHandler) websocketReceiveNotification() error {
	for {
		messageType, messageBytes, err := notification.connector.ReadMessage()
		if err != nil {
			return fmt.Errorf("error receiving data from notificationServer. message: %s", err.Error())
		}
		switch messageType {
		case websocket.TextMessage, websocket.BinaryMessage:
			err := notification.handleJsonNotification(messageBytes)
			if err != nil {
				break
				// return err
			}

		case websocket.CloseMessage:
			return fmt.Errorf("websocket closed by server, message: %s", string(messageBytes))
		default:
			glog.Infof("Unrecognized message received. received: %d", messageType)
		}
	}
}
