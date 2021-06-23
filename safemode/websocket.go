package safemode

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
)

type SafeModeHandler struct {
	connector  IWebsocketActions
	sessionObj *chan cautils.SessionObj
}

func NewSafeModeHandler(sessionObj *chan cautils.SessionObj) *SafeModeHandler {
	urlObj := initNotificationServerURL()

	return &SafeModeHandler{
		connector:  NewWebsocketActions(urlObj.String()),
		sessionObj: sessionObj,
	}
}

func (smHandler *SafeModeHandler) WebsocketConnection() error {
	retries := 0
	for {
		if err := smHandler.SetupWebsocket(); err != nil {
			if retries == 3 {
				return err
			}
			time.Sleep(5 * time.Second)
			retries += 1
			glog.Errorf("In WebsocketConnection, error: %s, retry: %d", err.Error(), retries)
		}
	}
}

// Websocket main function
func (smHandler *SafeModeHandler) SetupWebsocket() error {
	errs := make(chan error)
	_, err := smHandler.connector.DefaultDialer(nil)
	if err != nil {
		glog.Errorf("In SetupWebsocket: %v", err)
		return err
	}
	defer smHandler.connector.Close()
	go func() {
		if err := smHandler.websocketPingMessage(); err != nil {
			glog.Error(err)
			errs <- err
		}
	}()
	go func() {
		glog.Infof("Waiting for websocket to receive notifications")
		if err := smHandler.websocketReceiveNotification(); err != nil {
			glog.Error(err)
			errs <- err
		}
	}()

	return <-errs
}
func (smHandler *SafeModeHandler) websocketReceiveNotification() error {
	for {
		messageType, messageBytes, err := smHandler.connector.ReadMessage()
		if err != nil {
			return fmt.Errorf("error receiving data from notificationServer. message: %s", err.Error())
		}
		switch messageType {
		case websocket.TextMessage, websocket.BinaryMessage:
			safeMode, err := convertJsonNotification(messageBytes)
			if err != nil {
				break
				// return err
			}
			smHandler.HandlerSafeModeNotification(safeMode)

		case websocket.CloseMessage:
			return fmt.Errorf("websocket closed by server, message: %s", string(messageBytes))
		default:
			glog.Infof("Unrecognized message received. received: %d", messageType)
		}
	}
}
