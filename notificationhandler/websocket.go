package notificationhandler

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/cluster-notifier-api-go/notificationserver"
	"github.com/golang/glog"
	"github.com/gorilla/websocket"
)

type NotificationHandler struct {
	connector   IWebsocketActions
	sessionObj  *chan cautils.SessionObj
	safeModeObj *chan apis.SafeMode
}

func NewTriggerHandlerNotificationHandler(sessionObj *chan cautils.SessionObj, safeModeObj *chan apis.SafeMode) *NotificationHandler {
	urlStr := initARMOHelmNotificationServiceURL()

	return &NotificationHandler{
		connector:   NewWebsocketActions(urlStr),
		sessionObj:  sessionObj,
		safeModeObj: safeModeObj,
	}
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
	if cautils.NotificationServerWSURL == "" {
		return nil
	}
	retries := 0
	for {
		if err := notification.SetupWebsocket(); err != nil {
			retries += 1
			time.Sleep(time.Duration(retries*2) * time.Second)
			glog.Warningf("In WebsocketConnection, warning: %s, retry: %d", err.Error(), retries)
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
			var notif *notificationserver.Notification
			switch messageBytes[0] {
			case '{', '[', '"':
				notif, err = decodeJsonNotification(messageBytes)
				if err != nil {
					glog.Errorf("failed to handle notification as JSON: %s, %v", messageBytes, err)
					notif, err = decodeBsonNotification(messageBytes)
					if err != nil {
						glog.Errorf("failed to handle notification as BSON: %s, %v", messageBytes, err)
						continue
					}
				}
			default:
				notif, err = decodeBsonNotification(messageBytes)
				if err != nil {
					glog.Errorf("failed to handle notification as BSON: %s, %v", messageBytes, err)
					continue
				}
			}

			err := notification.handleNotification(notif)
			if err != nil {
				glog.Errorf("failed to handle notification: %s, reason: %s", messageBytes, err.Error())
			}
		case websocket.CloseMessage:
			return fmt.Errorf("websocket closed by server, message: %s", string(messageBytes))
		default:
			glog.Infof("Unrecognized message received. received: %d", messageType)
		}
	}
}
