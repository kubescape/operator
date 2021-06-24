package safemode

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/url"
	"strings"
	"time"

	"github.com/armosec/capacketsgo/apis"
	"github.com/armosec/capacketsgo/notificationserver"
	"gopkg.in/mgo.v2/bson"

	"github.com/golang/glog"
)

func (smHandler *SafeModeHandler) websocketPingMessage() error {
	for {
		time.Sleep(30 * time.Second)
		if err := smHandler.connector.WritePingMessage(); err != nil {
			glog.Errorf("PING, %s", err.Error())
			return fmt.Errorf("PING, %s", err.Error())
		}
	}
}

func convertJsonNotification(bytesNotification []byte) (*apis.SafeMode, error) {
	notification := &notificationserver.Notification{}
	if err := json.Unmarshal(bytesNotification, notification); err != nil {
		glog.Error(err)
		return nil, err
	}

	safeMode := &apis.SafeMode{}
	notificationBytes, err := json.Marshal(notification.Notification)
	if err != nil {
		return safeMode, err
	}

	glog.Infof("Notification: %s", string(notificationBytes))
	if err := json.Unmarshal(notificationBytes, safeMode); err != nil {
		glog.Error(err)
		return nil, err
	}

	return safeMode, nil

}
func convertBsonNotification(bytesNotification []byte) (*apis.SafeMode, error) {
	notification := &notificationserver.Notification{}
	if err := bson.Unmarshal(bytesNotification, notification); err != nil {
		if err := json.Unmarshal(bytesNotification, notification); err != nil {
			glog.Error(err)
			return nil, err
		}
	}

	safeMode := apis.SafeMode{}
	notificationBytes, ok := notification.Notification.([]byte)
	if !ok {
		var err error
		notificationBytes, err = json.Marshal(notification.Notification)
		if err != nil {
			return &safeMode, err
		}
	}

	glog.Infof("Notification: %s\n", string(notificationBytes))
	if err := json.Unmarshal(notificationBytes, &safeMode); err != nil {
		glog.Error(err)
		return nil, err
	}
	return &safeMode, nil

}
func initNotificationServerURL() string {
	urlObj := url.URL{}
	host := cautils.NotificationServerURL
	if host == "" {
		return ""
	}

	scheme := "ws"
	if strings.HasPrefix(host, "ws://") {
		host = strings.TrimPrefix(host, "ws://")
		scheme = "ws"
	} else if strings.HasPrefix(host, "wss://") {
		host = strings.TrimPrefix(host, "wss://")
		scheme = "wss"
	}

	urlObj.Scheme = scheme
	urlObj.Host = host
	urlObj.Path = notificationserver.PathWebsocketV1

	q := urlObj.Query()
	// customerGUID := strings.ToUpper(cautils.CustomerGUID)
	// customerGUID = strings.Replace(customerGUID, "-", "", -1)
	// q.Add(notificationserver.TargetCustomer, customerGUID)
	// q.Add(notificationserver.TargetCluster, cautils.ClusterName)
	q.Add(notificationserver.TargetComponent, notificationserver.TargetComponentLoggerValue)
	urlObj.RawQuery = q.Encode()

	return urlObj.String()
}
