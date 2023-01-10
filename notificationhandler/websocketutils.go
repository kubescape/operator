package notificationhandler

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kubescape/operator/utils"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/cluster-notifier-api-go/notificationserver"
	"gopkg.in/mgo.v2/bson"

	"github.com/golang/glog"
)

func parseNotificationCommand(notification interface{}) (*apis.Commands, error) {
	cmds := &apis.Commands{}

	var notificationBytes []byte
	var err error
	switch b := notification.(type) {
	case []byte:
		notificationBytes = b
	default:
		if notificationBytes, err = json.Marshal(notification); err != nil {
			return nil, fmt.Errorf("failed to marshal notification payload from command, reason: %s", err.Error())
		}
	}
	if err = json.Unmarshal(notificationBytes, cmds); err != nil {
		return nil, fmt.Errorf("failed to convert notification payload to commands structure, reason: %s", err.Error())
	}
	return cmds, err
}

func (notification *NotificationHandler) handleNotification(notif *notificationserver.Notification) error {
	dst := notif.Target["dest"] // TODO: move target "dest" so it will be a constant
	switch dst {
	case "trigger", "kubescape": // the "kubescape" is for backward compatibility
		cmds, err := parseNotificationCommand(notif.Notification)
		if err != nil {
			return err
		}
		for _, cmd := range cmds.Commands {
			sessionObj := utils.NewSessionObj(&cmd, "WebSocket", cmd.JobTracking.ParentID, cmd.JobTracking.JobID, 1)
			*notification.sessionObj <- *sessionObj
		}
	}

	return nil

}

func initNotificationServerURL() string {
	urlObj := url.URL{}
	host := utils.ClusterConfig.GatewayWebsocketURL
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
	q.Add(notificationserver.TargetCustomer, utils.ClusterConfig.AccountID)
	q.Add(notificationserver.TargetCluster, utils.ClusterConfig.ClusterName)
	q.Add(notificationserver.TargetComponent, notificationserver.TargetComponentTriggerHandler)
	urlObj.RawQuery = q.Encode()

	return urlObj.String()
}

func (notification *NotificationHandler) websocketPingMessage() error {
	for {
		time.Sleep(30 * time.Second)
		if err := notification.connector.WritePingMessage(); err != nil {
			glog.Errorf("PING, %s", err.Error())
			return fmt.Errorf("PING, %s", err.Error())
		}
	}
}

func decodeJsonNotification(bytesNotification []byte) (*notificationserver.Notification, error) {
	notif := &notificationserver.Notification{}
	if err := json.Unmarshal(bytesNotification, notif); err != nil {
		return nil, err
	}
	return notif, nil
	
}

func decodeBsonNotification(bytesNotification []byte) (*notificationserver.Notification, error) {
	notif := &notificationserver.Notification{}
	if err := bson.Unmarshal(bytesNotification, notif); err != nil {
		return nil, err
	}
	return notif, nil
}
