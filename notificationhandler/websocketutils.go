package notificationhandler

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/url"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/cluster-notifier-api-go/notificationserver"
	"gopkg.in/mgo.v2/bson"

	"github.com/golang/glog"
)

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
		glog.Error(err)
		return nil, err
	}
	return notif, nil
}

func decodeBsonNotification(bytesNotification []byte) (*notificationserver.Notification, error) {
	notif := &notificationserver.Notification{}
	if err := bson.Unmarshal(bytesNotification, notif); err != nil {
		glog.Error(err)
		return nil, err
	}
	return notif, nil
}

func NewCommands() interface{} {
	cmds := apis.Commands{Commands: []apis.Command{{CommandName: "1234", ResponseID: "1234567"}}}
	fmt.Println(cmds)
	return &cmds
}

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
	dst := notif.Target["dest"]
	switch dst {
	// case "kubescape":
	// 	// sent by this function in dash BE: KubescapeInClusterHandler
	// 	policyNotificationBytes, ok := notif.Notification.([]byte)
	// 	if !ok {
	// 		return fmt.Errorf("handleNotification, kubescape, failed to get policyNotificationBytes")
	// 	}
	// 	policyNotification := &opapolicy.PolicyNotification{}
	// 	if err := json.Unmarshal(policyNotificationBytes, policyNotification); err != nil {
	// 		return fmt.Errorf("handleNotification, kubescape, failed to Unmarshal: %v", err)
	// 	}

	// 	sessionOnj := cautils.NewSessionObj(&apis.Command{
	// 		CommandName: string(policyNotification.NotificationType),
	// 		Designators: []armotypes.PortalDesignator{policyNotification.Designators},
	// 		JobTracking: apis.JobTracking{JobID: policyNotification.JobID},
	// 		Args: map[string]interface{}{
	// 			"kubescapeJobParams": policyNotification.KubescapeJobParams,
	// 			"rules":              policyNotification.Rules},
	// 	}, "WebSocket", "", policyNotification.JobID, 1)
	// 	*notification.sessionObj <- *sessionOnj

	case "trigger", "kubescape":
		cmds, err := parseNotificationCommand(notif.Notification)
		if err != nil {
			return err
		}
		for _, cmd := range cmds.Commands {
			sessionObj := cautils.NewSessionObj(&cmd, "WebSocket", cmd.JobTracking.ParentID, cmd.JobTracking.JobID, 1)
			*notification.sessionObj <- *sessionObj
		}

	case "safeMode":
		safeMode, e := parseSafeModeNotification(notif.Notification)
		if e != nil {
			return e
		}

		// send to pipe
		*notification.safeModeObj <- *safeMode
	}

	return nil

}

func initARMOHelmNotificationServiceURL() string {
	urlObj := url.URL{}
	host := cautils.NotificationServerWSURL
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
	q.Add(notificationserver.TargetCustomer, cautils.ClusterConfig.CustomerGUID)
	q.Add(notificationserver.TargetCluster, cautils.ClusterConfig.ClusterName)
	q.Add(notificationserver.TargetComponent, notificationserver.TargetComponentTriggerHandler)
	urlObj.RawQuery = q.Encode()

	return urlObj.String()
}

func initNotificationServerURL() string {
	urlObj := url.URL{}
	host := cautils.NotificationServerWSURL
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
	q.Add(notificationserver.TargetComponent, notificationserver.TargetComponentTriggerHandler)
	urlObj.RawQuery = q.Encode()

	return urlObj.String()
}

func parseSafeModeNotification(notification interface{}) (*apis.SafeMode, error) {
	safeMode := &apis.SafeMode{}
	notificationBytes, err := json.Marshal(notification)
	if err != nil {
		return safeMode, err
	}

	glog.Infof("Notification: %s", string(notificationBytes))
	if err := json.Unmarshal(notificationBytes, safeMode); err != nil {
		glog.Error(err)
		return safeMode, err
	}
	if safeMode.InstanceID == "" {
		safeMode.InstanceID = safeMode.PodName
	}

	return safeMode, nil
}
