package cautils

import (
	"fmt"

	icacli "github.com/armosec/cacli-wrapper-go/cacli"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/cluster-notifier-api-go/notificationserver"

	"github.com/golang/glog"
)

var (
	CAInitContainerName = "ca-init-container"
)

func MapToString(m map[string]interface{}) []string {
	s := []string{}
	for i := range m {
		s = append(s, i)
	}
	return s
}

func SendSafeModeReport(sessionObj *SessionObj, message string, code int) {
	safeMode := apis.SafeMode{}

	safeMode.JobID = sessionObj.Reporter.GetJobID()
	safeMode.Wlid = sessionObj.Reporter.GetTarget()
	safeMode.Reporter = "Websocket"
	safeMode.StatusCode = code
	safeMode.Message = message

	safeModeURL := fmt.Sprintf("http://%s/v1/sendnotification", NotificationServerRESTURL)
	target := map[string]string{notificationserver.TargetComponent: notificationserver.TargetComponentLoggerValue}

	// pushing notification
	if err := notificationserver.PushNotificationServer(safeModeURL, target, safeMode, true); err != nil {
		glog.Error(err)
		return
	}
}

func NewCacliObj() icacli.ICacli {
	if SystemMode == SystemModeScan {
		return icacli.NewCacliWithoutLogin()
	}
	return icacli.NewCacli(CA_DASHBOARD_BACKEND, false)
}
