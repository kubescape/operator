package cautils

import (
	"fmt"

	icacli "github.com/armosec/cacli-wrapper-go/cacli"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/cluster-notifier-api-go/notificationserver"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"

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

func NewCacliObj(systemModeRunner SystemModeRunner) icacli.ICacli {
	if systemModeRunner == SystemModeScan {
		return icacli.NewCacliWithoutLogin()
	}
	return icacli.NewCacli(CA_DASHBOARD_BACKEND, false)
}

func GetStartupActins() []apis.Command {
	if SystemMode == SystemModeScan {
		return []apis.Command{
			{
				CommandName: apis.SCAN,
				WildWlid:    pkgwlid.GetK8sWLID(CA_CLUSTER_NAME, "", "", ""),
			},
		}
	}
	return []apis.Command{}
}
