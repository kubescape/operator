package cautils

import (
	"fmt"

	icacli "github.com/armosec/cacli-wrapper-go/cacli"
	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"
	"github.com/armosec/utils-go/boolutils"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/cluster-notifier-api-go/notificationserver"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"

	"github.com/golang/glog"
)

var (
	CAInitContainerName = "ca-init-container"
)

const KubescapeRequestPathV1 = "v1/scan"

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

	safeModeURL := fmt.Sprintf("http://%s/v1/sendnotification", ClusterConfig.NotificationRestURL)
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
	return icacli.NewCacli(ClusterConfig.Dashboard, false)
}

func GetStartupActins() []apis.Command {
	if SystemMode == SystemModeScan {
		return []apis.Command{
			{
				CommandName: string(apis.TypeRunKubescape),
				Args: map[string]interface{}{
					KubescapeRequestPathV1: utilsmetav1.PostScanRequest{
						Submit: boolutils.BoolPointer(true),
					},
				},
			},
			{
				CommandName: apis.SCAN,
				WildWlid:    pkgwlid.GetK8sWLID(ClusterConfig.ClusterName, "", "", ""),
			},
		}
	}
	return []apis.Command{}
}
