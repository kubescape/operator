package cronjobs

import (
	"k8s-ca-websocket/cautils"

	icacli "github.com/armosec/cacli-wrapper-go/cacli"

	"github.com/golang/glog"
)

func VulnScanCronJob() {
	glog.Infof("starting to run vulnerai scans")
	if client == nil {
		client = icacli.NewCacli(cautils.CA_DASHBOARD_BACKEND, false)
	}
	status, err := client.Status()
	if err != nil || !status.LoggedIn {
		glog.Infof("probably need to relog")

		if err := client.Login(); err != nil {
			glog.Errorf("unable to login to cacli in order to perform cluster posture scans")
		}
	}

	glog.Infof("starting to run vulnerai scans")
	if err := client.VulnerabilityScan(cautils.CA_CLUSTER_NAME, "", "", nil); err != nil {
		glog.Error(err)
	}
	// client.
}
