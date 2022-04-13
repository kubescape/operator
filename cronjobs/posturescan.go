package cronjobs

import (
	"k8s-ca-websocket/cautils"

	icacli "github.com/armosec/cacli-wrapper-go/cacli"

	"github.com/golang/glog"
)

var client *icacli.Cacli

func PostureScanCronJob() {
	frameworks := loadFrameworks()

	if client == nil {
		client = icacli.NewCacli(cautils.CA_DASHBOARD_BACKEND, false)
	}
	status, err := client.Status()
	if err != nil || !status.LoggedIn {
		if err := client.Login(); err != nil {
			glog.Errorf("unable to login to cacli in order to perform cluster posture scans")
		}
	}

	for _, framework := range frameworks {
		go func(framework string) {
			glog.Infof("running %v framework posture scan on cluster", framework)
			if err := client.RunPostureScan(framework, cautils.CA_CLUSTER_NAME); err != nil {
				glog.Errorf("running posture framework %s failed due to: %v", framework, err.Error())
			}
		}(framework)

	}
}

func loadFrameworks() []string {
	return []string{"MITRE"}
}
