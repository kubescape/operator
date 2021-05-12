package cronjobs

import (
	"os"

	"github.com/robfig/cron"

	"github.com/golang/glog"
)

// New returns a new Cron job runner, in the Local time zone.
func StartCronJob() {
	glog.Infof("starting websocket cronjobs")
	cronjobmgr := cron.New()
	glog.Infof("starting posture scan in main")
	cronjobmgr.AddFunc(GetPostureScanSchedule(), PostureScanCronJob)
	glog.Infof("starting vuln scan in main")

	cronjobmgr.AddFunc(GetPvulnerabilityScanSchedule(), VulnScanCronJob)

	cronjobmgr.Start()
}

func GetPostureScanSchedule() string {
	posturescanSchedule := os.Getenv("CA_POSTURE_SCAN_SCHEDULE")
	if len(posturescanSchedule) == 0 {
		posturescanSchedule = "@every 12h"
	}
	return posturescanSchedule
}

func GetPvulnerabilityScanSchedule() string {
	vulnScanSchedule := os.Getenv("CA_VULN_SCAN_SCHEDULE")
	if len(vulnScanSchedule) == 0 {
		vulnScanSchedule = "@every 11h"
	}
	return vulnScanSchedule
}
