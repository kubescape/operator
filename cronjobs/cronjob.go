package cronjobs

import "os"

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
