package websocket

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"
	"os"

	reporterlib "asterix.cyberarmor.io/cyberarmor/capacketsgo/system-reports/datastructures"

	"github.com/golang/glog"
)

var previousReports []string

var (
	// UPDATE workload
	UPDATE = "update"
	// REMOVE workload
	REMOVE = "remove"
	// SIGN image
	SIGN = "sign"
	// INJECT namespace
	INJECT = "inject"
	// RESTART pod
	RESTART = "restart"

	CALabel = "cyberarmor"

	CAInjectOld = "injectCyberArmor"
	CAWlidOld   = "wlid"

	CAPrefix = "cyberarmor"
	CAInject = CAPrefix + ".inject"

	// annotation related
	CAStatus   = CAPrefix + ".status"
	CAAttached = CAPrefix + ".attached"
	CASigned   = CAPrefix + ".signed"
	CAWlid     = CAPrefix + ".wlid"
	CAUpdate   = CAPrefix + ".last-update"
	CAIgnoe    = CAPrefix + ".ignore"
)
var (
	controllerLable = "controller-uid"
)

// HandlePostmanRequest Parse received commands and run the command
func (wsh *WebSocketHandler) HandlePostmanRequest(receivedCommands []byte) []error {
	commands := cautils.Commands{}
	errorList := []error{}

	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
		return []error{err}
	}
	for _, c := range commands.Commands {
		if c.CommandName == "" {
			err := fmt.Errorf("command not found. wlid: %s", c.Wlid)
			glog.Error(err)
			return []error{err}
		}
		if c.Wlid == "" {
			err := fmt.Errorf("wlid not found. command: %s", c.CommandName)
			glog.Error(err)
			return []error{err}
		}
		if err := cautils.IsWalidValid(c.Wlid); err != nil {
			err := fmt.Errorf("invalid: %s, wlid: %s", err.Error(), c.Wlid)
			glog.Error(err)
			return []error{err}
		}
		status := "SUCCESS"
		glog.Infof("Running %s command, wlid: %s", c.CommandName, c.Wlid)
		if err := wsh.runCommand(c); err != nil {
			glog.Errorf("%v", err)
			status = "FAIL"
			errorList = append(errorList, err)
		}
		glog.Infof("Done command %s, wlid: %s, status: %s", c.CommandName, c.Wlid, status)

	}
	return errorList
}
func (wsh *WebSocketHandler) runCommand(c cautils.Command) error {
	reporter := reporterlib.BaseReport{ActionID: "2", ActionIDN: 1, Reporter: "websocket", Status: reporterlib.JobStarted, Target: c.Wlid}
	if jobid, hasJobID := c.Args["jobID"]; hasJobID {
		reporter.JobID = fmt.Sprintf("%v", jobid)
	}
	switch c.CommandName {
	case UPDATE:
		glog.Infof("in update/attach")
		reporter.ActionName = "attach(inject wlid)"
		reporter.SendAsRoutine(previousReports, true)
		er := updateWorkload(c.Wlid, UPDATE, &c)
		if er != nil {
			reporter.AddError(er.Error())
			reporter.Status = reporterlib.JobFailed
		} else {
			reporter.Status = reporterlib.JobSuccess
		}
		reporter.SendAsRoutine(previousReports, true)
		return er
	case RESTART:
		reporter.ActionName = "update(resetart)"
		reporter.SendAsRoutine(previousReports, true)
		er := updateWorkload(c.Wlid, RESTART, &c)
		if er != nil {
			reporter.AddError(er.Error())
			reporter.Status = reporterlib.JobFailed
		} else {
			reporter.Status = reporterlib.JobSuccess
		}
		reporter.SendAsRoutine(previousReports, true)
		return er
	case REMOVE:
		reporter.ActionName = "detach"
		reporter.SendAsRoutine(previousReports, true)
		return detachWorkload(c.Wlid)
	case SIGN:
		reporter.ActionName = "sign"
		reporter.SendAsRoutine(previousReports, true)
		er := signWorkload(c.Wlid)
		if er != nil {
			reporter.AddError(er.Error())
			reporter.Status = reporterlib.JobFailed
		} else {
			reporter.Status = reporterlib.JobSuccess
		}
		reporter.SendAsRoutine(previousReports, true)
		return er
	case INJECT:
		return updateWorkload(c.Wlid, INJECT, &c)
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func detachWorkload(wlid string) error {
	// if cautils.GetKindFromWlid(wlid) != "Namespace" {
	// 	// add wlid to the ignore list
	// 	ns := cautils.GetNamespaceFromWlid(wlid)
	// 	namespaceWlid := cautils.GetWLID(cautils.GetClusterFromWlid(wlid), ns, "Namespace", ns)
	// 	if err := excludeWlid(namespaceWlid, wlid); err != nil { // add wlid to the namespace ignore list
	// 		return err
	// 	}
	// }
	return updateWorkload(wlid, REMOVE, &cautils.Command{})
}

func attachWorkload(wlid string) error {
	// if cautils.GetKindFromWlid(wlid) != "Namespace" {
	// 	// remove wlid from the ignore list
	// 	ns := cautils.GetNamespaceFromWlid(wlid)
	// 	namespaceWlid := cautils.GetWLID(cautils.GetClusterFromWlid(wlid), ns, "Namespace", ns)
	// 	if err := includeWlid(namespaceWlid, wlid); err != nil { // add wlid to the namespace ignore list
	// 		return err
	// 	}
	// }
	return updateWorkload(wlid, REMOVE, &cautils.Command{})
}
func signWorkload(wlid string) error {
	var err error
	workload, err := getWorkload(wlid)
	if err != nil {
		return err
	}

	vulnScanURL, found := os.LookupEnv("CA_VULNSCAN")
	if found {
		go sendWorkloadToVulnerabilityScanner(vulnScanURL, wlid)
	}

	s := sign.NewSigner(wlid)
	if cautils.CA_USE_DOCKER {
		err = s.SignImageDocker(workload)
	} else {
		err = s.SignImageOcimage(workload)
	}
	if err != nil {
		return err
	}

	glog.Infof("Done signing, updating workload, wlid: %s", wlid)
	// err = updateWorkload(wlid, SIGN)
	return err
}
