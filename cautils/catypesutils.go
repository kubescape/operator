package cautils

import (
	"fmt"

	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	reportutils "github.com/armosec/logger-go/system-reports/utilities"
	"github.com/golang/glog"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
)

func NewSessionObj(command *apis.Command, message, parentID, jobID string, actionNumber int) *SessionObj {
	reporter := reporterlib.NewBaseReport(CA_CUSTOMER_GUID, message)
	target := command.GetID()
	if target == armotypes.DesignatorsToken {
		target = fmt.Sprintf("wlid://cluster-%s/", CA_CLUSTER_NAME)
	}
	reporter.SetTarget(target)

	reporter.SetJobID(jobID)
	reporter.SetParentAction(parentID)
	reporter.SetActionIDN(actionNumber)
	if command.CommandName != "" {
		reporter.SetActionName(string(command.CommandName))
	}

	sessionObj := SessionObj{
		Command:  *command,
		Reporter: reporter,
		ErrChan:  make(chan error),
	}
	go sessionObj.WatchErrors()

	reporter.SendAsRoutine(reportutils.EmptyString, true, sessionObj.ErrChan)
	return &sessionObj
}

func (sessionObj *SessionObj) WatchErrors() {
	for err := range sessionObj.ErrChan {
		if err != nil {
			glog.Errorf("failed to send job report due to: %s", err.Error())
		}
	}
}

func NewJobTracking(reporter reporterlib.IReporter) *apis.JobTracking {
	return &apis.JobTracking{
		JobID:            reporter.GetJobID(),
		ParentID:         reporter.GetParentAction(),
		LastActionNumber: reporter.GetActionIDN() + 1,
	}
}
