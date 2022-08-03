package cautils

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	"github.com/golang/glog"
	"github.com/google/uuid"

	"github.com/armosec/armoapi-go/apis"
)

func NewSessionObj(command *apis.Command, message, parentID, jobID string, actionNumber int) *SessionObj {
	reporter := reporterlib.NewBaseReport(AccountID, message)
	target := command.GetID()
	if target == apitypes.DesignatorsToken {
		target = fmt.Sprintf("wlid://cluster-%s/", ClusterName)
	}
	if target == "" {
		target = fmt.Sprintf("%v", command.Args)
	}
	reporter.SetTarget(target)

	if jobID == "" {
		jobID = uuid.NewString()
	}
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

	reporter.SendAsRoutine(true, sessionObj.ErrChan)
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
