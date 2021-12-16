package cautils

import (
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	reportutils "github.com/armosec/logger-go/system-reports/utilities"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
)

func NewSessionObj(command *apis.Command, message, parentID, jobID string, actionNumber int) *SessionObj {
	reporter := reporterlib.NewBaseReport(CA_CUSTOMER_GUID, message)
	target := command.GetID()
	if target == armotypes.DesignatorsToken {
		target = CA_CLUSTER_NAME
	}
	reporter.SetTarget(target)
	reporter.SetParentAction(parentID)
	reporter.SetJobID(jobID)
	reporter.SetActionIDN(actionNumber)
	reporter.SendAsRoutine(reportutils.EmptyString, true)

	sessionObj := SessionObj{
		Command:  *command,
		Reporter: reporter,
	}
	return &sessionObj
}

func NewJobTracking(reporter reporterlib.IReporter) *apis.JobTracking {
	return &apis.JobTracking{
		JobID:            reporter.GetJobID(),
		ParentID:         reporter.GetParentAction(),
		LastActionNumber: reporter.GetActionIDN() + 1,
	}
}
