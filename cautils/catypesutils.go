package cautils

import (
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"
	reportutils "github.com/armosec/capacketsgo/system-reports/utilities"

	"github.com/armosec/capacketsgo/apis"
	"github.com/armosec/capacketsgo/system-reports/datastructures"
)

func NewSessionObj(command *apis.Command, message, parentID, jobID string, actionNumber int) *SessionObj {
	reporter := reporterlib.NewBaseReport(CA_CUSTOMER_GUID, message)
	reporter.SetTarget(command.GetID())
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

func NewJobTracking(reporter datastructures.IReporter) *apis.JobTracking {
	return &apis.JobTracking{
		JobID:            reporter.GetJobID(),
		ParentID:         reporter.GetParentAction(),
		LastActionNumber: reporter.GetActionIDN() + 1,
	}
}
