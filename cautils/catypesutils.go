package cautils

import (
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"
	reportutils "github.com/armosec/capacketsgo/system-reports/utilities"
)

func NewSessionObj(command *Command, message string) *SessionObj {
	reporter := reporterlib.NewBaseReport(CA_CUSTOMER_GUID, message)
	reporter.SetTarget(command.Wlid)
	reporter.SendAsRoutine(reportutils.EmptyString, true)

	sessionObj := SessionObj{
		Command:  *command,
		Reporter: reporter,
	}
	return &sessionObj
}
