package cautils

import (
	reporterlib "asterix.cyberarmor.io/cyberarmor/capacketsgo/system-reports/datastructures"
	reportutils "asterix.cyberarmor.io/cyberarmor/capacketsgo/system-reports/utilities"
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
