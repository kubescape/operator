package utils

import (
	"time"
)

type dummyReportSender struct{}

// newDummyReportSender returns a dummy Report Sender
//
// A dummy report sender stands in for a proper report sender, but does not
// report anywhere
func newDummyReportSender() *dummyReportSender {
	return &dummyReportSender{}
}

func (s *dummyReportSender) GetReportID() string { return "" }

func (s *dummyReportSender) AddError(errorString string) {}
func (s *dummyReportSender) GetNextActionId() string     { return "" }
func (s *dummyReportSender) NextActionID()               {}

func (s *dummyReportSender) SimpleReportAnnotations(setParent bool, setCurrent bool) (string, string) {
	return "", ""
}

func (s *dummyReportSender) SetReporter(string)     {}
func (s *dummyReportSender) SetStatus(string)       {}
func (s *dummyReportSender) SetActionName(string)   {}
func (s *dummyReportSender) SetTarget(string)       {}
func (s *dummyReportSender) SetActionID(string)     {}
func (s *dummyReportSender) SetJobID(string)        {}
func (s *dummyReportSender) SetParentAction(string) {}
func (s *dummyReportSender) SetTimestamp(time.Time) {}
func (s *dummyReportSender) SetActionIDN(int)       {}
func (s *dummyReportSender) SetCustomerGUID(string) {}
func (s *dummyReportSender) SetDetails(string)      {}

func (s *dummyReportSender) GetReporter() string     { return "" }
func (s *dummyReportSender) GetStatus() string       { return "" }
func (s *dummyReportSender) GetActionName() string   { return "" }
func (s *dummyReportSender) GetTarget() string       { return "" }
func (s *dummyReportSender) GetErrorList() []string  { return []string{""} }
func (s *dummyReportSender) GetActionID() string     { return "" }
func (s *dummyReportSender) GetJobID() string        { return "" }
func (s *dummyReportSender) GetParentAction() string { return "" }
func (s *dummyReportSender) GetTimestamp() time.Time {
	return time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
}
func (s *dummyReportSender) GetActionIDN() int       { return -1 }
func (s *dummyReportSender) GetCustomerGUID() string { return "" }
func (s *dummyReportSender) GetDetails() string      { return "" }

func (s *dummyReportSender) Send() (int, string, error) {return 200, "", nil}

func (s *dummyReportSender) SendAsRoutine(bool) {}

func (s *dummyReportSender) SendAction(action string, sendReport bool)                      {}
func (s *dummyReportSender) SendError(err error, sendReport bool, initErrors bool)          {}
func (s *dummyReportSender) SendStatus(status string, sendReport bool)                      {}
func (s *dummyReportSender) SendDetails(details string, sendReport bool)                    {}
func (s *dummyReportSender) SendWarning(warning string, sendReport bool, initWarnings bool) {}
