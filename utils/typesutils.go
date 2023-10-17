package utils

import (
	"context"
	"fmt"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/identifiers"

	"github.com/armosec/utils-go/httputils"
	"github.com/google/uuid"
	beClientV1 "github.com/kubescape/backend/pkg/client/v1"
	beServerV1 "github.com/kubescape/backend/pkg/server/v1"
	"github.com/kubescape/backend/pkg/server/v1/systemreports"
	"github.com/kubescape/operator/config"
)

var (
	ReporterHttpClient httputils.IHttpClient
)

func getRequestHeaders(token string) map[string]string {
	return map[string]string{
		"Content-Type":                "application/json",
		beServerV1.RequestTokenHeader: token,
	}
}

func NewSessionObj(ctx context.Context, config config.IConfig, command *apis.Command, message, parentID, jobID string, actionNumber int) *SessionObj {
	reporter := systemreports.NewBaseReport(config.AccountID(), message)
	target := command.GetID()
	if target == identifiers.DesignatorsToken {
		target = fmt.Sprintf("wlid://cluster-%s/", config.ClusterName())
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
		Reporter: beClientV1.NewBaseReportSender(config.EventReceiverURL(), ReporterHttpClient, getRequestHeaders(config.Token()), reporter),
	}

	sessionObj.Reporter.SendAsRoutine(true)
	return &sessionObj
}

func NewJobTracking(reporter systemreports.IReporter) *apis.JobTracking {
	return &apis.JobTracking{
		JobID:            reporter.GetJobID(),
		ParentID:         reporter.GetParentAction(),
		LastActionNumber: reporter.GetActionIDN() + 1,
	}
}
