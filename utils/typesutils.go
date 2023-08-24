package utils

import (
	"context"
	"fmt"

	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	"github.com/armosec/utils-go/httputils"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/identifiers"
)

var ReporterHttpClient httputils.IHttpClient

func NewSessionObj(ctx context.Context, clusterConfig utilsmetadata.ClusterConfig, command *apis.Command, message, parentID, jobID string, actionNumber int) *SessionObj {
	reporter := reporterlib.NewBaseReport(clusterConfig.AccountID, message, clusterConfig.EventReceiverRestURL, ReporterHttpClient)
	target := command.GetID()
	if target == identifiers.DesignatorsToken {
		target = fmt.Sprintf("wlid://cluster-%s/", clusterConfig.ClusterName)
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
	go sessionObj.WatchErrors(ctx)

	reporter.SendAsRoutine(true, sessionObj.ErrChan)
	return &sessionObj
}

func (sessionObj *SessionObj) WatchErrors(ctx context.Context) {
	for err := range sessionObj.ErrChan {
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to send job report", helpers.Error(err))
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
