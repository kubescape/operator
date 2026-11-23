package utils

import (
	"context"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/google/uuid"
	beServerV1 "github.com/kubescape/backend/pkg/server/v1"
	"github.com/kubescape/operator/config"
)

func GetRequestHeaders(accessKey string) map[string]string {
	return map[string]string{
		"Content-Type":             "application/json",
		beServerV1.AccessKeyHeader: accessKey,
	}
}

func NewSessionObj(ctx context.Context, config config.IConfig, command *apis.Command, parentJobId, jobID string) *SessionObj {
	var customerGUID string
	if config != nil {
		customerGUID = config.AccountID()
	}
	sessionObj := SessionObj{
		CustomerGUID: customerGUID,
		JobID:        jobID,
		ParentJobID:  parentJobId,
		Command:      command,
		Timestamp:    time.Now(),
	}

	if jobID == "" {
		sessionObj.JobID = uuid.NewString()
	}

	return &sessionObj
}

func (s *SessionObj) SetOperatorCommandDetails(opcmd *OperatorCommandDetails) {
	if s == nil {
		return
	}
	s.ParentCommandDetails = opcmd
}
