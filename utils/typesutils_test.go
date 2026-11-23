package utils

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/google/uuid"
	beServerV1 "github.com/kubescape/backend/pkg/server/v1"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRequestHeaders(t *testing.T) {
	headers := GetRequestHeaders("my-access-key")
	assert.Equal(t, "application/json", headers["Content-Type"])
	assert.Equal(t, "my-access-key", headers[beServerV1.AccessKeyHeader])
}

func TestNewSessionObj(t *testing.T) {
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{},
		utilsmetadata.ClusterConfig{AccountID: "acc-123"},
		&beUtils.Credentials{Account: "acc-123"},
		config.Config{},
	)
	require.NoError(t, err)

	cmd := &apis.Command{CommandName: apis.TypeRunKubescape}

	t.Run("preserves explicit jobID and extracts account ID", func(t *testing.T) {
		s := NewSessionObj(context.Background(), cfg, cmd, "parent-1", "job-1")
		require.NotNil(t, s)
		assert.Equal(t, "acc-123", s.CustomerGUID)
		assert.Equal(t, "job-1", s.JobID)
		assert.Equal(t, "parent-1", s.ParentJobID)
		assert.Same(t, cmd, s.Command)
		assert.False(t, s.Timestamp.IsZero())
	})

	t.Run("generates UUID when jobID is empty", func(t *testing.T) {
		s := NewSessionObj(context.Background(), cfg, cmd, "parent-1", "")
		require.NotNil(t, s)
		_, parseErr := uuid.Parse(s.JobID)
		assert.NoError(t, parseErr)
	})

	t.Run("nil config does not panic", func(t *testing.T) {
		var s *SessionObj
		assert.NotPanics(t, func() {
			s = NewSessionObj(context.Background(), nil, cmd, "parent-1", "job-2")
		})
		require.NotNil(t, s)
		assert.Empty(t, s.CustomerGUID)
		assert.Equal(t, "job-2", s.JobID)
	})
}

func TestSetOperatorCommandDetails(t *testing.T) {
	assert.NotPanics(t, func() {
		var nilSession *SessionObj
		nilSession.SetOperatorCommandDetails(&OperatorCommandDetails{})
	})

	s := &SessionObj{}
	details := &OperatorCommandDetails{StartedAt: time.Now()}
	s.SetOperatorCommandDetails(details)
	assert.Same(t, details, s.ParentCommandDetails)
}

func TestJobGettersAndSetters(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "val")
	obj := SessionObj{JobID: "job-42", CustomerGUID: "cust-1"}

	var j Job
	j.SetContext(ctx)
	j.SetObj(obj)

	assert.Equal(t, "val", j.Context().Value(ctxKey{}))
	assert.Equal(t, "job-42", j.Obj().JobID)
	assert.Equal(t, "cust-1", j.Obj().CustomerGUID)
}
