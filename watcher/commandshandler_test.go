package watcher

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/command"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvokeCommandCarriesTheJobTrackingOfTheBody(t *testing.T) {
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	sessions := make(chan utils.SessionObj, 1)
	pool, err := ants.NewPoolWithFunc(1, func(i interface{}) {
		job := i.(utils.Job)
		sessions <- job.Obj()
	})
	require.NoError(t, err)
	defer pool.Release()
	handler := &OperatorCommandsHandler{ctx: context.Background(), pool: pool, config: cfg}

	tests := []struct {
		name       string
		tracking   apis.JobTracking
		guid       string
		wantJob    string
		wantParent string
	}{
		{name: "parent id from the body, job id from the GUID", tracking: apis.JobTracking{JobID: "job-1", ParentID: "parent-1"}, guid: "guid-1", wantJob: "guid-1", wantParent: "parent-1"},
		{name: "no tracking in the body", guid: "guid-2", wantJob: "guid-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(apis.Command{CommandName: apis.TypeRunKubescape, JobTracking: tt.tracking})
			require.NoError(t, err)
			handler.invokeCommand(context.Background(), v1alpha1.OperatorCommand{Spec: v1alpha1.OperatorCommandSpec{
				GUID:        tt.guid,
				CommandType: string(command.OperatorCommandTypeOperatorAPI),
				Body:        body,
			}})
			select {
			case session := <-sessions:
				assert.Equal(t, tt.wantJob, session.JobID)
				assert.Equal(t, tt.wantParent, session.ParentJobID)
				assert.Equal(t, apis.TypeRunKubescape, session.Command.CommandName)
			case <-time.After(5 * time.Second):
				t.Fatal("the command was not handed to the worker pool")
			}
		})
	}
}
