package restapihandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionRequest_InvalidJSONReturnsInternalServerError(t *testing.T) {
	handler := NewHTTPHandler(nil, telemetryConfig{})
	req := httptest.NewRequest(http.MethodPost, "/v1/triggerAction", strings.NewReader(`{invalid-json`))
	w := httptest.NewRecorder()

	handler.ActionRequest(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotEmpty(t, w.Body.String())
}

func TestHandleActionRequest_SkipsEmptyCommandNameAndDispatchesValidCommands(t *testing.T) {
	jobs := make(chan utils.Job, 4)
	pool, err := ants.NewPoolWithFunc(2, func(value interface{}) {
		jobs <- value.(utils.Job)
	})
	require.NoError(t, err)
	defer pool.Release()

	handler := NewHTTPHandler(pool, telemetryConfig{})
	payload := `{
		"commands": [
			{"commandName": ""},
			{
				"commandName": "kubescapeScan",
				"jobTracking": {"jobID": "job-1", "parentID": "parent-1"},
				"args": {"secret": "should-be-redacted-in-logs"}
			},
			{
				"commandName": "scan",
				"jobTracking": {"jobID": "job-2"}
			}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/triggerAction", strings.NewReader(payload))
	w := httptest.NewRecorder()
	handler.ActionRequest(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())

	received := make(map[string]utils.SessionObj, 2)
	for i := 0; i < 2; i++ {
		select {
		case job := <-jobs:
			obj := job.Obj()
			received[obj.JobID] = obj
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for dispatched job")
		}
	}

	require.Contains(t, received, "job-1")
	assert.Equal(t, apis.TypeCommand("kubescapeScan"), received["job-1"].Command.CommandName)
	assert.Equal(t, "parent-1", received["job-1"].ParentJobID)
	assert.Equal(t, "test-account", received["job-1"].CustomerGUID)
	assert.Equal(t, "should-be-redacted-in-logs", received["job-1"].Command.Args["secret"])

	require.Contains(t, received, "job-2")
	assert.Equal(t, apis.TypeCommand("scan"), received["job-2"].Command.CommandName)
}

func TestHandleActionRequest_PoolErrors(t *testing.T) {
	t.Run("nil pool returns error instead of panicking", func(t *testing.T) {
		handler := NewHTTPHandler(nil, telemetryConfig{})
		req := httptest.NewRequest(http.MethodPost, "/v1/triggerAction", strings.NewReader(`{"commands":[{"commandName":"kubescapeScan"}]}`))
		w := httptest.NewRecorder()

		assert.NotPanics(t, func() {
			handler.ActionRequest(w, req)
		})
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "worker pool is not initialized")
	})

	t.Run("released pool returns error", func(t *testing.T) {
		pool, err := ants.NewPoolWithFunc(1, func(_ interface{}) {})
		require.NoError(t, err)
		pool.Release()

		handler := NewHTTPHandler(pool, telemetryConfig{})
		err = handler.HandleActionRequest(context.Background(), []byte(`{"commands":[{"commandName":"kubescapeScan"}]}`))
		require.Error(t, err)
	})
}

func TestDisplayReceivedCommand(t *testing.T) {
	assert.NotPanics(t, func() {
		displayReceivedCommand([]byte(`invalid json`))
		displayReceivedCommand([]byte(`{"commands":[{"commandName":"kubescapeScan","args":{"token":"secret"}}]}`))
	})
}
