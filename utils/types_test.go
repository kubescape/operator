package utils

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newSessionWithPatchCapture(t *testing.T) (*SessionObj, *[]byte) {
	t.Helper()
	dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	var capturedPatch []byte
	dynClient.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction, ok := action.(k8stesting.PatchAction)
		require.True(t, ok)
		capturedPatch = append([]byte(nil), patchAction.GetPatch()...)
		return true, nil, nil
	})

	session := &SessionObj{
		ParentCommandDetails: &OperatorCommandDetails{
			Command: &v1alpha1.OperatorCommand{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cmd-1",
					Namespace: "kubescape",
				},
			},
			StartedAt: time.Now().Add(-time.Second),
			Client:    &k8sinterface.KubernetesApi{DynamicClient: dynClient},
		},
	}
	return session, &capturedPatch
}

func decodeStatusPatch(t *testing.T, patch []byte) v1alpha1.OperatorCommandStatus {
	t.Helper()
	require.NotEmpty(t, patch)
	var body struct {
		Status v1alpha1.OperatorCommandStatus `json:"status"`
	}
	require.NoError(t, json.Unmarshal(patch, &body))
	return body.Status
}

func TestSetOperatorCommandStatus_NilGuards(t *testing.T) {
	ctx := context.Background()

	assert.NotPanics(t, func() {
		var nilSession *SessionObj
		nilSession.SetOperatorCommandStatus(ctx, WithSuccess())

		(&SessionObj{}).SetOperatorCommandStatus(ctx, WithSuccess())
		(&SessionObj{ParentCommandDetails: &OperatorCommandDetails{}}).SetOperatorCommandStatus(ctx, WithSuccess())
		(&SessionObj{
			ParentCommandDetails: &OperatorCommandDetails{
				Command: &v1alpha1.OperatorCommand{},
				Client:  &k8sinterface.KubernetesApi{},
			},
		}).SetOperatorCommandStatus(ctx, WithSuccess())
	})
}

func TestSetOperatorCommandStatus_SuccessAndPayload(t *testing.T) {
	session, captured := newSessionWithPatchCapture(t)
	payload := []byte(`{"result":"ok"}`)

	session.SetOperatorCommandStatus(context.Background(), nil, WithSuccess(), WithPayload(payload))

	status := decodeStatusPatch(t, *captured)
	assert.Equal(t, "operator", status.Executer)
	assert.True(t, status.Started)
	assert.True(t, status.Completed)
	assert.Nil(t, status.Error)
	assert.Equal(t, payload, status.Payload)
}

func TestSetOperatorCommandStatus_WithErrorAndNilError(t *testing.T) {
	t.Run("nil error does not panic and leaves error empty", func(t *testing.T) {
		session, captured := newSessionWithPatchCapture(t)
		assert.NotPanics(t, func() {
			session.SetOperatorCommandStatus(context.Background(), WithError(nil))
		})
		status := decodeStatusPatch(t, *captured)
		assert.Nil(t, status.Error)
	})

	t.Run("single error sets status error message", func(t *testing.T) {
		session, captured := newSessionWithPatchCapture(t)
		session.SetOperatorCommandStatus(context.Background(), WithError(errors.New("scan failed")))
		status := decodeStatusPatch(t, *captured)
		require.NotNil(t, status.Error)
		assert.Equal(t, "scan failed", status.Error.Message)
	})
}

func TestSetOperatorCommandStatus_MultipleErrorsFiltersNil(t *testing.T) {
	t.Run("multiple non-nil errors with nil entries", func(t *testing.T) {
		session, captured := newSessionWithPatchCapture(t)
		session.SetOperatorCommandStatus(
			context.Background(),
			WithMultipleErrors([]error{errors.New("first"), nil, errors.New("second")}),
		)

		status := decodeStatusPatch(t, *captured)
		require.NotNil(t, status.Error)
		assert.Equal(t, "Failed with multiple errors", status.Error.Message)

		var msgs []string
		require.NoError(t, json.Unmarshal(status.Payload, &msgs))
		assert.Equal(t, []string{"first", "second"}, msgs)
	})

	t.Run("single non-nil error after filtering nil", func(t *testing.T) {
		session, captured := newSessionWithPatchCapture(t)
		session.SetOperatorCommandStatus(
			context.Background(),
			WithMultipleErrors([]error{nil, errors.New("only-one")}),
		)

		status := decodeStatusPatch(t, *captured)
		require.NotNil(t, status.Error)
		assert.Equal(t, "only-one", status.Error.Message)
	})
}
