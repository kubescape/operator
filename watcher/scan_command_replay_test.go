package watcher

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/backend/pkg/command"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestOperatorCommandReceiverRegisteredBeforeStartupList(t *testing.T) {
	watcher := &CommandWatchHandler{commandReceivers: mapset.NewSet[chan v1alpha1.OperatorCommand]()}
	handler := NewOperatorCommandsHandler(context.Background(), nil, nil, watcher, nil)
	require.Equal(t, 1, watcher.commandReceivers.Cardinality(), "startup list can run before handler Start")
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	body, err := json.Marshal(apis.Command{CommandName: apis.TypeRunKubescape})
	require.NoError(t, err)
	opcmd := v1alpha1.OperatorCommand{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request", CreationTimestamp: metav1.NewTime(time.Now().Add(-31 * time.Minute))},
		Spec:       v1alpha1.OperatorCommandSpec{CommandType: string(command.OperatorCommandTypeOperatorAPI), Body: body},
		Status:     v1alpha1.OperatorCommandStatus{Started: true, Completed: false, Payload: []byte(scanID)},
	}
	data, err := json.Marshal(opcmd)
	require.NoError(t, err)
	var object map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &object))
	watcher.AddHandler(&unstructured.Unstructured{Object: object})
	select {
	case delivered := <-handler.commands:
		require.Equal(t, []byte(scanID), delivered.Status.Payload)
	default:
		t.Fatal("startup list dropped the pending scan before handler Start")
	}
}

func TestOldPendingScanIsDeliveredForOutcomeRecovery(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	body, err := json.Marshal(apis.Command{CommandName: apis.TypeRunKubescape})
	require.NoError(t, err)
	command := v1alpha1.OperatorCommand{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request", CreationTimestamp: metav1.NewTime(time.Now().Add(-31 * time.Minute))},
		Spec:       v1alpha1.OperatorCommandSpec{CommandType: string(command.OperatorCommandTypeOperatorAPI), Body: body},
		Status:     v1alpha1.OperatorCommandStatus{Started: true, Completed: false, Payload: []byte(scanID)},
	}
	data, err := json.Marshal(command)
	require.NoError(t, err)
	var object map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &object))
	receiver := make(chan v1alpha1.OperatorCommand, 1)
	watcher := &CommandWatchHandler{commandReceivers: mapset.NewSet[chan v1alpha1.OperatorCommand]()}
	watcher.RegisterForCommands(receiver)
	watcher.AddHandler(&unstructured.Unstructured{Object: object})
	select {
	case delivered := <-receiver:
		require.Equal(t, []byte(scanID), delivered.Status.Payload)
	default:
		t.Fatal("unfinished scan with a stored scan ID was not delivered for recovery")
	}
}
