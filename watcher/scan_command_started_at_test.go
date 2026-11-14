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
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestReplayedPendingScanKeepsOriginalStartedAtInCommandStatus(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	originalStart := metav1.NewTime(time.Now().Add(-31 * time.Minute).Truncate(time.Second))
	body, err := json.Marshal(apis.Command{CommandName: apis.TypeRunKubescape})
	require.NoError(t, err)
	opcmd := v1alpha1.OperatorCommand{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request", CreationTimestamp: originalStart},
		Spec:       v1alpha1.OperatorCommandSpec{CommandType: string(command.OperatorCommandTypeOperatorAPI), Body: body},
		Status: v1alpha1.OperatorCommandStatus{Started: true, Completed: false, StartedAt: &originalStart,
			Payload: []byte(scanID)},
	}
	encoded, err := json.Marshal(opcmd)
	require.NoError(t, err)
	var object map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &object))

	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	patched := make(chan v1alpha1.OperatorCommandStatus, 1)
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patched <- body.Status
		return true, &unstructured.Unstructured{}, nil
	})
	k8sAPI := &k8sinterface.KubernetesApi{DynamicClient: dynamic}
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := ants.NewPoolWithFunc(1, func(input interface{}) {
		job := input.(utils.Job)
		session := job.Obj()
		session.SetOperatorCommandStatus(job.Context(), utils.WithSuccess(), utils.WithPayload([]byte(scanID)))
	})
	require.NoError(t, err)
	defer pool.Release()
	commandWatcher := NewCommandWatchHandler(k8sAPI, cfg)
	operatorHandler := NewOperatorCommandsHandler(ctx, pool, k8sAPI, commandWatcher, cfg)
	go operatorHandler.Start()
	require.Eventually(t, func() bool { return commandWatcher.commandReceivers.Cardinality() == 1 }, time.Second, time.Millisecond)
	commandWatcher.AddHandler(&unstructured.Unstructured{Object: object})
	select {
	case status := <-patched:
		require.NotNil(t, status.StartedAt)
		require.Equal(t, originalStart.Time, status.StartedAt.Time)
	case <-time.After(time.Second):
		t.Fatal("replayed OperatorCommand did not update its status")
	}
}
