package mainhandler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/continuousscanning"
	"github.com/kubescape/operator/utils"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
)

func TestOperatorControlExclusions(t *testing.T) {
	args := map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{
		"targetType": "framework", "targetNames": []string{"nsa"},
		"excludeControls": []string{"C-0070"},
	}}
	request, err := getKubescapeV1ScanRequest(args, nil, nil)
	require.NoError(t, err)
	body, err := json.Marshal(request)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &fields))
	require.JSONEq(t, `["C-0070"]`, string(fields["excludeControls"]))
}

func TestOperatorControlExclusionsDefaultsAndReplay(t *testing.T) {
	defaults := []string{" C-0069 "}
	tests := []struct {
		name      string
		payload   interface{}
		want      []string
		wantError bool
	}{
		{"absent", map[string]interface{}{}, []string{"C-0069"}, false},
		{"empty", map[string]interface{}{"excludeControls": []string{}}, []string{"C-0069"}, false},
		{"null", map[string]interface{}{"excludeControls": nil}, []string{"C-0069"}, false},
		{"union", map[string]interface{}{"excludeControls": []string{"c-0069", " C-0070 "}}, []string{"C-0069", "C-0070"}, false},
		{"blank", map[string]interface{}{"excludeControls": []string{" "}}, nil, true},
		{"wrong type", map[string]interface{}{"excludeControls": "C-0070"}, nil, true},
		{"null entry", map[string]interface{}{"excludeControls": []interface{}{nil}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{utils.KubescapeScanV1: tt.payload}
			request, err := getKubescapeV1ScanRequest(args, nil, defaults)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, request.ExcludeControls)
			data, err := wrapRequestWithCommand(request)
			require.NoError(t, err)
			var commands apis.Commands
			require.NoError(t, json.Unmarshal(data, &commands))
			replayed, err := getKubescapeV1ScanRequest(commands.Commands[0].Args, nil, defaults)
			require.NoError(t, err)
			require.Equal(t, request, replayed)
			request.ExcludeControls[0] = "changed"
			require.Equal(t, []string{" C-0069 "}, defaults)
		})
	}
	_, err := getKubescapeV1ScanRequest(map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{}}, nil, []string{" "})
	require.Error(t, err)
}

func TestContinuousControlExclusions(t *testing.T) {
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{ClusterName: "test"}, nil, config.Config{ExcludeControls: []string{"C-0069"}})
	require.NoError(t, err)
	jobs := make(chan utils.Job, 1)
	pool, err := ants.NewPoolWithFunc(1, func(value interface{}) { jobs <- value.(utils.Job) })
	require.NoError(t, err)
	defer pool.Release()
	object := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]interface{}{"name": "example", "namespace": "default"},
		"spec": map[string]interface{}{"containers": []interface{}{map[string]interface{}{"name": "app", "image": "nginx"}}},
	}}
	for _, eventType := range []watch.EventType{watch.Added, watch.Modified, watch.Deleted} {
		t.Run(string(eventType), func(t *testing.T) {
			handler := continuousscanning.NewTriggeringHandler(pool, cfg)
			if eventType == watch.Deleted {
				handler = continuousscanning.NewDeletedCleanerHandler(pool, cfg, storagefake.NewSimpleClientset())
			}
			require.NoError(t, handler.Handle(context.Background(), watch.Event{Type: eventType, Object: object}))
			select {
			case job := <-jobs:
				request, err := getKubescapeV1ScanRequest(job.Obj().Command.Args, cfg.DefaultFrameworks(), cfg.ExcludeControls())
				require.NoError(t, err)
				require.Equal(t, []string{"C-0069"}, request.ExcludeControls)
				require.NotNil(t, request.ScanObject)
				require.NotNil(t, request.IsDeletedScanObject)
				require.Equal(t, eventType == watch.Deleted, *request.IsDeletedScanObject)
				require.NotNil(t, request.HostScanner)
				require.False(t, *request.HostScanner)
			case <-time.After(5 * time.Second):
				t.Fatal("continuous event did not create a scan command")
			}
		})
	}
}
