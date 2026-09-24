package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestNamespaceFilterPodProcessing(t *testing.T) {
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, armometadata.ClusterConfig{ClusterName: "test"}, nil, config.Config{})
	require.NoError(t, err)
	k8sAPI := utils.NewK8sInterfaceFake(k8sfake.NewSimpleClientset())
	k8sAPI.DynamicClient = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	wh := NewWatchHandler(cfg, k8sAPI, kssfake.NewSimpleClientset(), nil)
	commands := make(chan *apis.Command, 1)
	pool, err := ants.NewPoolWithFunc(1, func(i interface{}) { job := i.(utils.Job); commands <- job.Obj().Command })
	require.NoError(t, err)
	defer pool.Release()
	pod := bytesToPod(readFileToBytes(podKubeProxy))
	require.NotNil(t, pod)
	_, err = cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":[],"excludeNamespaces":["kube-system"]}`))
	require.NoError(t, err)
	wh.handlePodWatcher(context.Background(), pod, pool)
	require.Empty(t, wh.SlugToImageID.Keys())
	select {
	case <-commands:
		t.Fatal("excluded pod produced a scan command")
	default:
	}
	_, err = cfg.UpdateNamespaceFilters([]byte(allowNamespaces))
	require.NoError(t, err)
	wh.handlePodWatcher(context.Background(), pod, pool)
	select {
	case cmd := <-commands:
		require.Equal(t, apis.TypeScanImages, cmd.CommandName)
	case <-time.After(5 * time.Second):
		t.Fatal("newly allowed pod was not scanned")
	}
}
