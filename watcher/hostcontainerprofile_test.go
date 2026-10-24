package watcher

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

// chartExcludeNamespaces is the kubescape-operator chart's default excludeNamespaces.
var chartExcludeNamespaces = []string{"kubescape", "kube-system", "kube-public", "kube-node-lease", "kubeconfig", "gmp-system", "gmp-public"}

// hostContainerProfile is the host profile as node-agent's host monitoring writes it:
// stored in node-agent's own namespace, with a host WLID and the Node workload kind.
func hostContainerProfile(node string) *spdxv1beta1.ContainerProfile {
	return &spdxv1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-" + node + "-host",
			Namespace: "kubescape",
			Annotations: map[string]string{
				helpersv1.InstanceIDMetadataKey: "apiVersion-v1/namespace-host/kind-Node/name-host-" + node + "/containerName-host",
				helpersv1.WlidMetadataKey:       "wlid://cluster-unknown/namespace-host/host-" + node,
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
			Labels: map[string]string{
				helpersv1.ApiVersionMetadataKey:       "v1",
				helpersv1.RelatedKindMetadataKey:      "Node",
				helpersv1.RelatedNameMetadataKey:      "host-" + node,
				helpersv1.RelatedNamespaceMetadataKey: "host",
				helpersv1.ContainerNameMetadataKey:    "host",
			},
		},
	}
}

func TestHandleContainerProfileEvents_HostProfile(t *testing.T) {
	deploymentProfile := &spdxv1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-storage-abc-storage",
			Namespace: "kubescape",
			Annotations: map[string]string{
				helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-kubescape/kind-ReplicaSet/name-storage-abc/containerName-storage",
				helpersv1.WlidMetadataKey:       "wlid://cluster-c/namespace-kubescape/deployment-storage",
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
			},
		},
	}
	tests := []struct {
		name      string
		profile   *spdxv1beta1.ContainerProfile
		nodes     []runtime.Object
		exclude   []string
		wantWlids []string
	}{
		{
			name:      "host profile is scanned with the chart defaults",
			profile:   hostContainerProfile("worker-1"),
			nodes:     []runtime.Object{&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}}},
			exclude:   chartExcludeNamespaces,
			wantWlids: []string{"wlid://cluster-unknown/namespace-host/host-worker-1"},
		},
		{
			name:    "host profile of a removed node is skipped",
			profile: hostContainerProfile("worker-1"),
			exclude: chartExcludeNamespaces,
		},
		{
			name:    "host profile is skipped when the host namespace is excluded",
			profile: hostContainerProfile("worker-1"),
			nodes:   []runtime.Object{&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}}},
			exclude: []string{"host"},
		},
		{
			name:    "workload profile in an excluded namespace is still skipped",
			profile: deploymentProfile,
			exclude: chartExcludeNamespaces,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.LoadConfig("../configuration")
			require.NoError(t, err)
			require.True(t, cfg.SkipProfilesWithoutInstances)
			cfg.ExcludeNamespaces = tt.exclude
			operatorConfig, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, cfg)
			require.NoError(t, err)

			sch := runtime.NewScheme()
			require.NoError(t, scheme.AddToScheme(sch))
			k8sAPI := &k8sinterface.KubernetesApi{
				KubernetesClient: k8sfake.NewClientset(tt.nodes...),
				DynamicClient:    dynamicfake.NewSimpleDynamicClient(sch, tt.nodes...),
			}
			wh := NewWatchHandler(operatorConfig, k8sAPI, kssfake.NewSimpleClientset(tt.profile), nil)

			queue := NewCooldownQueueWithParams(200*time.Millisecond, 50*time.Millisecond)
			cmdCh := make(chan *apis.Command, 4)
			errCh := make(chan error, 4)
			go wh.HandleContainerProfileEvents(queue, cmdCh, errCh)
			queue.Enqueue(watch.Event{Type: watch.Added, Object: tt.profile})
			time.Sleep(time.Second)
			queue.Stop()
			for err := range errCh {
				require.NoError(t, err)
			}
			close(cmdCh)

			var wlids []string
			for cmd := range cmdCh {
				assert.Equal(t, utils.CommandScanContainerProfile, cmd.CommandName)
				assert.Equal(t, tt.profile.Namespace, cmd.Args[utils.ArgsNamespace])
				wlids = append(wlids, cmd.Wlid)
			}
			assert.Equal(t, tt.wantWlids, wlids)
		})
	}
}
