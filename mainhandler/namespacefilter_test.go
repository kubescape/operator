package mainhandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-k8s-go/armometadata"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/require"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestNamespaceFilteredScanDispatch(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	oldVuln, oldKubescape := VulnScanHttpClient, KubescapeHttpClient
	t.Cleanup(func() { VulnScanHttpClient, KubescapeHttpClient = oldVuln, oldKubescape })
	host := strings.TrimPrefix(server.URL, "http://")
	VulnScanHttpClient, KubescapeHttpClient = server.Client(), server.Client()
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{Components: config.Components{
		Kubevuln: config.Component{Enabled: true}, Kubescape: config.Component{Enabled: true},
	}}, armometadata.ClusterConfig{KubevulnURL: host, KubescapeURL: host}, nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	wlid := pkgwlid.GetWLID("cluster", "payments", "deployment", "api")
	commands := []*apis.Command{
		{CommandName: apis.TypeScanImages, Wlid: wlid, Args: map[string]interface{}{
			utils.ArgsContainerData: &utils.ContainerData{Wlid: wlid, ImageTag: "docker.io/library/nginx:latest"},
		}},
		{CommandName: utils.CommandScanContainerProfile, Args: map[string]interface{}{
			utils.ArgsNamespace: "payments", utils.ArgsName: "profile",
		}},
		{CommandName: utils.CommandScanContainerProfile, Wlid: pkgwlid.GetWLID("cluster", "other", "deployment", "api"), Args: map[string]interface{}{
			utils.ArgsNamespace: "payments", utils.ArgsName: "profile",
		}},
		{CommandName: apis.TypeRunKubescape, Wlid: wlid, Args: map[string]interface{}{
			utils.KubescapeScanV1: map[string]interface{}{},
		}},
	}
	for _, cmd := range commands {
		t.Run(string(cmd.CommandName), func(t *testing.T) {
			handler := &ActionHandler{config: cfg, k8sAPI: utils.NewK8sInterfaceFake(k8sfake.NewSimpleClientset()), sessionObj: &utils.SessionObj{Command: cmd}}
			// The command was built while allowed; filters change before execution.
			_, err := cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`))
			require.NoError(t, err)
			before := calls.Load()
			require.NoError(t, handler.runCommand(context.Background()))
			require.Equal(t, before, calls.Load())
			_, err = cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":[],"excludeNamespaces":[]}`))
			require.NoError(t, err)
			require.NoError(t, handler.runCommand(context.Background()))
			require.Equal(t, before+1, calls.Load())
		})
	}

	// SBOM scan commands carry their resolved workload in Wlid. Their storage
	// namespace must not suppress scans of an otherwise allowed workload.
	_, err = cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":[],"excludeNamespaces":["kubescape"]}`))
	require.NoError(t, err)
	cmd := &apis.WebsocketScanCommand{Wlid: wlid, ImageScanParams: apis.ImageScanParams{Args: map[string]interface{}{utils.ArgsNamespace: "kubescape"}}}
	before := calls.Load()
	require.NoError(t, sendCommandToScanner(context.Background(), cfg, cmd, apis.TypeScanImages))
	require.Equal(t, before+1, calls.Load())
	_, err = cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`))
	require.NoError(t, err)
	require.NoError(t, sendCommandToScanner(context.Background(), cfg, cmd, apis.TypeScanImages))
	require.Equal(t, before+1, calls.Load())

	// A cluster-wide posture request has no workload namespace to filter here.
	clusterCommand := &apis.Command{CommandName: apis.TypeRunKubescape, Args: map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{}}}
	handler := &ActionHandler{config: cfg, sessionObj: &utils.SessionObj{Command: clusterCommand}}
	require.NoError(t, handler.runCommand(context.Background()))
	require.Equal(t, before+2, calls.Load())
	require.NoError(t, sendWorkloadToRegistryScan(context.Background(), cfg, &apis.RegistryScanCommand{}))
	require.Equal(t, before+3, calls.Load())
}
