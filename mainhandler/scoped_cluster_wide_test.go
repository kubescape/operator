package mainhandler

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// clusterWideImageScan is a cluster-wide image scan request, as the SecurityException
// watcher sends for its image rescans: a WildWlid that names the cluster and no namespace.
func clusterWideImageScan() *utils.SessionObj {
	return &utils.SessionObj{Command: &apis.Command{
		CommandName: apis.TypeScanImages,
		WildWlid:    pkgwlid.GetK8sWLID("cluster", "", "", ""),
	}}
}

func namespaceForHandler(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// TestHandleImageScanningScopedRequest_ClusterWideLooksUpProfilesInPodNamespace checks that a
// cluster-wide request looks each pod's ContainerProfile up in the pod's own namespace. With
// the empty namespace of the request, a real client refuses the Get ("an empty namespace may
// not be set when a resource name is provided"), so no relevancy scan was ever started.
func TestHandleImageScanningScopedRequest_ClusterWideLooksUpProfilesInPodNamespace(t *testing.T) {
	ns := "default"
	pod := nakedRunningPodForHandler(ns, "my-pod", []string{"nginx"})
	slugs := withContainerSlugsForHandler(t, pod)
	require.Len(t, slugs, 1)

	k8sClient := k8sfake.NewClientset(namespaceForHandler(ns), pod)
	storageClient := kssfake.NewClientset(containerProfileForHandler(ns, slugs[0]))
	scanner := newScannerStub(t)
	mainHandler := newMainHandlerForTest(k8sClient, storageClient, scanner)

	mainHandler.HandleImageScanningScopedRequest(context.Background(), clusterWideImageScan())

	var lookedUpIn []string
	for _, action := range storageClient.Actions() {
		if action.Matches("get", "containerprofiles") {
			lookedUpIn = append(lookedUpIn, action.(clienttesting.GetAction).GetNamespace())
		}
	}
	assert.Equal(t, []string{ns}, lookedUpIn, "the ContainerProfile must be looked up in the pod's namespace")
	assert.Equal(t, 1, scanner.requestCount())
}

// TestHandleImageScanningScopedRequest_ClusterWideHonoursIncludedNamespaces checks that the
// namespace filter applies to the namespaces a cluster-wide request covers, not to the
// request's own empty namespace, which no include list contains.
func TestHandleImageScanningScopedRequest_ClusterWideHonoursIncludedNamespaces(t *testing.T) {
	included := nakedRunningPodForHandler("payments", "api", []string{"nginx"})
	other := nakedRunningPodForHandler("other", "worker", []string{"nginx"})

	k8sClient := k8sfake.NewClientset(namespaceForHandler("payments"), namespaceForHandler("other"), included, other)
	scanner := newScannerStub(t)
	mainHandler := newMainHandlerForTest(k8sClient, kssfake.NewClientset(), scanner)
	cfg, ok := mainHandler.config.(*config.OperatorConfig)
	require.True(t, ok)
	_, err := cfg.UpdateNamespaceFilters([]byte(`{"includeNamespaces":["payments"],"excludeNamespaces":[]}`))
	require.NoError(t, err)

	mainHandler.HandleImageScanningScopedRequest(context.Background(), clusterWideImageScan())

	assert.Equal(t, 1, scanner.requestCount(), "only the pod in the included namespace is scanned")
}
