package mainhandler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/identifiers"
	beUtils "github.com/kubescape/backend/pkg/utils"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestCombineKubescapeCMDArgsWithFrameworkName(t *testing.T) {
	fullCMD := combineKubescapeCMDArgsWithFrameworkName("mitre", []string{"scan", "framework"})
	if strings.Join(fullCMD, " ") != "scan framework mitre" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{"scan", "framework"})
	if strings.Join(fullCMD, " ") != "scan" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{"scan", "framework", "--environment"})
	if strings.Join(fullCMD, " ") != "scan --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("mitre", []string{"scan", "framework", "--environment"})
	if strings.Join(fullCMD, " ") != "scan framework mitre --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("mitre", []string{"--environment"})
	if strings.Join(fullCMD, " ") != "scan framework mitre --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{"--environment"})
	if strings.Join(fullCMD, " ") != "scan --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{})
	if strings.Join(fullCMD, " ") != "scan" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("mitre", []string{})
	if strings.Join(fullCMD, " ") != "scan framework mitre" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
}

// nakedRunningPodForHandler builds a pod with no OwnerReferences and no pod-template-hash
// label, so utils.PodHasParent(pod) is false and GetParentIDForPod's
// CalculateWorkloadParentRecursive call short-circuits without touching a dynamic client.
// It has one running container per name in containerNames, each with a well-formed ImageID.
func nakedRunningPodForHandler(ns, name string, containerNames []string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}
	pod.APIVersion = "v1"
	pod.Kind = "Pod"

	for i, cName := range containerNames {
		image := fmt.Sprintf("docker.io/library/nginx:%d", i)
		imageID := fmt.Sprintf("docker.io/library/nginx@sha256:%064d", i)
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
			Name:  cName,
			Image: image,
		})
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
			Name:    cName,
			Image:   image,
			ImageID: imageID,
			State: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))},
			},
		})
	}
	return pod
}

// withContainerSlugsForHandler computes the "with-container" slug (GetSlug(false)) for every
// container of pod, in the same way HandleImageScanningScopedRequest does.
func withContainerSlugsForHandler(t *testing.T, pod *corev1.Pod) []string {
	t.Helper()
	instanceIDs, err := instanceidhandlerv1.GenerateInstanceIDFromRuntimeObj(pod, nil)
	require.NoError(t, err)
	require.Len(t, instanceIDs, len(pod.Spec.Containers))

	slugs := make([]string, 0, len(instanceIDs))
	for _, instanceID := range instanceIDs {
		slug, err := instanceID.GetSlug(false)
		require.NoError(t, err)
		slugs = append(slugs, slug)
	}
	return slugs
}

// containerProfileForHandler builds a ContainerProfile named with the given (with-container)
// slug, carrying annotations that satisfy utils.SkipContainerProfile so it is picked up by
// utils.GetContainerProfileForRelevancyScan.
func containerProfileForHandler(ns, slug string) *spdxv1beta1.ContainerProfile {
	return &spdxv1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      slug,
			Annotations: map[string]string{
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
				helpersv1.InstanceIDMetadataKey: slug,
				helpersv1.WlidMetadataKey:       "wlid://cluster-test/namespace-" + ns + "/deployment-test",
			},
		},
	}
}

// getContainerProfileActionNames returns the resource names of every "get containerprofiles"
// action recorded against the fake storage client.
func getContainerProfileActionNames(t *testing.T, storageClient interface{ Actions() []clienttesting.Action }) []string {
	t.Helper()
	var names []string
	for _, action := range storageClient.Actions() {
		if !action.Matches("get", "containerprofiles") {
			continue
		}
		getAction, ok := action.(clienttesting.GetAction)
		require.True(t, ok, "expected a GetAction, got %T", action)
		names = append(names, getAction.GetName())
	}
	return names
}

// scannerStub stands in for kubevuln. HandleSingleRequest only reaches it if the dispatch
// switch in runCommand actually routes the command to actionHandler.scanContainerProfile
// (i.e. GetContainerProfileScanCommand set the right CommandName) and that handler completes
// successfully (which is also the only way slugs[s] = true gets set in
// HandleImageScanningScopedRequest). Counting requests therefore lets tests detect both the
// CommandName regression and the per-workload dedup regression, neither of which a bare
// "get containerprofiles" assertion on the storage client can distinguish from a correct fix.
type scannerStub struct {
	server *httptest.Server
	mu     sync.Mutex
	count  int
}

func newScannerStub(t *testing.T) *scannerStub {
	t.Helper()
	s := &scannerStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		s.count++
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *scannerStub) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *scannerStub) hostPort() string {
	return strings.TrimPrefix(s.server.URL, "http://")
}

// newMainHandlerForTest builds a MainHandler wired to fake Kubernetes and storage clientsets,
// with Kubevuln enabled and pointed at scanner. This lets a found ContainerProfile's scan
// command actually complete end-to-end through actionHandler.scanContainerProfile, instead of
// short-circuiting on a "kubevuln is not enabled" error before slugs[s] = true is ever reached.
func newMainHandlerForTest(k8sClient *k8sfake.Clientset, storageClient *kssfake.Clientset, scanner *scannerStub) *MainHandler {
	capabilities := config.CapabilitiesConfig{
		Components: config.Components{
			Kubevuln: config.Component{Enabled: true},
		},
	}
	clusterConfig := utilsmetadata.ClusterConfig{KubevulnURL: scanner.hostPort()}
	// VulnScanHttpClient is normally set once at startup (see main.go); scanContainerProfile
	// uses it directly (not via config), so tests that expect a real POST to reach the
	// scanner stub must set it explicitly too.
	VulnScanHttpClient = utils.InitHttpClient(clusterConfig.KubevulnURL)
	return &MainHandler{
		k8sAPI:          utils.NewK8sInterfaceFake(k8sClient),
		ksStorageClient: storageClient,
		config:          config.NewOperatorConfig(capabilities, clusterConfig, &beUtils.Credentials{}, config.Config{}),
	}
}

func sessionObjForNamespaceForHandler(ns string) *utils.SessionObj {
	return &utils.SessionObj{
		Command: &apis.Command{
			CommandName: apis.TypeScanImages,
			Designators: []identifiers.PortalDesignator{
				{Attributes: map[string]string{identifiers.AttributeNamespace: ns}},
			},
		},
	}
}

// TestHandleImageScanningScopedRequest_LooksUpWithContainerSlug is a regression test: the
// ContainerProfile lookup must use the with-container slug (GetSlug(false)), matching how
// ContainerProfile objects are actually named. Before the fix, the code derived and looked up
// a separate no-container slug (GetSlug(true)), which always 404'd.
func TestHandleImageScanningScopedRequest_LooksUpWithContainerSlug(t *testing.T) {
	ns := "default"
	pod := nakedRunningPodForHandler(ns, "my-pod", []string{"nginx"})
	slugs := withContainerSlugsForHandler(t, pod)
	require.Len(t, slugs, 1)

	k8sClient := k8sfake.NewClientset(pod)
	storageClient := kssfake.NewSimpleClientset(containerProfileForHandler(ns, slugs[0]))
	scanner := newScannerStub(t)

	mainHandler := newMainHandlerForTest(k8sClient, storageClient, scanner)
	sessionObj := sessionObjForNamespaceForHandler(ns)

	mainHandler.HandleImageScanningScopedRequest(context.Background(), sessionObj)

	gotNames := getContainerProfileActionNames(t, storageClient)
	assert.Equal(t, slugs, gotNames, "expected a single 'get containerprofiles' call using the with-container slug")
	// Only reachable if GetContainerProfileScanCommand's CommandName correctly routes through
	// runCommand's dispatch switch into actionHandler.scanContainerProfile.
	assert.Equal(t, 1, scanner.requestCount(), "expected the container-profile scan to actually dispatch to the scanner")
}

// TestHandleImageScanningScopedRequest_MultiContainerDoesNotDedupeAcrossContainers is a
// regression test for the per-workload dedup bug: the dedup map used to be keyed by the
// no-container slug (identical for every container of the same pod), so finding one
// container's profile would incorrectly skip looking up the remaining containers'. With the
// fix, dedup is keyed by the with-container slug, so every container is looked up.
func TestHandleImageScanningScopedRequest_MultiContainerDoesNotDedupeAcrossContainers(t *testing.T) {
	ns := "default"
	pod := nakedRunningPodForHandler(ns, "my-pod", []string{"nginx", "sidecar", "init"})
	slugs := withContainerSlugsForHandler(t, pod)
	require.Len(t, slugs, 3)

	profiles := make([]runtime.Object, 0, len(slugs))
	for _, slug := range slugs {
		profiles = append(profiles, containerProfileForHandler(ns, slug))
	}

	k8sClient := k8sfake.NewClientset(pod)
	storageClient := kssfake.NewSimpleClientset(profiles...)
	scanner := newScannerStub(t)

	mainHandler := newMainHandlerForTest(k8sClient, storageClient, scanner)
	sessionObj := sessionObjForNamespaceForHandler(ns)

	mainHandler.HandleImageScanningScopedRequest(context.Background(), sessionObj)

	gotNames := getContainerProfileActionNames(t, storageClient)
	assert.ElementsMatch(t, slugs, gotNames, "expected one 'get containerprofiles' call per container, each with its own with-container slug")
	// Each container's scan must independently reach the scanner: with Kubevuln enabled,
	// a reintroduced per-workload dedup (keyed by the no-container slug, identical across
	// containers) would mark the workload "done" after the first successful dispatch and
	// skip the rest, so this count would drop below len(slugs) if that regression returned.
	assert.Equal(t, len(slugs), scanner.requestCount(), "expected one dispatched scan per container, none dropped by dedup")
}
