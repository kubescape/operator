package watcher

import (
	"context"
	_ "embed"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func NewWatchHandlerMock() *WatchHandler {
	return &WatchHandler{
		iwMap:                             NewImageHashWLIDsMap(),
		wlidsToContainerToImageIDMap:      make(map[string]map[string]string),
		wlidsToContainerToImageIDMapMutex: &sync.RWMutex{},
		instanceIDsMutex:                  &sync.RWMutex{},
	}
}

func TestNewWatchHandlerProducesValidResult(t *testing.T) {
	tt := []struct {
		name                string
		imageIDsToWLIDSsMap map[string][]string
		expectedIWMap       map[string][]string
	}{
		{
			name:                "Creating with provided empty map returns matching empty map",
			imageIDsToWLIDSsMap: map[string][]string{},
			expectedIWMap:       map[string][]string{},
		},
		{
			name:                "Creating with provided nil map returns matching empty map",
			imageIDsToWLIDSsMap: nil,
			expectedIWMap:       map[string][]string{},
		},
		{
			name: "Creating with provided non-empty map returns matching map",
			imageIDsToWLIDSsMap: map[string][]string{
				"imageid-01": {"wlid-01"},
			},
			expectedIWMap: map[string][]string{
				"imageid-01": {"wlid-01"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.TODO()
			k8sClient := k8sfake.NewSimpleClientset()
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset()

			wh, err := NewWatchHandler(ctx, k8sAPI, storageClient, tc.imageIDsToWLIDSsMap, nil)

			actualMap := wh.iwMap.Map()
			for imageID := range actualMap {
				sort.Strings(actualMap[imageID])
			}
			assert.NoErrorf(t, err, "Constructing should produce no errors")
			assert.NotNilf(t, wh, "Constructing should create a non-nil object")
			assert.Equal(t, tc.expectedIWMap, actualMap)
		})
	}
}

func Test_getSBOMWatcher(t *testing.T) {
	ctx := context.TODO()
	k8sClient := k8sfake.NewSimpleClientset()
	k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
	storageClient := kssfake.NewSimpleClientset()
	wh, _ := NewWatchHandler(ctx, k8sAPI, storageClient, nil, nil)

	sbomWatcher, err := wh.getSBOMWatcher()

	assert.NoErrorf(t, err, "Should get no errors")
	assert.NotNilf(t, sbomWatcher, "Returned value should not be nil")
}

func TestHandleSBOMFilteredEvents(t *testing.T) {
	tt := []struct {
		name                string
		instanceIDs         []string
		inputEvents         []watch.Event
		expectedObjectNames []string
		expectedErrors      []error
	}{
		{
			name:        "Adding a new Filtered SBOM with an unknown instance ID should delete it from storage",
			instanceIDs: []string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: v1.ObjectMeta{
							Name: "test-instance-id",
							Labels: map[string]string{
								"kubescape.io/workload-api-version":    "v1",
								"kubescape.io/workload-namespace":      "routing",
								"kubescape.io/workload-kind":           "deployment",
								"kubescape.io/workload-name":           "nginx-main-router",
								"kubescape.io/workload-container-name": "nginx",
							},
						},
					},
				},
			},
			expectedObjectNames: []string{},
			expectedErrors:      []error{},
		},
		{
			name:        "Adding a new Filtered SBOM with known instance ID should keep it in storage",
			instanceIDs: []string{"apiVersion-v1/namespace-routing/kind-deployment/name-nginx-main-router/containerName-nginx"},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: v1.ObjectMeta{
							Name: "test-instance-id",
							Labels: map[string]string{
								"kubescape.io/workload-api-version":    "v1",
								"kubescape.io/workload-namespace":      "routing",
								"kubescape.io/workload-kind":           "deployment",
								"kubescape.io/workload-name":           "nginx-main-router",
								"kubescape.io/workload-container-name": "nginx",
							},
						},
					},
				},
			},
			expectedObjectNames: []string{"test-instance-id"},
			expectedErrors:      []error{},
		},
		{
			name:        "Deleting a Filtered SBOM should be ignored",
			instanceIDs: []string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Deleted,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: v1.ObjectMeta{
							Name: "test-instance-id",
							Labels: map[string]string{
								"kubescape.io/workload-api-version":    "v1",
								"kubescape.io/workload-namespace":      "routing",
								"kubescape.io/workload-kind":           "deployment",
								"kubescape.io/workload-name":           "nginx-main-router",
								"kubescape.io/workload-container-name": "nginx",
							},
						},
					},
				},
			},
			expectedObjectNames: []string{"test-instance-id"},
			expectedErrors:      []error{},
		},
		{
			name:        "Adding a new Filtered SBOM with a missing labels should produce an error",
			instanceIDs: []string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: v1.ObjectMeta{
							Name: "test-instance-id",
						},
					},
				},
			},
			expectedObjectNames: []string{},
			expectedErrors:      []error{ErrMissingInstanceIDLabels},
		},
		{
			name:        "Adding an unsupported object should produce an error",
			instanceIDs: []string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.VulnerabilityManifest{
						ObjectMeta: v1.ObjectMeta{
							Name: "test-instance-id",
						},
					},
				},
			},
			expectedObjectNames: []string{},
			expectedErrors:      []error{ErrUnsupportedObject},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare starting startingObjects for storage
			startingObjects := []runtime.Object{}
			for _, e := range tc.inputEvents {
				startingObjects = append(startingObjects, e.Object)
			}

			ctx := context.Background()
			k8sClient := k8sfake.NewSimpleClientset()
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset(startingObjects...)
			iwMap := map[string][]string(nil)

			errorCh := make(chan error)
			sbomFilteredEvents := make(chan watch.Event)

			wh, _ := NewWatchHandler(ctx, k8sAPI, storageClient, iwMap, tc.instanceIDs)

			go wh.HandleSBOMFilteredEvents(sbomFilteredEvents, errorCh)

			go func() {
				for _, e := range tc.inputEvents {
					sbomFilteredEvents <- e
				}

				close(sbomFilteredEvents)
			}()

			actualErrors := []error{}
			for err := range errorCh {
				actualErrors = append(actualErrors, err)
			}

			actualObjects, _ := storageClient.SpdxV1beta1().SBOMSPDXv2p3Filtereds("").List(ctx, v1.ListOptions{})

			actualObjectNames := []string{}
			for _, obj := range actualObjects.Items {
				actualObjectNames = append(actualObjectNames, obj.ObjectMeta.Name)
			}

			assert.Equal(t, tc.expectedObjectNames, actualObjectNames)
			assert.Equal(t, tc.expectedErrors, actualErrors)
		})

	}
}

func TestHandleSBOMEvents(t *testing.T) {
	tt := []struct {
		name              string
		imageIDstoWlids   map[string][]string
		inputEvents       []watch.Event
		expectedSBOMNames []string
		expectedErrors    []error
	}{
		{
			name:            "New SBOM with unrecognized imageHash as name gets deleted",
			imageIDstoWlids: map[string][]string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName", Namespace: "kubescape"},
					},
				},
			},
			expectedSBOMNames: []string{},
			expectedErrors:    []error{},
		},
		{
			name:            "Non-SBOM objects get ignored",
			imageIDstoWlids: map[string][]string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.VulnerabilityManifest{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
			},
			expectedSBOMNames: []string{},
			expectedErrors:    []error{ErrUnsupportedObject},
		},
		{
			name:            "Modified SBOM with unrecognized imageHash as name gets deleted",
			imageIDstoWlids: map[string][]string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Modified,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName", Namespace: "kubescape"},
					},
				},
			},
			expectedSBOMNames: []string{},
			expectedErrors:    []error{},
		},
		{
			name:            "Deleted SBOM with unrecognized imageHash gets ignored",
			imageIDstoWlids: map[string][]string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Deleted,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName", Namespace: "kubescape"},
					},
				},
			},
			// Since the fake client does not receive a delete
			// request, it will still have the original value
			// stored.
			expectedSBOMNames: []string{"testName"},
			expectedErrors:    []error{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sfake.NewSimpleClientset()

			objects := []runtime.Object{}
			for _, event := range tc.inputEvents {
				objects = append(objects, event.Object)
			}

			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			ksStorageClient := kssfake.NewSimpleClientset(objects...)
			wh, _ := NewWatchHandler(context.TODO(), k8sAPI, ksStorageClient, tc.imageIDstoWlids, nil)

			errCh := make(chan error)

			sbomEvents := make(chan watch.Event)

			go func() {
				for _, event := range tc.inputEvents {
					sbomEvents <- event
				}

				close(sbomEvents)
			}()

			go wh.HandleSBOMEvents(sbomEvents, errCh)

			actualErrors := []error{}

			var done bool
			for !done {
				select {
				case err, ok := <-errCh:
					if ok {
						actualErrors = append(actualErrors, err)
					} else {
						done = true
					}
				}
			}

			storedObjects, _ := ksStorageClient.SpdxV1beta1().SBOMSPDXv2p3s("").List(context.TODO(), v1.ListOptions{})

			remainingSBOMNames := []string{}
			for _, obj := range storedObjects.Items {
				remainingSBOMNames = append(remainingSBOMNames, obj.ObjectMeta.Name)
			}

			assert.Equalf(t, tc.expectedSBOMNames, remainingSBOMNames, "Commands should match")
			assert.Equalf(t, tc.expectedErrors, actualErrors, "Errors should match")
		})
	}
}

func TestSBOMWatch(t *testing.T) {
	t.Skipf(
		"vladklokun: blocks and deadlocks while listening on the sbomWatcher.ResultChan(). " +
			"Does not reproduce in a live cluster on a live Watch() object",
	)

	k8sClient := k8sfake.NewSimpleClientset()

	expectedWlid := "some-imageID"
	imageIDsToWlids := map[string][]string{
		"some-imageID": {expectedWlid},
	}

	k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
	ksStorageClient := kssfake.NewSimpleClientset()
	wh, _ := NewWatchHandler(context.TODO(), k8sAPI, ksStorageClient, imageIDsToWlids, nil)

	sessionObjCh := make(chan utils.SessionObj)
	sessionObjChPtr := &sessionObjCh

	ctx := context.TODO()
	sbomClient := ksStorageClient.SpdxV1beta1().SBOMSPDXv2p3s("")
	sbomWatcher, _ := sbomClient.Watch(ctx, v1.ListOptions{})
	sbomWatcher.ResultChan()

	SBOMStub := spdxv1beta1.SBOMSPDXv2p3{
		ObjectMeta: v1.ObjectMeta{Name: "some-imageID"},
	}

	expectedCommands := []apis.Command{{CommandName: apis.TypeScanImages, Wlid: expectedWlid}}

	doneCh := make(chan struct{})
	go wh.SBOMWatch(context.TODO(), sessionObjChPtr)

	go func() {
		sbomClient.Create(ctx, &SBOMStub, v1.CreateOptions{})
		doneCh <- struct{}{}
	}()

	<-doneCh

	actualCommands := []apis.Command{}
	sessionObj := <-*sessionObjChPtr
	actualCommands = append(actualCommands, sessionObj.Command)

	assert.Equalf(t, expectedCommands, actualCommands, "Produced commands should match")

}

// func TestBuildImageIDsToWlidsMap(t *testing.T) {
// 	tests := []struct {
// 		name                string
// 		podList             core1.PodList
// 		expectedImageIDsMap map[string][]string
// 	}{
// 		{
// 			name: "remove prefix docker-pullable://",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "test",
// 							Namespace: "default",
// 						},
// 						TypeMeta: v1.TypeMeta{
// 							Kind: "pod",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:1",
// 									Name:    "container1",
// 								},
// 							},
// 						},
// 					}}},
// 			expectedImageIDsMap: map[string][]string{
// 				"alpine@sha256:1": {pkgwlid.GetWLID("", "default", "pod", "test")},
// 			},
// 		},
// 		{
// 			name: "image id without docker-pullable:// prefix",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "test",
// 							Namespace: "default",
// 						},
// 						TypeMeta: v1.TypeMeta{
// 							Kind: "pod",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "alpine@sha256:1",
// 									Name:    "container1",
// 								},
// 							},
// 						},
// 					}}},
// 			expectedImageIDsMap: map[string][]string{
// 				"alpine@sha256:1": {pkgwlid.GetWLID("", "default", "pod", "test")},
// 			},
// 		},
// 		{
// 			name: "two wlids for the same image id",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "test",
// 							Namespace: "default",
// 						},
// 						TypeMeta: v1.TypeMeta{
// 							Kind: "pod",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:1",
// 									Name:    "container1",
// 								},
// 							},
// 						},
// 					},
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "test2",
// 							Namespace: "default",
// 						},
// 						TypeMeta: v1.TypeMeta{
// 							Kind: "pod",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:1",
// 									Name:    "container2",
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 			expectedImageIDsMap: map[string][]string{
// 				"alpine@sha256:1": {pkgwlid.GetWLID("", "default", "pod", "test"), pkgwlid.GetWLID("", "default", "pod", "test2")},
// 			},
// 		},
// 		{
// 			name: "two wlids two image ids",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "test",
// 							Namespace: "default",
// 						},
// 						TypeMeta: v1.TypeMeta{
// 							Kind: "pod",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:1",
// 									Name:    "container1",
// 								},
// 							},
// 						},
// 					},
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "test2",
// 							Namespace: "default",
// 						},
// 						TypeMeta: v1.TypeMeta{
// 							Kind: "pod",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:2",
// 									Name:    "container2",
// 								},
// 							},
// 						},
// 					}}},
// 			expectedImageIDsMap: map[string][]string{
// 				"alpine@sha256:1": {pkgwlid.GetWLID("", "default", "pod", "test")},
// 				"alpine@sha256:2": {pkgwlid.GetWLID("", "default", "pod", "test2")},
// 			},
// 		},
// 		{
// 			name: "one wlid two image ids",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "test",
// 							Namespace: "default",
// 						},
// 						TypeMeta: v1.TypeMeta{
// 							Kind: "pod",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:1",
// 									Name:    "container1",
// 								},
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:2",
// 									Name:    "container2",
// 								},
// 							},
// 						},
// 					}}},
// 			expectedImageIDsMap: map[string][]string{
// 				"alpine@sha256:1": {pkgwlid.GetWLID("", "default", "pod", "test")},
// 				"alpine@sha256:2": {pkgwlid.GetWLID("", "default", "pod", "test")},
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		wh := NewWatchHandlerMock()
// 		t.Run(tt.name, func(t *testing.T) {
// 			wh.buildIDs(context.TODO(), &tt.podList)
// 			assert.True(t, reflect.DeepEqual(wh.getImagesIDsToWlidMap(), tt.expectedImageIDsMap))
// 		})
// 	}
// }

// func TestBuildWlidsToContainerToImageIDMap(t *testing.T) {
// 	tests := []struct {
// 		name                                 string
// 		podList                              core1.PodList
// 		expectedwlidsToContainerToImageIDMap WlidsToContainerToImageIDMap
// 	}{
// 		{
// 			name: "imageID with docker-pullable prefix",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "pod1",
// 							Namespace: "namespace1",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:1",
// 									Name:    "container1",
// 								},
// 							},
// 						},
// 					}},
// 			},
// 			expectedwlidsToContainerToImageIDMap: WlidsToContainerToImageIDMap{
// 				pkgwlid.GetWLID("", "namespace1", "pod", "pod1"): {
// 					"container1": "alpine@sha256:1",
// 				},
// 			},
// 		},
// 		{
// 			name: "imageID without docker-pullable prefix",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "pod1",
// 							Namespace: "namespace1",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "alpine@sha256:1",
// 									Name:    "container1",
// 								},
// 							},
// 						},
// 					}},
// 			},
// 			expectedwlidsToContainerToImageIDMap: WlidsToContainerToImageIDMap{
// 				pkgwlid.GetWLID("", "namespace1", "pod", "pod1"): {
// 					"container1": "alpine@sha256:1",
// 				},
// 			},
// 		},
// 		{
// 			name: "two containers for same wlid",
// 			podList: core1.PodList{
// 				Items: []core1.Pod{
// 					{
// 						ObjectMeta: v1.ObjectMeta{
// 							Name:      "pod3",
// 							Namespace: "namespace3",
// 						},
// 						Status: core1.PodStatus{
// 							ContainerStatuses: []core1.ContainerStatus{
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:3",
// 									Name:    "container3",
// 								},
// 								{
// 									ImageID: "docker-pullable://alpine@sha256:4",
// 									Name:    "container4",
// 								},
// 							},
// 						},
// 					},
// 				}},
// 			expectedwlidsToContainerToImageIDMap: WlidsToContainerToImageIDMap{
// 				pkgwlid.GetWLID("", "namespace3", "pod", "pod3"): {
// 					"container3": "alpine@sha256:3",
// 					"container4": "alpine@sha256:4",
// 				},
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		wh := NewWatchHandlerMock()
// 		t.Run(tt.name, func(t *testing.T) {
// 			wh.buildIDs(context.TODO(), &tt.podList)
// 			got := wh.getWlidsToContainerToImageIDMap()
// 			assert.True(t, reflect.DeepEqual(got, tt.expectedwlidsToContainerToImageIDMap))
// 		})
// 	}
// }

func Test_addToImageIDToWlidsMap(t *testing.T) {
	type inputOperation struct {
		imageID string
		wlid    string
	}

	tt := []struct {
		name            string
		inputOperations []inputOperation
		expectedMap     map[string][]string
	}{
		{
			name: "Adding imageName@hashType:imageHash keys with wlids produces expected maps",
			inputOperations: []inputOperation{
				{"alpine@sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "wlid1"},
				{"alpine@sha256:486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7", "wlid2"},
				// add the new wlid to the same imageID
				{"alpine@sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "wlid3"},
			},
			expectedMap: map[string][]string{
				"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824": {"wlid1", "wlid3"},
				"486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7": {"wlid2"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			wh := NewWatchHandlerMock()

			for _, op := range tc.inputOperations {
				wh.addToImageIDToWlidsMap(op.imageID, op.wlid)
			}

			actualMap := wh.iwMap.Map()
			for imageID := range actualMap {
				sort.Strings(actualMap[imageID])
			}

			assert.Equal(t, tc.expectedMap, actualMap)
		})
	}
}

func TestAddTowlidsToContainerToImageIDMap(t *testing.T) {
	wh := NewWatchHandlerMock()

	wh.addToWlidsToContainerToImageIDMap("wlid1", "container1", "alpine@sha256:1")
	wh.addToWlidsToContainerToImageIDMap("wlid2", "container2", "alpine@sha256:2")

	assert.True(t, reflect.DeepEqual(wh.getWlidsToContainerToImageIDMap(), WlidsToContainerToImageIDMap{
		"wlid1": {
			"container1": "alpine@sha256:1",
		},
		"wlid2": {
			"container2": "alpine@sha256:2",
		},
	}))
}

func TestGetNewImageIDsToContainerFromPod(t *testing.T) {
	wh := NewWatchHandlerMock()

	wh.iwMap = NewImageHashWLIDsMapFrom(map[string][]string{
		"alpine@sha256:1": {"wlid"},
		"alpine@sha256:2": {"wlid"},
		"alpine@sha256:3": {"wlid"},
	})

	tests := []struct {
		name     string
		pod      *core1.Pod
		expected map[string]string
	}{
		{
			name: "no new images",
			pod: &core1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod1",
					Namespace: "namespace1",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:2",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string]string{},
		},
		{
			name: "one new image",
			pod: &core1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod2",
					Namespace: "namespace2",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:4",
							Name:    "container4",
						},
					},
				},
			},
			expected: map[string]string{
				"container4": "alpine@sha256:4",
			},
		},
		{
			name: "two new images",
			pod: &core1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod3",
					Namespace: "namespace3",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:4",
							Name:    "container4",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:5",
							Name:    "container5",
						},
					},
				},
			},
			expected: map[string]string{
				"container4": "alpine@sha256:4",
				"container5": "alpine@sha256:5",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, wh.getNewContainerToImageIDsFromPod(tt.pod))
		})
	}
}

func TestCleanUpWlidsToContainerToImageIDMap(t *testing.T) {
	wh := NewWatchHandlerMock()
	wh.wlidsToContainerToImageIDMap = map[string]map[string]string{
		"pod1": {"container1": "alpine@sha256:1"},
		"pod2": {"container2": "alpine@sha256:2"},
		"pod3": {"container3": "alpine@sha256:3"},
	}
	wh.cleanUpWlidsToContainerToImageIDMap()

	assert.Equal(t, len(wh.wlidsToContainerToImageIDMap), 0)
}

func Test_cleanUpIDs(t *testing.T) {
	wh := NewWatchHandlerMock()
	wh.iwMap = NewImageHashWLIDsMapFrom(map[string][]string{
		"alpine@sha256:1": {"pod1"},
		"alpine@sha256:2": {"pod2"},
		"alpine@sha256:3": {"pod3"},
	})
	wh.wlidsToContainerToImageIDMap = map[string]map[string]string{
		"pod1": {"container1": "alpine@sha256:1"},
		"pod2": {"container2": "alpine@sha256:2"},
		"pod3": {"container3": "alpine@sha256:3"},
	}
	wh.cleanUpIDs()

	assert.Equal(t, 0, len(wh.iwMap.Map()))
	assert.Equal(t, 0, len(wh.wlidsToContainerToImageIDMap))
}

//go:embed testdata/deployment-two-containers.json
var deploymentTwoContainersJson []byte

//go:embed testdata/deployment.json
var deploymentJson []byte
