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
	"github.com/stretchr/testify/assert"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	// Kubescape storage client
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"k8s.io/apimachinery/pkg/watch"
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
		name string
		imageIDsToWLIDSsMap map[string][]string
		expectedIWMap map[string][]string
	}{
		{
			name: "Creating with provided empty map returns matching empty map",
			imageIDsToWLIDSsMap: map[string][]string{},
			expectedIWMap: map[string][]string{},
		},
		{
			name: "Creating with provided nil map returns matching empty map",
			imageIDsToWLIDSsMap: nil,
			expectedIWMap: map[string][]string{},
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

			wh, err := NewWatchHandler(ctx, k8sAPI, storageClient, tc.imageIDsToWLIDSsMap)

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
	wh, _ := NewWatchHandler(ctx, k8sAPI, storageClient, nil)

	sbomWatcher, err := wh.getSBOMWatcher()

	assert.NoErrorf(t, err, "Should get no errors")
	assert.NotNilf(t, sbomWatcher, "Returned value should not be nil")
}

func TestHandleSBOMProducesMatchingCommands(t *testing.T) {
	tt := []struct {
		name          string
		sbomNamespace string
		sboms         []spdxv1beta1.SBOMSPDXv2p3
		wlidMap       map[string][]string
	}{
		{
			name:          "Valid SBOM produces matching command",
			sbomNamespace: "sbom-test-ns",
			sboms: []spdxv1beta1.SBOMSPDXv2p3{
				{
					ObjectMeta: v1.ObjectMeta{
						Name:      "0acbac6272564700d30edebaf7d546330836f8e0065b26cd2789b83b912e049d",
						Namespace: "sbom-test-ns",
					},
				},
			},
			wlidMap: map[string][]string{
				"0acbac6272564700d30edebaf7d546330836f8e0065b26cd2789b83b912e049d": {
					"wlid://test-wlid",
				},
			},
		},
		{
			"Two valid SBOMs produce matching commands",
			"sbom-test-ns",
			[]spdxv1beta1.SBOMSPDXv2p3{
				{
					ObjectMeta: v1.ObjectMeta{
						Name:      "0acbac6272564700d30edebaf7d546330836f8e0065b26cd2789b83b912e049d",
						Namespace: "sbom-test-ns",
					},
				},
				{
					ObjectMeta: v1.ObjectMeta{
						Name:      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
						Namespace: "sbom-test-ns",
					},
				},
			},
			map[string][]string{
				"0acbac6272564700d30edebaf7d546330836f8e0065b26cd2789b83b912e049d": {
					"wlid://test-wlid",
				},
				"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": {
					"wlid://test-wlid-02",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.TODO()

			k8sClient := k8sfake.NewSimpleClientset()
			ksStorageClient := kssfake.NewSimpleClientset()

			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			wh, _ := NewWatchHandler(ctx, k8sAPI, ksStorageClient, tc.wlidMap)

			commandCh := make(chan *apis.Command)
			errors := make(chan error)

			sbomWatcher, _ := ksStorageClient.SpdxV1beta1().SBOMSPDXv2p3s("").Watch(ctx, v1.ListOptions{})
			sbomEvents := sbomWatcher.ResultChan()

			go wh.HandleSBOMEvents(sbomEvents, commandCh, errors)

			// Handling the event is expected to transform
			// incloming imageID in the SBOM name to a valid WLID
			expectedWlidsCounter := map[string]int{}

			for _, sbom := range tc.sboms {
				ksStorageClient.SpdxV1beta1().SBOMSPDXv2p3s(tc.sbomNamespace).Create(ctx, &sbom, v1.CreateOptions{})
				expectedSbomWlid := tc.wlidMap[sbom.ObjectMeta.Name][0]
				expectedWlidsCounter[expectedSbomWlid] += 1
			}
			sbomWatcher.Stop()

			actualWlids := map[string]int{}
			for command := range commandCh {
				assert.Equalf(t, apis.TypeScanImages, command.CommandName, "Should produce Scan commands")

				actualWlids[command.Wlid] += 1
			}

			assert.Equalf(t, expectedWlidsCounter, actualWlids, "Produced WLIDs should match the expected.")
		},
		)
	}
}

func TestHandleSBOMEvents(t *testing.T) {
	tt := []struct {
		name             string
		imageIDstoWlids  map[string][]string
		inputEvents      []watch.Event
		expectedCommands []apis.Command
		expectedErrors   []error
	}{
		{
			name: "Bookmark event gets ignored",
			imageIDstoWlids: map[string][]string{
				"testName": {"testWlid"},
			},
			inputEvents: []watch.Event{
				{
					Type: watch.Bookmark,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
			},
			expectedCommands: []apis.Command{},
			expectedErrors:   []error{},
		},
		{
			name: "Deleted event gets ignored",
			imageIDstoWlids: map[string][]string{
				"testName": {"testWlid"},
			},
			inputEvents: []watch.Event{
				{
					Type: watch.Deleted,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
			},
			expectedCommands: []apis.Command{},
			expectedErrors:   []error{},
		},
		{
			name: "Added event gets an appropriate result",
			imageIDstoWlids: map[string][]string{
				"testName": {"testWlid"},
			},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "testWlid",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{},
		},
		{
			name: "Mismatched object gets an appropriate error",
			imageIDstoWlids: map[string][]string{
				"testName": {"testWlid"},
			},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &core1.Pod{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
			},
			expectedCommands: []apis.Command{},
			expectedErrors:   []error{ErrUnsupportedObject},
		},
		{
			name: "Skipped event does not disrupt listeners",
			imageIDstoWlids: map[string][]string{
				"testName": {"testWlid"},
			},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
				{
					Type: watch.Bookmark,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
				{
					Type: watch.Added,
					Object: &core1.Pod{
						ObjectMeta: v1.ObjectMeta{Name: "testName"},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "testWlid",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{ErrUnsupportedObject},
		},
		{
			name: "Multiple added events produce matching commands",
			imageIDstoWlids: map[string][]string{
				"imageID-01": {"wlid-01"},
				"imageID-02": {"wlid-02"},
			},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "imageID-01"},
					},
				},
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "imageID-02"},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid-01",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid-02",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{},
		},
		{
			name:            "Unknown ImageID produces a matching error",
			imageIDstoWlids: map[string][]string{},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "Unknown Image ID"},
					},
				},
			},
			expectedCommands: []apis.Command{},
			expectedErrors:   []error{ErrUnknownImageID},
		},
		{
			name: "Missing ImageID does not disrupt further processing",
			imageIDstoWlids: map[string][]string{
				"imageID-01": {"test-wlid-01"},
				"imageID-02": {"test-wlid-02"},
			},
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "Unknown Image ID"},
					},
				},
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "imageID-01"},
					},
				},
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3{
						ObjectMeta: v1.ObjectMeta{Name: "imageID-02"},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "test-wlid-01",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "test-wlid-02",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{ErrUnknownImageID},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := k8sfake.NewSimpleClientset()

			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			ksStorageClient := kssfake.NewSimpleClientset()
			wh, _ := NewWatchHandler(context.TODO(), k8sAPI, ksStorageClient, tc.imageIDstoWlids)

			commandsCh := make(chan *apis.Command)
			errCh := make(chan error)

			sbomEvents := make(chan watch.Event)

			go func() {
				for _, event := range tc.inputEvents {
					sbomEvents <- event
				}

				close(sbomEvents)
			}()

			go wh.HandleSBOMEvents(sbomEvents, commandsCh, errCh)

			actualCommands := []apis.Command{}
			actualErrors := []error{}

			var done bool
			for !done {
				select {
				case command, ok := <-commandsCh:
					if ok {
						actualCommands = append(actualCommands, *command)
					} else {
						done = true
					}
				case err, ok := <-errCh:
					if ok {
						actualErrors = append(actualErrors, err)
					} else {
						done = true
					}
				}
			}

			assert.Equalf(t, tc.expectedCommands, actualCommands, "Commands should match")
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
	wh, _ := NewWatchHandler(context.TODO(), k8sAPI, ksStorageClient, imageIDsToWlids)

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

func TestAddToImageIDToWlidsMap(t *testing.T) {
	wh := NewWatchHandlerMock()

	wh.addToImageIDToWlidsMap("alpine@sha256:1", "wlid1")
	wh.addToImageIDToWlidsMap("alpine@sha256:2", "wlid2")
	// add the new wlid to the same imageID
	wh.addToImageIDToWlidsMap("alpine@sha256:1", "wlid3")

	actualMap := wh.iwMap.Map()
	for imageID := range actualMap {
		sort.Strings(actualMap[imageID])
	}

	assert.Equal(t, map[string][]string{
		"alpine@sha256:1": {"wlid1", "wlid3"},
		"alpine@sha256:2": {"wlid2"},
	}, actualMap)
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
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
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
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
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
							ImageID: "docker-pullable://alpine@sha256:4",
							Name:    "container4",
						},
						{
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
