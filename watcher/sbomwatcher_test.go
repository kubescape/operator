package watcher

import (
	"context"
	_ "embed"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

const (
	testImageID       = "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2"
	testImageHashOnly = "aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2"
	testImageTag      = "nginx:1.14.0"
	testWlid          = "wlid://cluster-test/namespace-default/deployment-nginx"
	testContainerName = "nginx"
)

func newTestHandler(t *testing.T, startingObjects ...runtime.Object) *WatchHandler {
	t.Helper()
	clusterConfig := utilsmetadata.ClusterConfig{}
	cfg, err := config.LoadConfig("../configuration")
	assert.NoError(t, err)
	operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, cfg)

	k8sClient := k8sfake.NewClientset()
	k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
	storageClient := kssfake.NewSimpleClientset(startingObjects...)
	return NewWatchHandler(operatorConfig, k8sAPI, storageClient, nil)
}

func TestHandleSBOMEvents(t *testing.T) {
	tt := []struct {
		name                string
		seedContainerData   bool // pre-populate ImageToContainerData so Wlid is known
		inputEvents         []watch.Event
		expectedObjectNames []string
		expectedCommands    []*apis.Command
		expectedErrors      []error
	}{
		{
			name:              "Adding a new SBOM with known Wlid produces a matching scan command",
			seedContainerData: true,
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSyft{
						ObjectMeta: metav1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							Annotations: map[string]string{
								helpersv1.ImageIDMetadataKey:  testImageID,
								helpersv1.ImageTagMetadataKey: testImageTag,
							},
						},
					},
				},
				{
					Type: watch.Modified,
					Object: &spdxv1beta1.SBOMSyft{
						ObjectMeta: metav1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-e4ff-657a",
							Annotations: map[string]string{
								helpersv1.ImageIDMetadataKey:  testImageID,
								helpersv1.ImageTagMetadataKey: testImageTag,
							},
						},
					},
				},
			},
			expectedCommands: []*apis.Command{
				{
					Wlid:        testWlid,
					CommandName: apis.TypeScanImages,
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							ContainerName: testContainerName,
							ImageID:       testImageID,
							ImageTag:      testImageTag,
							Wlid:          testWlid,
						},
					},
				},
				{
					Wlid:        testWlid,
					CommandName: apis.TypeScanImages,
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							ContainerName: testContainerName,
							ImageID:       testImageID,
							ImageTag:      testImageTag,
							Wlid:          testWlid,
						},
					},
				},
			},
			expectedObjectNames: []string{
				"replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
				"replicaset-nginx-6ccd565b7d-nginx-e4ff-657a",
			},
		},
		{
			name:              "Missing image tag",
			seedContainerData: true,
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSyft{
						ObjectMeta: metav1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							Annotations: map[string]string{
								helpersv1.ImageIDMetadataKey:  testImageID,
								helpersv1.ImageTagMetadataKey: "", // missing image tag
							},
						},
					},
				},
			},
			expectedObjectNames: []string{"replicaset-nginx-6ccd565b7d-nginx-49d3-1861"},
			expectedErrors: []error{
				ErrMissingImageTag,
			},
		},
		{
			name: "Delete event",
			inputEvents: []watch.Event{
				{
					Type:   watch.Deleted,
					Object: &spdxv1beta1.SBOMSyft{},
				},
			},
			expectedObjectNames: []string{""},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var startingObjects []runtime.Object
			for _, e := range tc.inputEvents {
				startingObjects = append(startingObjects, e.Object)
			}

			ctx := context.Background()
			wh := newTestHandler(t, startingObjects...)
			if tc.seedContainerData {
				wh.ImageToContainerData.Set(testImageHashOnly, utils.ContainerData{
					ContainerName: testContainerName,
					Wlid:          testWlid,
				})
			}

			eventQueue := NewCooldownQueueWithParams(1*time.Second, 1*time.Second)
			cmdCh := make(chan *apis.Command)
			errorCh := make(chan error)

			go wh.HandleSBOMEvents(eventQueue, cmdCh, errorCh)

			go func() {
				for _, e := range tc.inputEvents {
					eventQueue.Enqueue(e)
				}
				time.Sleep(5 * time.Second)
				eventQueue.Stop()
			}()

			done := false
			var actualErrors []error
			var actualCommands []*apis.Command
			for !done {
				select {
				case err, ok := <-errorCh:
					if !ok {
						done = true
						break
					}
					actualErrors = append(actualErrors, err)
				case cmd, ok := <-cmdCh:
					if !ok {
						done = true
						break
					}
					actualCommands = append(actualCommands, cmd)
				}
			}

			actualObjects, _ := wh.storageClient.SpdxV1beta1().SBOMSyfts("").List(ctx, metav1.ListOptions{})

			var actualObjectNames []string
			for _, obj := range actualObjects.Items {
				actualObjectNames = append(actualObjectNames, obj.ObjectMeta.Name)
			}

			assert.Equal(t, tc.expectedObjectNames, actualObjectNames, "Objects in the storage don't match")
			assert.Equal(t, tc.expectedErrors, actualErrors, "Errors don't match")
			assert.ElementsMatch(t, tc.expectedCommands, actualCommands, "Commands don't match")
		})
	}
}

// TestValidateContainerData covers the validation gate directly, including the
// new ErrMissingWlid case added to fix kubescape/operator#378.
func TestValidateContainerData(t *testing.T) {
	cases := []struct {
		name    string
		data    *utils.ContainerData
		wantErr error
	}{
		{
			name:    "all fields present",
			data:    &utils.ContainerData{ImageID: testImageID, ImageTag: testImageTag, Wlid: testWlid},
			wantErr: nil,
		},
		{
			name:    "missing ImageID",
			data:    &utils.ContainerData{ImageTag: testImageTag, Wlid: testWlid},
			wantErr: ErrMissingImageID,
		},
		{
			name:    "missing ImageTag",
			data:    &utils.ContainerData{ImageID: testImageID, Wlid: testWlid},
			wantErr: ErrMissingImageTag,
		},
		{
			name:    "missing Wlid (regression for #378)",
			data:    &utils.ContainerData{ImageID: testImageID, ImageTag: testImageTag},
			wantErr: ErrMissingWlid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, validateContainerData(tc.data), tc.wantErr)
		})
	}
}

// TestSBOMRetryBackoff verifies the bounded exponential backoff schedule.
func TestSBOMRetryBackoff(t *testing.T) {
	// Force a known schedule.
	origInit, origMax := sbomRetryInitialDelay, sbomRetryMaxDelay
	sbomRetryInitialDelay = 1 * time.Second
	sbomRetryMaxDelay = 8 * time.Second
	t.Cleanup(func() {
		sbomRetryInitialDelay = origInit
		sbomRetryMaxDelay = origMax
	})

	assert.Equal(t, 1*time.Second, sbomRetryBackoff(0))
	assert.Equal(t, 2*time.Second, sbomRetryBackoff(1))
	assert.Equal(t, 4*time.Second, sbomRetryBackoff(2))
	assert.Equal(t, 8*time.Second, sbomRetryBackoff(3))
	// Capped.
	assert.Equal(t, 8*time.Second, sbomRetryBackoff(4))
	assert.Equal(t, 8*time.Second, sbomRetryBackoff(20))
	// Even a huge attempt that would overflow the shift stays capped.
	assert.Equal(t, 8*time.Second, sbomRetryBackoff(64))
}

// TestHandleSBOMEvents_WlidArrivesLate reproduces the issue: an SBOM event
// arrives before the owning pod is observed. The handler must NOT dispatch a
// scan command with Wlid="". Once the pod information lands, the re-enqueued
// SBOM should produce a correctly-attributed scan command.
func TestHandleSBOMEvents_WlidArrivesLate(t *testing.T) {
	origInit, origMax, origAttempts := sbomRetryInitialDelay, sbomRetryMaxDelay, sbomRetryMaxAttempts
	sbomRetryInitialDelay = 100 * time.Millisecond
	sbomRetryMaxDelay = 200 * time.Millisecond
	sbomRetryMaxAttempts = 10
	t.Cleanup(func() {
		sbomRetryInitialDelay = origInit
		sbomRetryMaxDelay = origMax
		sbomRetryMaxAttempts = origAttempts
	})

	sbom := &spdxv1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-nginx-late-wlid",
			Namespace: "default",
			Annotations: map[string]string{
				helpersv1.ImageIDMetadataKey:  testImageID,
				helpersv1.ImageTagMetadataKey: testImageTag,
			},
		},
	}

	wh := newTestHandler(t, sbom)
	eventQueue := NewCooldownQueueWithParams(150*time.Millisecond, 50*time.Millisecond)
	cmdCh := make(chan *apis.Command, 4)
	errorCh := make(chan error, 4)

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		wh.HandleSBOMEvents(eventQueue, cmdCh, errorCh)
	}()
	t.Cleanup(func() {
		eventQueue.Stop()
		<-handlerDone
	})

	// Enqueue the SBOM while ImageToContainerData is empty.
	eventQueue.Enqueue(watch.Event{Type: watch.Added, Object: sbom})

	// After a couple of retry cycles, simulate the pod informer populating the map.
	time.AfterFunc(350*time.Millisecond, func() {
		wh.ImageToContainerData.Set(testImageHashOnly, utils.ContainerData{
			ContainerName: testContainerName,
			Wlid:          testWlid,
		})
	})

	var cmd *apis.Command
	select {
	case cmd = <-cmdCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("expected a scan command after Wlid became available")
	}

	assert.Equal(t, testWlid, cmd.Wlid, "scan command must carry the correct Wlid, not an empty string")
	assert.Equal(t, apis.TypeScanImages, cmd.CommandName)

	// No errors should have been emitted (re-enqueue path does not produce errors
	// until retries are exhausted).
	select {
	case err := <-errorCh:
		t.Fatalf("unexpected error before retry exhaustion: %v", err)
	default:
	}

	// Bookkeeping should be cleared after success.
	key := sbom.Namespace + "/" + sbom.Name
	_, exists := wh.sbomRetryAttempts.Load(key)
	assert.False(t, exists, "retry counter must be cleared on success")
}

// TestHandleSBOMEvents_WlidNeverArrives_ExhaustsRetries verifies the
// "don't retry forever" requirement from the issue discussion: after a bounded
// number of attempts, the SBOM is dropped with ErrMissingWlid and no malformed
// scan command is ever produced.
func TestHandleSBOMEvents_WlidNeverArrives_ExhaustsRetries(t *testing.T) {
	origInit, origMax, origAttempts := sbomRetryInitialDelay, sbomRetryMaxDelay, sbomRetryMaxAttempts
	sbomRetryInitialDelay = 50 * time.Millisecond
	sbomRetryMaxDelay = 50 * time.Millisecond
	sbomRetryMaxAttempts = 3
	t.Cleanup(func() {
		sbomRetryInitialDelay = origInit
		sbomRetryMaxDelay = origMax
		sbomRetryMaxAttempts = origAttempts
	})

	sbom := &spdxv1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-orphan-sbom",
			Namespace: "default",
			Annotations: map[string]string{
				helpersv1.ImageIDMetadataKey:  testImageID,
				helpersv1.ImageTagMetadataKey: testImageTag,
			},
		},
	}

	wh := newTestHandler(t, sbom)
	eventQueue := NewCooldownQueueWithParams(60*time.Millisecond, 20*time.Millisecond)
	cmdCh := make(chan *apis.Command, 4)
	errorCh := make(chan error, 4)

	// Drain cmdCh in the background so we can assert nothing was sent.
	var cmdMu sync.Mutex
	var receivedCmds []*apis.Command
	cmdDone := make(chan struct{})
	go func() {
		defer close(cmdDone)
		for c := range cmdCh {
			cmdMu.Lock()
			receivedCmds = append(receivedCmds, c)
			cmdMu.Unlock()
		}
	}()

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		wh.HandleSBOMEvents(eventQueue, cmdCh, errorCh)
	}()
	t.Cleanup(func() {
		eventQueue.Stop()
		<-handlerDone
		close(cmdCh)
		<-cmdDone
	})

	eventQueue.Enqueue(watch.Event{Type: watch.Added, Object: sbom})

	var finalErr error
	select {
	case finalErr = <-errorCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("expected ErrMissingWlid after retries exhausted")
	}
	assert.ErrorIs(t, finalErr, ErrMissingWlid)

	cmdMu.Lock()
	assert.Empty(t, receivedCmds, "no scan commands should be dispatched when Wlid never resolves")
	cmdMu.Unlock()

	// Bookkeeping must be cleared on exhaustion to avoid leaking memory if the
	// SBOM is later re-observed.
	key := sbom.Namespace + "/" + sbom.Name
	_, exists := wh.sbomRetryAttempts.Load(key)
	assert.False(t, exists, "retry counter must be cleared on exhaustion")
}
