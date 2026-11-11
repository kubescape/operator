package watcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// recordingObserver records what SBOMWatch tells an SBOMObserver.
type recordingObserver struct {
	mu    sync.Mutex
	pods  []string
	sboms []string
}

func (o *recordingObserver) ObservePod(eventType watch.EventType, pod *corev1.Pod) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pods = append(o.pods, string(eventType)+" "+pod.Namespace+"/"+pod.Name)
}

func (o *recordingObserver) ObserveSBOM(eventType watch.EventType, sbom *spdxv1beta1.SBOMSyft) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sboms = append(o.sboms, string(eventType)+" "+sbom.Name)
}

func (o *recordingObserver) seen() (pods, sboms []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.pods...), append([]string(nil), o.sboms...)
}

func testSBOM(name string) *spdxv1beta1.SBOMSyft {
	return &spdxv1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kubescape",
			Annotations: map[string]string{
				helpersv1.ImageIDMetadataKey:  testImageID,
				helpersv1.ImageTagMetadataKey: testImageTag,
				helpersv1.StatusMetadataKey:   helpersv1.Learning,
			},
		},
	}
}

// startHandleSBOMEvents runs HandleSBOMEvents until the test ends.
func startHandleSBOMEvents(t *testing.T, wh *WatchHandler) (*CooldownQueue, chan *apis.Command, chan error) {
	t.Helper()
	eventQueue := NewCooldownQueueWithParams(50*time.Millisecond, 10*time.Millisecond)
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
	return eventQueue, cmdCh, errorCh
}

// With kubevuln off, SBOMWatch runs only for the observer: it is told about
// the SBOM, and no scan command goes out, although the Wlid is known.
func TestHandleSBOMEvents_DisabledImageScansOnlyTellTheObserver(t *testing.T) {
	wh := newTestHandler(t)
	observer := &recordingObserver{}
	wh.SetSBOMObserver(observer)
	wh.DisableImageScans()
	wh.ImageToContainerData.Set(testImageHashOnly, utils.ContainerData{ContainerName: testContainerName, Wlid: testWlid})
	eventQueue, cmdCh, errorCh := startHandleSBOMEvents(t, wh)

	eventQueue.Enqueue(watch.Event{Type: watch.Added, Object: testSBOM("nginx-sbom")})

	assert.Eventually(t, func() bool {
		_, sboms := observer.seen()
		return len(sboms) == 1
	}, 3*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, cmdCh)
	assert.Empty(t, errorCh)
}

// An SBOM re-enqueued while its Wlid is unknown reaches the observer once, not
// once per retry.
func TestHandleSBOMEvents_TellsTheObserverOnceWhileWaitingForTheWlid(t *testing.T) {
	origInit, origMax, origAttempts := sbomRetryInitialDelay, sbomRetryMaxDelay, sbomRetryMaxAttempts
	sbomRetryInitialDelay = 20 * time.Millisecond
	sbomRetryMaxDelay = 40 * time.Millisecond
	sbomRetryMaxAttempts = 3
	t.Cleanup(func() {
		sbomRetryInitialDelay = origInit
		sbomRetryMaxDelay = origMax
		sbomRetryMaxAttempts = origAttempts
	})
	wh := newTestHandler(t)
	observer := &recordingObserver{}
	wh.SetSBOMObserver(observer)
	eventQueue, _, errorCh := startHandleSBOMEvents(t, wh)

	eventQueue.Enqueue(watch.Event{Type: watch.Added, Object: testSBOM("nginx-sbom")})

	select {
	case err := <-errorCh:
		assert.ErrorIs(t, err, ErrMissingWlid)
	case <-time.After(5 * time.Second):
		t.Fatal("expected the retries to run out")
	}
	_, sboms := observer.seen()
	assert.Equal(t, []string{"ADDED nginx-sbom"}, sboms)
}

// SBOMWatch passes its pod events to the observer, and with image scans off
// it does not resolve their workloads.
func TestSBOMWatch_TellsTheObserverAboutPods(t *testing.T) {
	wh := newTestHandler(t)
	observer := &recordingObserver{}
	wh.SetSBOMObserver(observer)
	wh.DisableImageScans()
	wh.eventQueue = NewCooldownQueueWithParams(50*time.Millisecond, 10*time.Millisecond)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Name: testContainerName, ImageID: testImageID}},
		},
	}
	_, err := wh.k8sAPI.KubernetesClient.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	pool, err := ants.NewPoolWithFunc(1, func(interface{}) {})
	assert.NoError(t, err)
	defer pool.Release()

	go wh.SBOMWatch(context.Background(), pool)

	assert.Eventually(t, func() bool {
		pods, _ := observer.seen()
		return len(pods) > 0 && pods[0] == "ADDED default/nginx"
	}, 3*time.Second, 20*time.Millisecond)
	assert.Empty(t, wh.ImageToContainerData.Get(testImageHashOnly).Wlid)
}
