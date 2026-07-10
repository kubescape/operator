package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	beUtils "github.com/kubescape/backend/pkg/utils"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const testClusterName = "test-cluster"

// shortenTunables sets the package tunables to test-friendly durations and
// returns a restore func. Call before constructing a handler (the cooldown queue
// captures its durations at construction).
func shortenTunables(t *testing.T) {
	t.Helper()
	origCooldown := securityExceptionCooldown
	origEviction := securityExceptionEvictionInterval
	origThrottle := securityExceptionRescanThrottle
	origRetry := securityExceptionWatchRetryInterval
	securityExceptionCooldown = 10 * time.Millisecond
	securityExceptionEvictionInterval = 5 * time.Millisecond
	securityExceptionRescanThrottle = 10 * time.Millisecond
	securityExceptionWatchRetryInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		securityExceptionCooldown = origCooldown
		securityExceptionEvictionInterval = origEviction
		securityExceptionRescanThrottle = origThrottle
		securityExceptionWatchRetryInterval = origRetry
	})
}

func testConfig() config.IConfig {
	return config.NewOperatorConfig(
		config.CapabilitiesConfig{},
		utilsmetadata.ClusterConfig{ClusterName: testClusterName},
		&beUtils.Credentials{},
		config.Config{},
	)
}

func fakeDynamicClient(objs ...runtime.Object) dynamic.Interface {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, objs...)
}

func newSecurityException(namespace, name, expiresAt string) *unstructured.Unstructured {
	kind := "SecurityException"
	if namespace == "" {
		kind = "ClusterSecurityException"
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   securityExceptionGroup,
		Version: securityExceptionVersion,
		Kind:    kind,
	})
	obj.SetName(name)
	if namespace != "" {
		obj.SetNamespace(namespace)
	}
	spec := map[string]interface{}{}
	if expiresAt != "" {
		spec["expiresAt"] = expiresAt
	}
	obj.Object["spec"] = spec
	return obj
}

// recordingHandler wires a handler whose rescans are captured on a channel.
func recordingHandler(t *testing.T, objs ...runtime.Object) (*SecurityExceptionWatchHandler, <-chan *apis.Command) {
	t.Helper()
	shortenTunables(t)
	wh := newSecurityExceptionWatchHandler(testConfig(), fakeDynamicClient(objs...))
	dispatched := make(chan *apis.Command, 16)
	wh.dispatchRescan = func(ctx context.Context, cmd *apis.Command) error {
		dispatched <- cmd
		return nil
	}
	return wh, dispatched
}

func TestBuildRescanCommand(t *testing.T) {
	cmd := buildRescanCommand(testClusterName)

	assert.Equal(t, apis.TypeRunKubescape, cmd.CommandName)
	assert.Equal(t, pkgwlid.GetK8sWLID(testClusterName, "", "", ""), cmd.WildWlid)

	raw, ok := cmd.Args[utils.KubescapeScanV1]
	require.True(t, ok, "command must carry a KubescapeScanV1 payload")
	psr, ok := raw.(utilsmetav1.PostScanRequest)
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"allcontrols", "nsa", "mitre"}, psr.TargetNames)
	require.NotNil(t, psr.HostScanner)
	assert.False(t, *psr.HostScanner)
}

func TestParseExpiresAt(t *testing.T) {
	tt := []struct {
		name    string
		value   string
		present bool
	}{
		{"absent", "", false},
		{"valid rfc3339", "2026-07-01T00:00:00Z", true},
		{"invalid format", "not-a-date", false},
		{"date only", "2026-07-01", false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			obj := newSecurityException("prod", "x", tc.value)
			got, ok := parseExpiresAt(obj)
			assert.Equal(t, tc.present, ok)
			if tc.present {
				want, _ := time.Parse(time.RFC3339, tc.value)
				assert.True(t, want.Equal(got))
			}
		})
	}
}

func TestParseExpiresAtMissingSpec(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	obj.SetName("x")
	_, ok := parseExpiresAt(obj)
	assert.False(t, ok)
}

func TestRequestRescanCoalesces(t *testing.T) {
	wh := newSecurityExceptionWatchHandler(testConfig(), fakeDynamicClient())
	for i := 0; i < 5; i++ {
		wh.requestRescan()
	}
	assert.Len(t, wh.rescanSignal, 1, "multiple requests must collapse into one pending rescan")
}

func TestSweepExpiredTriggersOnceThenIdempotent(t *testing.T) {
	past := "2020-01-01T00:00:00Z"
	future := "2999-01-01T00:00:00Z"
	wh, _ := recordingHandler(t,
		newSecurityException("prod", "expired-se", past),
		newSecurityException("prod", "live-se", future),
		newSecurityException("", "expired-cse", past),
		newSecurityException("", "no-expiry-cse", ""),
	)
	wh.clock = func() time.Time { return time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) }

	wh.sweepExpired(context.Background())

	// two expired exceptions (namespaced + cluster) were found
	assert.Len(t, wh.expiredSeen, 2)
	assert.Len(t, wh.rescanSignal, 1, "a newly-expired exception must request a rescan")

	// drain and sweep again: nothing new expired, so no additional rescan
	<-wh.rescanSignal
	wh.sweepExpired(context.Background())
	assert.Len(t, wh.rescanSignal, 0, "already-expired exceptions must not re-trigger")
}

func TestSweepExpiredRearmsWhenExpiryPushedOut(t *testing.T) {
	past := "2020-01-01T00:00:00Z"
	future := "2999-01-01T00:00:00Z"
	wh, _ := recordingHandler(t, newSecurityException("prod", "se", past))
	wh.clock = func() time.Time { return time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) }

	wh.sweepExpired(context.Background())
	require.Len(t, wh.expiredSeen, 1)
	<-wh.rescanSignal

	// user pushes expiresAt into the future -> mark must be cleared
	_, err := wh.dynamicClient.Resource(securityExceptionGVR).Namespace("prod").
		Update(context.Background(), newSecurityException("prod", "se", future), metav1.UpdateOptions{})
	require.NoError(t, err)

	wh.sweepExpired(context.Background())
	assert.Len(t, wh.expiredSeen, 0, "no-longer-expired exception must be un-marked")
	assert.Len(t, wh.rescanSignal, 0)
}

func TestListExistingEnqueuesEachObject(t *testing.T) {
	wh, _ := recordingHandler(t,
		newSecurityException("prod", "a", ""),
		newSecurityException("prod", "b", ""),
	)

	require.NoError(t, wh.listExisting(context.Background(), securityExceptionGVR))

	got := drainEvents(t, wh.eventQueue, 2, time.Second)
	names := map[string]bool{}
	for _, e := range got {
		names[e.Object.(*unstructured.Unstructured).GetName()] = true
	}
	assert.Equal(t, map[string]bool{"a": true, "b": true}, names)
}

func TestHandleEventsDispatchesRescan(t *testing.T) {
	wh, dispatched := recordingHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go wh.rescanLoop(ctx)
	go wh.handleEvents(ctx)

	wh.eventQueue.Enqueue(watch.Event{Type: watch.Added, Object: newSecurityException("prod", "se", "")})

	select {
	case cmd := <-dispatched:
		assert.Equal(t, apis.TypeRunKubescape, cmd.CommandName)
	case <-time.After(2 * time.Second):
		t.Fatal("expected a rescan to be dispatched for the enqueued event")
	}
}

func TestSecurityExceptionWatchDispatchesForExistingException(t *testing.T) {
	wh, dispatched := recordingHandler(t, newSecurityException("prod", "pre-existing", ""))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go wh.SecurityExceptionWatch(ctx)

	select {
	case cmd := <-dispatched:
		assert.Equal(t, apis.TypeRunKubescape, cmd.CommandName)
		assert.Equal(t, pkgwlid.GetK8sWLID(testClusterName, "", "", ""), cmd.WildWlid)
	case <-time.After(3 * time.Second):
		t.Fatal("expected a rescan for the pre-existing exception on startup")
	}
}

// drainEvents reads up to n events from the queue within the timeout.
func drainEvents(t *testing.T, q *CooldownQueue, n int, timeout time.Duration) []watch.Event {
	t.Helper()
	var events []watch.Event
	deadline := time.After(timeout)
	for len(events) < n {
		select {
		case e := <-q.ResultChan:
			events = append(events, e)
		case <-deadline:
			t.Fatalf("timed out waiting for %d events, got %d", n, len(events))
		}
	}
	return events
}
