package restapihandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dispatchWaitTimeout  = 300 * time.Millisecond
	dispatchPollInterval = 5 * time.Millisecond
)

// assertNeverDispatched asserts counter stays at 0 for the whole poll window,
// not just immediately: the worker pool schedules jobs asynchronously, so a
// naive immediate check could pass even if dispatch happens moments later.
func assertNeverDispatched(t *testing.T, counter *int32Counter) {
	t.Helper()
	assert.Never(t, func() bool { return counter.get() != 0 }, dispatchWaitTimeout, dispatchPollInterval, "a rejected command must never reach the worker pool")
}

func newTestConfig(t *testing.T) config.IConfig {
	t.Helper()
	return config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, config.Config{Namespace: "kubescape"})
}

// newCountingPool returns a pool that increments count for every job it
// receives, so a test can assert whether triggerAction actually dispatched a
// command (rather than only checking the HTTP-level response, which is
// always "ok" regardless of whether a command was rejected — see ActionRequest).
func newCountingPool(t *testing.T) (*ants.PoolWithFunc, *int32Counter) {
	t.Helper()
	counter := &int32Counter{}
	pool, err := ants.NewPoolWithFunc(4, func(i any) {
		counter.inc()
	})
	require.NoError(t, err)
	t.Cleanup(pool.Release)
	return pool, counter
}

type int32Counter struct {
	mu    sync.Mutex
	value int
}

func (c *int32Counter) inc() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
}

func (c *int32Counter) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

// The endpoint has no caller authentication, so its dispatch surface must be
// limited to exactly the commands its legitimate callers (the operator's own
// scan-scheduling CronJobs) send. This test locks in that allowlist.
func TestTriggerActionAllowedCommands(t *testing.T) {
	assert.Equal(t, map[apis.NotificationPolicyType]bool{
		apis.TypeRunKubescape:   true, // kubescape-scheduler
		apis.TypeScanImages:     true, // kubevuln-scheduler
		apis.TypeScanRegistryV2: true, // registry scan CronJob
	}, triggerActionAllowedCommands)
	assert.False(t, triggerActionAllowedCommands[apis.TypeOperatorAction], "operatorAction (and therefore patch/annotate/quarantine/revert) must never be dispatchable via the unauthenticated triggerAction endpoint")
}

func TestHandleActionRequest_AllowedCommandIsDispatched(t *testing.T) {
	pool, counter := newCountingPool(t)
	resthandler := NewHTTPHandler(pool, newTestConfig(t))

	body := `{"commands":[{"commandName":"scan","designators":[{"designatorType":"Attributes","attributes":{}}]}]}`
	require.NoError(t, resthandler.HandleActionRequest(context.Background(), []byte(body)))

	require.Eventually(t, func() bool { return counter.get() == 1 }, dispatchWaitTimeout, dispatchPollInterval, "an allowed command must be dispatched to the worker pool")
}

func TestHandleActionRequest_OperatorActionIsRejected(t *testing.T) {
	pool, counter := newCountingPool(t)
	resthandler := NewHTTPHandler(pool, newTestConfig(t))

	// The exact shape a caller would need to trigger the new "patch" action —
	// must never reach the worker pool through this endpoint.
	body := `{"commands":[{"commandName":"operatorAction","args":{"action":"patch","dryRun":false,"target":{"kind":"Deployment","namespace":"payments","name":"api"},"patch":"{\"metadata\":{\"labels\":{\"pwned\":\"true\"}}}"}}]}`
	require.NoError(t, resthandler.HandleActionRequest(context.Background(), []byte(body)))

	assertNeverDispatched(t, counter)
}

func TestHandleActionRequest_UnknownCommandIsRejected(t *testing.T) {
	pool, counter := newCountingPool(t)
	resthandler := NewHTTPHandler(pool, newTestConfig(t))

	body := `{"commands":[{"commandName":"deleteEverything"}]}`
	require.NoError(t, resthandler.HandleActionRequest(context.Background(), []byte(body)))

	assertNeverDispatched(t, counter)
}

func TestHandleActionRequest_EmptyCommandNameIsRejected(t *testing.T) {
	pool, counter := newCountingPool(t)
	resthandler := NewHTTPHandler(pool, newTestConfig(t))

	body := `{"commands":[{"commandName":""}]}`
	require.NoError(t, resthandler.HandleActionRequest(context.Background(), []byte(body)))

	assertNeverDispatched(t, counter)
}

// A batch mixing an allowed and a disallowed command must dispatch only the
// allowed one — one bad command must not block or be conflated with the rest.
func TestHandleActionRequest_MixedBatchDispatchesOnlyAllowed(t *testing.T) {
	pool, counter := newCountingPool(t)
	resthandler := NewHTTPHandler(pool, newTestConfig(t))

	body := `{"commands":[
		{"commandName":"operatorAction","args":{"action":"patch"}},
		{"commandName":"scan","designators":[{"designatorType":"Attributes","attributes":{}}]}
	]}`
	require.NoError(t, resthandler.HandleActionRequest(context.Background(), []byte(body)))

	require.Eventually(t, func() bool { return counter.get() == 1 }, dispatchWaitTimeout, dispatchPollInterval, "exactly the allowed command in the batch must be dispatched")
}

// End-to-end HTTP-level check: the endpoint still returns 200/"ok" for a
// rejected command (matching its existing behavior for e.g. an empty
// commandName) — the allowlist rejects the *dispatch*, it isn't surfaced as
// an HTTP error. This is what a live probe against the real endpoint would
// observe, so this test documents that shape rather than treating the
// rejection as invisible.
func TestActionRequest_RejectedCommandStillReturnsOK(t *testing.T) {
	pool, counter := newCountingPool(t)
	resthandler := NewHTTPHandler(pool, newTestConfig(t))

	body := `{"commands":[{"commandName":"operatorAction","args":{"action":"patch"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/triggerAction", strings.NewReader(body))
	rec := httptest.NewRecorder()

	resthandler.ActionRequest(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
	assertNeverDispatched(t, counter)
}
