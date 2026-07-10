package watcher

import (
	"context"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/boolutils"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/pager"
)

// SecurityException CRDs are served at kubescape.io/v1beta1 (see the Helm chart
// and kubescape's CRDExceptionsGetter). Keep this in sync when the CRD graduates.
const (
	securityExceptionGroup   = "kubescape.io"
	securityExceptionVersion = "v1beta1"
)

var (
	securityExceptionGVR = schema.GroupVersionResource{
		Group:    securityExceptionGroup,
		Version:  securityExceptionVersion,
		Resource: "securityexceptions",
	}
	clusterSecurityExceptionGVR = schema.GroupVersionResource{
		Group:    securityExceptionGroup,
		Version:  securityExceptionVersion,
		Resource: "clustersecurityexceptions",
	}
)

// Tunables declared as vars (not consts) so tests can shorten them.
var (
	// securityExceptionCooldown debounces rapid changes to the same exception.
	securityExceptionCooldown = 5 * time.Second
	// securityExceptionEvictionInterval is how often the cooldown cache is swept.
	securityExceptionEvictionInterval = 1 * time.Second
	// securityExceptionRescanThrottle is the minimum gap between two dispatched
	// full rescans, so a burst of changes (e.g. a GitOps apply of many CRDs)
	// collapses into a single cluster rescan.
	securityExceptionRescanThrottle = 10 * time.Second
	// securityExceptionExpirySweepInterval is how often expired exceptions are
	// swept. Expiry is evaluated at scan time by the scanners; this loop only
	// dispatches a rescan so previously-excepted findings resurface promptly.
	securityExceptionExpirySweepInterval = 5 * time.Minute
	// securityExceptionWatchRetryInterval backs off before re-establishing a
	// dropped watch.
	securityExceptionWatchRetryInterval = 5 * time.Second
)

// SecurityExceptionWatchHandler watches SecurityException and
// ClusterSecurityException CRDs and dispatches a cluster posture rescan whenever
// an exception is created, changed, removed, or expires — so results reflect the
// current set of exceptions without waiting for the next scheduled scan.
type SecurityExceptionWatchHandler struct {
	dynamicClient dynamic.Interface
	cfg           config.IConfig
	eventQueue    *CooldownQueue
	// dispatchRescan sends a rescan command; injectable for tests.
	dispatchRescan func(ctx context.Context, cmd *apis.Command) error
	// rescanSignal coalesces rescan requests: a buffered-by-one channel means
	// many triggers collapse into at most one pending rescan.
	rescanSignal chan struct{}
	// mu guards expiredSeen, which is touched by both the event handler and the
	// expiry sweep.
	mu sync.Mutex
	// expiredSeen tracks exceptions we have already rescanned on expiry, keyed by
	// GVR/namespace/name, so each expiry triggers exactly one rescan.
	expiredSeen map[string]struct{}
	clock       func() time.Time

	// tunables captured at construction so a running handler is unaffected by
	// later changes to the package globals (and so tests are race-free).
	rescanThrottle     time.Duration
	watchRetryInterval time.Duration
	expirySweep        time.Duration
}

// NewSecurityExceptionWatchHandler returns a handler that dispatches rescans onto
// the given worker pool.
func NewSecurityExceptionWatchHandler(cfg config.IConfig, dynamicClient dynamic.Interface, workerPool *ants.PoolWithFunc) *SecurityExceptionWatchHandler {
	wh := newSecurityExceptionWatchHandler(cfg, dynamicClient)
	wh.dispatchRescan = func(ctx context.Context, cmd *apis.Command) error {
		return utils.AddCommandToChannel(ctx, cfg, cmd, workerPool)
	}
	return wh
}

// newSecurityExceptionWatchHandler builds a handler without a dispatcher wired,
// so tests can inject their own dispatchRescan.
func newSecurityExceptionWatchHandler(cfg config.IConfig, dynamicClient dynamic.Interface) *SecurityExceptionWatchHandler {
	return &SecurityExceptionWatchHandler{
		dynamicClient:      dynamicClient,
		cfg:                cfg,
		eventQueue:         NewCooldownQueueWithParams(securityExceptionCooldown, securityExceptionEvictionInterval),
		rescanSignal:       make(chan struct{}, 1),
		expiredSeen:        map[string]struct{}{},
		clock:              time.Now,
		rescanThrottle:     securityExceptionRescanThrottle,
		watchRetryInterval: securityExceptionWatchRetryInterval,
		expirySweep:        securityExceptionExpirySweepInterval,
	}
}

// SecurityExceptionWatch starts the watchers, the expiry sweep and the rescan
// dispatcher. It blocks until ctx is cancelled.
func (wh *SecurityExceptionWatchHandler) SecurityExceptionWatch(ctx context.Context) {
	go wh.watchKind(ctx, securityExceptionGVR)
	go wh.watchKind(ctx, clusterSecurityExceptionGVR)
	go wh.expiryLoop(ctx)
	go wh.rescanLoop(ctx)
	wh.handleEvents(ctx)
}

// watchKind lists the existing objects of a kind (so exceptions present before
// the operator started are honored) and then follows changes, forwarding every
// event to the cooldown queue.
func (wh *SecurityExceptionWatchHandler) watchKind(ctx context.Context, gvr schema.GroupVersionResource) {
	if err := wh.listExisting(ctx, gvr); err != nil {
		logger.L().Ctx(ctx).Error("failed to list existing security exceptions",
			helpers.String("resource", gvr.Resource), helpers.Error(err))
	}

	for {
		if ctx.Err() != nil {
			return
		}
		w, err := wh.dynamicClient.Resource(gvr).Namespace(metav1.NamespaceAll).Watch(ctx, metav1.ListOptions{})
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to watch security exceptions, retrying",
				helpers.String("resource", gvr.Resource), helpers.Error(err))
			if !sleepCtx(ctx, wh.watchRetryInterval) {
				return
			}
			continue
		}
		wh.consumeWatch(ctx, gvr, w)
	}
}

// consumeWatch forwards events from a single watch until it closes or ctx ends.
func (wh *SecurityExceptionWatchHandler) consumeWatch(ctx context.Context, gvr schema.GroupVersionResource, w watch.Interface) {
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.ResultChan():
			if !ok {
				// watch closed; back off before the caller re-establishes it
				sleepCtx(ctx, wh.watchRetryInterval)
				return
			}
			if event.Type == watch.Bookmark || event.Type == watch.Error {
				continue
			}
			if _, ok := event.Object.(*unstructured.Unstructured); !ok {
				continue
			}
			logger.L().Debug("security exception event",
				helpers.String("resource", gvr.Resource),
				helpers.String("type", string(event.Type)))
			wh.eventQueue.Enqueue(event)
		}
	}
}

// listExisting enqueues an Added event for every currently-present object.
func (wh *SecurityExceptionWatchHandler) listExisting(ctx context.Context, gvr schema.GroupVersionResource) error {
	return pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return wh.dynamicClient.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		wh.eventQueue.Enqueue(watch.Event{Type: watch.Added, Object: obj})
		return nil
	})
}

// handleEvents consumes debounced events and requests a rescan for each.
func (wh *SecurityExceptionWatchHandler) handleEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-wh.eventQueue.ResultChan:
			if !ok {
				return
			}
			obj, ok := e.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			logger.L().Info("security exception changed, requesting rescan",
				helpers.String("kind", obj.GetKind()),
				helpers.String("name", obj.GetName()),
				helpers.String("namespace", obj.GetNamespace()),
				helpers.String("type", string(e.Type)))
			// On delete, the exception no longer suppresses anything, so its
			// expiry bookkeeping can be forgotten.
			if e.Type == watch.Deleted {
				wh.forgetExpired(obj)
			}
			wh.requestRescan()
		}
	}
}

// requestRescan signals the rescan loop without blocking. Because rescanSignal
// is buffered by one, concurrent requests coalesce into a single pending rescan.
func (wh *SecurityExceptionWatchHandler) requestRescan() {
	select {
	case wh.rescanSignal <- struct{}{}:
	default:
	}
}

// rescanLoop dispatches one cluster posture rescan per signal, throttled so a
// burst of changes does not produce a storm of full scans.
func (wh *SecurityExceptionWatchHandler) rescanLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-wh.rescanSignal:
			cmd := buildRescanCommand(wh.cfg.ClusterName())
			if err := wh.dispatchRescan(ctx, cmd); err != nil {
				logger.L().Ctx(ctx).Error("failed to dispatch security exception rescan", helpers.Error(err))
			} else {
				logger.L().Info("dispatched cluster posture rescan for security exception change")
			}
			if !sleepCtx(ctx, wh.rescanThrottle) {
				return
			}
		}
	}
}

// expiryLoop periodically sweeps for newly-expired exceptions and rescans so
// previously-suppressed findings resurface.
func (wh *SecurityExceptionWatchHandler) expiryLoop(ctx context.Context) {
	ticker := time.NewTicker(wh.expirySweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wh.sweepExpired(ctx)
		}
	}
}

// sweepExpired lists both kinds and requests a rescan if any exception has
// expired since the last sweep. Each expired exception triggers exactly one
// rescan (tracked in expiredSeen).
func (wh *SecurityExceptionWatchHandler) sweepExpired(ctx context.Context) {
	now := wh.clock()
	newlyExpired := false

	wh.mu.Lock()
	defer wh.mu.Unlock()
	for _, gvr := range []schema.GroupVersionResource{securityExceptionGVR, clusterSecurityExceptionGVR} {
		list, err := wh.dynamicClient.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to list security exceptions for expiry sweep",
				helpers.String("resource", gvr.Resource), helpers.Error(err))
			continue
		}
		for i := range list.Items {
			item := &list.Items[i]
			key := expiredKey(gvr, item)
			expiresAt, ok := parseExpiresAt(item)
			if !ok || now.Before(expiresAt) {
				// not expired (or never expires): drop any stale mark so a future
				// re-expiry (e.g. expiresAt pushed out then back) is caught again
				delete(wh.expiredSeen, key)
				continue
			}
			if _, seen := wh.expiredSeen[key]; seen {
				continue
			}
			wh.expiredSeen[key] = struct{}{}
			newlyExpired = true
			logger.L().Info("security exception expired, requesting rescan",
				helpers.String("kind", item.GetKind()),
				helpers.String("name", item.GetName()),
				helpers.String("namespace", item.GetNamespace()))
		}
	}
	if newlyExpired {
		wh.requestRescan()
	}
}

func (wh *SecurityExceptionWatchHandler) forgetExpired(obj *unstructured.Unstructured) {
	gvr := securityExceptionGVR
	if obj.GetNamespace() == "" {
		gvr = clusterSecurityExceptionGVR
	}
	wh.mu.Lock()
	delete(wh.expiredSeen, expiredKey(gvr, obj))
	wh.mu.Unlock()
}

// buildRescanCommand returns the cluster-wide posture rescan command, matching
// the operator's startup full scan.
func buildRescanCommand(clusterName string) *apis.Command {
	return &apis.Command{
		CommandName: apis.TypeRunKubescape,
		WildWlid:    pkgwlid.GetK8sWLID(clusterName, "", "", ""),
		Args: map[string]interface{}{
			utils.KubescapeScanV1: utilsmetav1.PostScanRequest{
				HostScanner: boolutils.BoolPointer(false),
				TargetType:  v1.KindFramework,
				TargetNames: []string{"allcontrols", "nsa", "mitre"},
			},
		},
	}
}

// parseExpiresAt reads spec.expiresAt as an RFC3339 timestamp. It returns
// (zero, false) when the field is absent, empty, or unparseable — an exception
// with no expiry never expires.
func parseExpiresAt(obj *unstructured.Unstructured) (time.Time, bool) {
	raw, found, err := unstructured.NestedString(obj.Object, "spec", "expiresAt")
	if err != nil || !found || raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func expiredKey(gvr schema.GroupVersionResource, obj *unstructured.Unstructured) string {
	return gvr.Resource + "/" + obj.GetNamespace() + "/" + obj.GetName()
}

// sleepCtx sleeps for d, returning false if ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
