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
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
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
	// securityExceptionWatchFailureAlertThreshold is how many consecutive watch
	// failures on a kind before the log escalates to an RBAC-misconfiguration
	// hint — so a ClusterRole missing get/list/watch surfaces clearly instead of
	// the informer silently retrying forever with no rescans.
	securityExceptionWatchFailureAlertThreshold = 3
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
	// mu guards expiredSeen and watchFailures, touched by both the event handlers
	// and the expiry sweep.
	mu sync.Mutex
	// expiredSeen tracks exceptions we have already rescanned on expiry, keyed by
	// GVR/namespace/name, so each expiry triggers exactly one rescan.
	expiredSeen map[string]struct{}
	// watchFailures counts consecutive informer watch failures per resource, so a
	// persistently-broken watch (e.g. missing RBAC) can be escalated in the logs.
	watchFailures map[string]int
	clock         func() time.Time

	// tunables captured at construction so a running handler is unaffected by
	// later changes to the package globals (and so tests are race-free).
	rescanThrottle time.Duration
	expirySweep    time.Duration
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
		dynamicClient:  dynamicClient,
		cfg:            cfg,
		eventQueue:     NewCooldownQueueWithParams(securityExceptionCooldown, securityExceptionEvictionInterval),
		rescanSignal:   make(chan struct{}, 1),
		expiredSeen:    map[string]struct{}{},
		watchFailures:  map[string]int{},
		clock:          time.Now,
		rescanThrottle: securityExceptionRescanThrottle,
		expirySweep:    securityExceptionExpirySweepInterval,
	}
}

// SecurityExceptionWatch starts the informers, the expiry sweep and the rescan
// dispatcher. It blocks until ctx is cancelled.
func (wh *SecurityExceptionWatchHandler) SecurityExceptionWatch(ctx context.Context) {
	defer wh.eventQueue.Stop()
	wh.startInformers(ctx)
	go wh.expiryLoop(ctx)
	go wh.rescanLoop(ctx)
	wh.handleEvents(ctx)
}

// startInformers builds a resilient dynamic informer for each exception kind.
//
// The shared informer machinery tracks resourceVersion and relists on watch
// errors (reconnects, "resource version too old"), so no create/update/delete is
// missed across the watch rotations the apiserver performs periodically — the gap
// a hand-rolled list-once + bare re-watch would leak through. The initial cache
// sync also replays every pre-existing exception as an Add, so exceptions present
// before the operator started are honored (replacing an explicit list step).
func (wh *SecurityExceptionWatchHandler) startInformers(ctx context.Context) {
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(wh.dynamicClient, 0, metav1.NamespaceAll, nil)
	for _, gvr := range []schema.GroupVersionResource{securityExceptionGVR, clusterSecurityExceptionGVR} {
		informer := factory.ForResource(gvr).Informer()
		// Must be set before the informer starts (below, via factory.Start).
		if err := informer.SetWatchErrorHandler(wh.newWatchErrorHandler(ctx, gvr)); err != nil {
			logger.L().Ctx(ctx).Error("failed to set security exception watch error handler",
				helpers.String("resource", gvr.Resource), helpers.Error(err))
		}
		if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { wh.enqueueInformerEvent(gvr, watch.Added, obj) },
			UpdateFunc: func(_, obj interface{}) { wh.enqueueInformerEvent(gvr, watch.Modified, obj) },
			DeleteFunc: func(obj interface{}) { wh.enqueueInformerEvent(gvr, watch.Deleted, obj) },
		}); err != nil {
			logger.L().Ctx(ctx).Error("failed to register security exception event handler",
				helpers.String("resource", gvr.Resource), helpers.Error(err))
		}
	}
	factory.Start(ctx.Done())
}

// enqueueInformerEvent normalizes an informer callback object to Unstructured
// (unwrapping delete tombstones) and forwards it to the cooldown queue. A
// delivered event also proves the watch is healthy, so it clears the consecutive
// failure counter used by the watch-error handler.
func (wh *SecurityExceptionWatchHandler) enqueueInformerEvent(gvr schema.GroupVersionResource, eventType watch.EventType, obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		// On delete the informer may deliver a DeletedFinalStateUnknown tombstone
		// when the final state was missed; unwrap the last-known object.
		tombstone, isTombstone := obj.(cache.DeletedFinalStateUnknown)
		if !isTombstone {
			return
		}
		if u, ok = tombstone.Obj.(*unstructured.Unstructured); !ok {
			return
		}
	}
	wh.resetWatchFailures(gvr)
	logger.L().Debug("security exception event",
		helpers.String("resource", gvr.Resource),
		helpers.String("type", string(eventType)))
	wh.eventQueue.Enqueue(watch.Event{Type: eventType, Object: u})
}

// newWatchErrorHandler returns a reflector error handler that makes a
// persistently-failing watch non-silent: it counts consecutive failures per
// resource and, past a threshold, escalates the log to an RBAC hint. The
// reflector already backs off between retries, so this does not spam.
func (wh *SecurityExceptionWatchHandler) newWatchErrorHandler(ctx context.Context, gvr schema.GroupVersionResource) cache.WatchErrorHandler {
	return func(_ *cache.Reflector, err error) {
		wh.mu.Lock()
		wh.watchFailures[gvr.Resource]++
		n := wh.watchFailures[gvr.Resource]
		wh.mu.Unlock()

		if n >= securityExceptionWatchFailureAlertThreshold {
			logger.L().Ctx(ctx).Error(
				"security exception watch is failing repeatedly; verify the operator ClusterRole grants get/list/watch on this resource under kubescape.io — rescans will not fire until the watch recovers",
				helpers.String("resource", gvr.Resource),
				helpers.Int("consecutiveFailures", n),
				helpers.Error(err))
			return
		}
		logger.L().Ctx(ctx).Error("security exception watch failed, retrying",
			helpers.String("resource", gvr.Resource),
			helpers.Int("consecutiveFailures", n),
			helpers.Error(err))
	}
}

// resetWatchFailures clears the consecutive-failure counter for a resource once
// a watch event is successfully delivered.
func (wh *SecurityExceptionWatchHandler) resetWatchFailures(gvr schema.GroupVersionResource) {
	wh.mu.Lock()
	delete(wh.watchFailures, gvr.Resource)
	wh.mu.Unlock()
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
				// Re-arm so a transient failure (e.g. the shared worker pool is
				// overloaded and Invoke returns ErrPoolOverload) is retried after
				// the throttle instead of being dropped until the next unrelated
				// change. The throttle sleep below prevents a tight retry loop.
				logger.L().Ctx(ctx).Error("failed to dispatch security exception rescan, will retry after throttle", helpers.Error(err))
				wh.requestRescan()
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

	// entry captures the expiry decision for one exception, computed outside the
	// lock so the (potentially slow) List calls never block forgetExpired.
	type entry struct {
		key       string
		expired   bool
		kind      string
		name      string
		namespace string
	}
	var entries []entry
	for _, gvr := range []schema.GroupVersionResource{securityExceptionGVR, clusterSecurityExceptionGVR} {
		// Paginate the list (matching the informer's list behavior) so the sweep
		// stays bounded if the exception count grows large.
		err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return wh.dynamicClient.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
		}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			item, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return nil
			}
			expiresAt, ok := parseExpiresAt(item)
			entries = append(entries, entry{
				key:       expiredKey(gvr, item),
				expired:   ok && !now.Before(expiresAt),
				kind:      item.GetKind(),
				name:      item.GetName(),
				namespace: item.GetNamespace(),
			})
			return nil
		})
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to list security exceptions for expiry sweep",
				helpers.String("resource", gvr.Resource), helpers.Error(err))
			continue
		}
	}

	newlyExpired := false
	wh.mu.Lock()
	for _, e := range entries {
		if !e.expired {
			// not expired (or never expires): drop any stale mark so a future
			// re-expiry (e.g. expiresAt pushed out then back) is caught again
			delete(wh.expiredSeen, e.key)
			continue
		}
		if _, seen := wh.expiredSeen[e.key]; seen {
			continue
		}
		wh.expiredSeen[e.key] = struct{}{}
		newlyExpired = true
		logger.L().Info("security exception expired, requesting rescan",
			helpers.String("kind", e.kind),
			helpers.String("name", e.name),
			helpers.String("namespace", e.namespace))
	}
	wh.mu.Unlock()

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
