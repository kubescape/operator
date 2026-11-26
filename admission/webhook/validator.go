package webhook

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	exporters "github.com/kubescape/operator/admission/exporter"
	"github.com/kubescape/operator/admission/rulebinding"
	"github.com/kubescape/operator/objectcache"
	"github.com/kubescape/operator/telemetry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes"
)

const (
	// defaultWorkerPoolSize is the number of goroutines draining the
	// admission evaluation queue. The pool is bounded; under burst load
	// excess events are dropped, never queued unboundedly.
	defaultWorkerPoolSize = 10
	// defaultQueueSize bounds the in-flight evaluation backlog. Values that
	// can't be enqueued because the queue is full are dropped with a warning.
	defaultQueueSize = 1000
	// dropLogInterval throttles drop warnings to every N drops so a burst
	// can't flood the operator log.
	dropLogInterval = 100
	// shutdownDrainTimeout bounds how long each worker spends draining queued
	// jobs after its context is canceled. Long enough to flush a full queue
	// against a healthy backend; short enough that pod termination is not
	// noticeably delayed.
	shutdownDrainTimeout = 10 * time.Second
)

// evalJob is the unit of work handed off to the validator's worker pool.
// Holding admission.Attributes directly is safe: the framework does not
// pool or recycle these records, so workers can read the same fields the
// validator handler saw.
//
// ctx carries the request-scoped context (values, tracing, and deadline)
// detached from the HTTP handler's lifecycle so that worker evaluation is not
// prematurely canceled when the HTTP response completes. cancel releases
// any deadline timer or context resources once evaluation is finished or dropped.
type evalJob struct {
	ctx    context.Context
	cancel context.CancelFunc
	attrs  admission.Attributes
}

// KindAcceptor decides whether an admission Kind should be evaluated by the
// rule pipeline. Implementations should return true for any Kind that at least
// one currently-loaded rule could match (and true for all Kinds when no
// static set can be determined). The validator uses this to skip work for
// events no rule targets.
type KindAcceptor interface {
	Accepts(kind string) bool
}

type AdmissionValidator struct {
	kubernetesClient *k8sinterface.KubernetesApi
	objectCache      objectcache.ObjectCache
	exporter         exporters.Exporter
	ruleBindingCache rulebinding.RuleBindingCache

	// selfSubject is the operator's own admission subject
	// (system:serviceaccount:<ns>:<sa>). When set, requests with a matching
	// UserInfo.Name are dropped before rule evaluation to prevent positive
	// feedback loops from the operator's own API writes. Empty when the
	// service account token cannot be parsed at startup.
	selfSubject string

	// kindAcceptor pre-filters admission events by Kind before they enter
	// the evaluation pipeline. nil means accept all Kinds.
	kindAcceptor KindAcceptor

	// Async evaluation pipeline. Validate() snapshots requests onto jobs
	// and returns nil immediately; worker goroutines drain the channel.
	jobs        chan evalJob
	workerCount int
	dropCount   atomic.Int64
	started     atomic.Bool
	wg          sync.WaitGroup
}

func NewAdmissionValidator(kubernetesClient *k8sinterface.KubernetesApi, objectCache objectcache.ObjectCache, exporter exporters.Exporter, ruleBindingCache rulebinding.RuleBindingCache) *AdmissionValidator {
	av := &AdmissionValidator{
		kubernetesClient: kubernetesClient,
		objectCache:      objectCache,
		exporter:         exporter,
		ruleBindingCache: ruleBindingCache,
		jobs:             make(chan evalJob, defaultQueueSize),
		workerCount:      defaultWorkerPoolSize,
	}

	subject, err := readSelfSubject(defaultServiceAccountTokenPath)
	if err != nil {
		logger.L().Warning("self-pod short-circuit disabled: could not read service account token",
			helpers.Error(err))
	} else {
		av.selfSubject = subject
		logger.L().Info("self-pod short-circuit enabled",
			helpers.String("selfSubject", subject))
	}

	return av
}

// SetSelfSubject overrides the operator's self subject. Exposed for tests.
func (av *AdmissionValidator) SetSelfSubject(subject string) {
	av.selfSubject = subject
}

// SetKindAcceptor installs the Kind pre-filter used to skip evaluation for
// admission events no loaded rule could match. Passing nil disables the
// pre-filter and accepts every Kind.
func (av *AdmissionValidator) SetKindAcceptor(a KindAcceptor) {
	av.kindAcceptor = a
}

// SetWorkerPool reconfigures the async evaluation pipeline. Must be called
// before Start. Exposed for tests; in production, defaults are used.
func (av *AdmissionValidator) SetWorkerPool(workers, queueSize int) {
	if av.started.Load() {
		return
	}
	if workers > 0 {
		av.workerCount = workers
	}
	if queueSize > 0 {
		av.jobs = make(chan evalJob, queueSize)
	}
}

// Start spawns the worker pool that drains the evaluation queue. Idempotent
// — subsequent calls are no-ops. Workers exit when ctx is canceled.
func (av *AdmissionValidator) Start(ctx context.Context) {
	if !av.started.CompareAndSwap(false, true) {
		return
	}
	registration, _ := telemetry.ObserveAdmission(func() int { return len(av.jobs) }, func() int { return cap(av.jobs) })
	if registration != nil {
		go func() { <-ctx.Done(); _ = registration.Unregister() }()
	}
	logger.L().Info("admission validator workers starting",
		helpers.Int("workers", av.workerCount),
		helpers.Int("queueSize", cap(av.jobs)))
	for i := 0; i < av.workerCount; i++ {
		av.wg.Add(1)
		go av.runWorker(ctx)
	}
}

// Wait blocks until all worker goroutines have exited. Exposed for tests and
// graceful shutdown.
func (av *AdmissionValidator) Wait() {
	av.wg.Wait()
}

// DropCount returns the cumulative number of admission events the validator
// has dropped because the evaluation queue was full. Suitable for export as
// a Prometheus counter.
func (av *AdmissionValidator) DropCount() int64 {
	return av.dropCount.Load()
}

func (av *AdmissionValidator) GetClientset() kubernetes.Interface {
	return av.objectCache.GetKubernetesCache().GetClientset()
}

// isSelfRequest reports whether the admission request originated from the
// operator's own ServiceAccount. Used to short-circuit feedback loops.
func (av *AdmissionValidator) isSelfRequest(attrs admission.Attributes) bool {
	if av.selfSubject == "" {
		return false
	}
	ui := attrs.GetUserInfo()
	if ui == nil {
		return false
	}
	return ui.GetName() == av.selfSubject
}

// Validate implements admission.ValidationInterface. The API server is
// synchronous from the framework's perspective, but our rule evaluation is
// not: matching requests are enqueued onto a bounded worker pool and the
// validator returns nil immediately. The API server never waits on CEL.
//
// Requests dropped here include:
//   - Requests from the operator's own ServiceAccount (feedback-loop guard).
//   - Requests whose Kind no loaded rule could match (Kind pre-filter).
//   - Requests that cannot be enqueued because the queue is full (drop with
//     warning + counter, never block the API server).
func (av *AdmissionValidator) Validate(ctx context.Context, attrs admission.Attributes, _ admission.ObjectInterfaces) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		telemetry.Admission(ctx, "dropped", 0)
		return err
	}
	if av.isSelfRequest(attrs) {
		telemetry.Admission(ctx, "self", 0)
		return nil
	}
	if av.kindAcceptor != nil && !av.kindAcceptor.Accepts(attrs.GetKind().Kind) {
		telemetry.Admission(ctx, "unmatched_kind", 0)
		return nil
	}
	// A DELETE carries the deleted object as the old object and no object.
	if attrs.GetObject() == nil && attrs.GetOldObject() == nil {
		telemetry.Admission(ctx, "empty", 0)
		return nil
	}

	// Detach from the incoming HTTP request context cancellation so that
	// workers are not canceled when handleWebhookValidate returns and the HTTP
	// connection completes. Retain request-scoped values and propagate any
	// client/request deadline.
	jobCtx := context.WithoutCancel(ctx)
	var cancel context.CancelFunc
	if deadline, ok := ctx.Deadline(); ok {
		jobCtx, cancel = context.WithDeadline(jobCtx, deadline)
	} else {
		jobCtx, cancel = context.WithCancel(jobCtx)
	}

	select {
	case av.jobs <- evalJob{ctx: jobCtx, cancel: cancel, attrs: attrs}:
		telemetry.Admission(ctx, "queued", 0)
	default:
		if cancel != nil {
			cancel()
		}
		telemetry.Admission(ctx, "dropped", 0)
		n := av.dropCount.Add(1)
		if n == 1 || n%dropLogInterval == 0 {
			logger.L().Warning("admission queue full, dropping event",
				helpers.String("kind", attrs.GetKind().Kind),
				helpers.String("namespace", attrs.GetNamespace()),
				helpers.String("name", attrs.GetName()),
				helpers.Int("totalDropped", int(n)))
		}
	}

	return nil
}

// runWorker drains the evaluation queue. While ctx is live the worker blocks
// on av.jobs. Once ctx is canceled the worker switches to a non-blocking
// drain pass so jobs enqueued just before cancellation are still processed,
// then exits. Drain uses a fresh context with a bounded timeout — the worker
// ctx is already canceled and would short-circuit downstream API calls.
func (av *AdmissionValidator) runWorker(ctx context.Context) {
	defer av.wg.Done()
	for {
		select {
		case <-ctx.Done():
			av.drainJobs()
			return
		case job := <-av.jobs:
			if ctx.Err() != nil {
				av.drainWithJob(job)
				return
			}
			av.processJob(ctx, job)
		}
	}
}

// drainJobs processes every job currently in the queue, then returns. Multiple
// workers may call this concurrently; the channel reads are safe and they
// race to empty the queue cooperatively.
func (av *AdmissionValidator) drainJobs() {
	av.drainJobsStartingWith(nil)
}

func (av *AdmissionValidator) drainWithJob(firstJob evalJob) {
	av.drainJobsStartingWith(&firstJob)
}

func (av *AdmissionValidator) drainJobsStartingWith(firstJob *evalJob) {
	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	defer cancel()

	if firstJob != nil {
		av.processJob(drainCtx, *firstJob)
	}

	for {
		select {
		case <-drainCtx.Done():
			remaining := len(av.jobs)
			if remaining > 0 {
				logger.L().Warning("admission validator drain timed out; abandoning queued jobs",
					helpers.Int("remaining", remaining))
				for {
					select {
					case job := <-av.jobs:
						if job.cancel != nil {
							job.cancel()
						}
					default:
						return
					}
				}
			}
			return
		case job := <-av.jobs:
			av.processJob(drainCtx, job)
		default:
			return
		}
	}
}

// processJob evaluates an enqueued job under the combined lifecycle context
// and the job's detached request context. If the job's deadline has already
// expired or if the job context was canceled while queued, evaluation is skipped.
func (av *AdmissionValidator) processJob(lifecycleCtx context.Context, job evalJob) {
	if job.cancel != nil {
		defer job.cancel()
	}

	reqCtx := job.ctx
	if reqCtx == nil {
		reqCtx = context.Background()
	}

	// Skip evaluation if the request-scoped deadline expired while queued.
	if err := reqCtx.Err(); err != nil {
		logger.L().Debug("admission worker: skipping job with canceled or expired context",
			helpers.String("kind", job.attrs.GetKind().Kind),
			helpers.String("name", job.attrs.GetName()),
			helpers.Error(err))
		telemetry.Admission(reqCtx, "error", 0)
		return
	}

	if err := lifecycleCtx.Err(); err != nil {
		return
	}

	evalCtx, cancelEval := linkContexts(lifecycleCtx, reqCtx)
	defer cancelEval()

	av.evaluate(evalCtx, job.attrs)
}

// linkContexts returns a context derived from reqCtx that is also canceled
// when lifecycleCtx is canceled.
func linkContexts(lifecycleCtx, reqCtx context.Context) (context.Context, context.CancelFunc) {
	if lifecycleCtx == nil {
		lifecycleCtx = context.Background()
	}
	if reqCtx == nil {
		reqCtx = context.Background()
	}

	ctx, cancel := context.WithCancel(reqCtx)
	stop := context.AfterFunc(lifecycleCtx, func() {
		cancel()
	})

	return ctx, func() {
		stop()
		cancel()
	}
}

// evaluate runs the full match + alert pipeline for a single admission event.
// Errors are logged and swallowed — alert export is best-effort.
func (av *AdmissionValidator) evaluate(ctx context.Context, attrs admission.Attributes) {
	if err := ctx.Err(); err != nil {
		return
	}
	start := time.Now()
	outcome := "error"
	defer func() { telemetry.Admission(ctx, outcome, time.Since(start)) }()
	var (
		object *unstructured.Unstructured
		err    error
	)
	if attrs.GetResource().Resource == "pods" && attrs.GetKind().Kind != "Pod" {
		object, err = av.fetchResource(ctx, attrs)
		if err != nil {
			logger.L().Warning("admission worker: failed to fetch resource",
				helpers.String("kind", attrs.GetKind().Kind),
				helpers.String("name", attrs.GetName()),
				helpers.Error(err))
			return
		}
	} else {
		admitted := attrs.GetObject()
		if admitted == nil {
			// DELETE: the rules apply to the object being deleted.
			admitted = attrs.GetOldObject()
		}
		un, ok := admitted.(*unstructured.Unstructured)
		if !ok {
			uMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(admitted)
			if err != nil {
				logger.L().Warning("admission worker: object cannot be converted to unstructured",
					helpers.String("kind", attrs.GetKind().Kind),
					helpers.Error(err))
				return
			}
			un = &unstructured.Unstructured{Object: uMap}
		}
		object = un
	}

	if err := ctx.Err(); err != nil {
		return
	}

	outcome = "evaluated"
	matchedRules := av.ruleBindingCache.ListRulesForObject(ctx, object)
	for _, rule := range matchedRules {
		if err := ctx.Err(); err != nil {
			return
		}
		failure := rule.ProcessEvent(attrs, av)
		if failure == nil {
			continue
		}
		logger.L().Info("Rule matched",
			helpers.String("ruleID", failure.GetRuleId()),
			helpers.Interface("failure", failure))
		av.exporter.SendAdmissionAlert(failure)
	}
}

// Fetch resource/objects from the Kubernetes API based on the given attributes.
func (av *AdmissionValidator) fetchResource(ctx context.Context, attrs admission.Attributes) (*unstructured.Unstructured, error) {
	// Get the GVR
	gvr := schema.GroupVersionResource{
		Group:    attrs.GetResource().Group,
		Version:  attrs.GetResource().Version,
		Resource: attrs.GetResource().Resource,
	}

	// Fetch the resource
	resource, err := av.kubernetesClient.DynamicClient.Resource(gvr).Namespace(attrs.GetNamespace()).Get(ctx, attrs.GetName(), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resource: %w", err)
	}

	return resource, nil
}

// We are implementing the Handles method from the ValidationInterface interface.
// This method returns true if this admission controller can handle the given operation, we accept all operations.
func (av *AdmissionValidator) Handles(operation admission.Operation) bool {
	return true
}
