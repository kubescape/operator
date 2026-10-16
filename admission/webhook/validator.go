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
type evalJob struct {
	attrs admission.Attributes
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
	if av.isSelfRequest(attrs) {
		telemetry.Admission(ctx, "self", 0)
		return nil
	}
	if av.kindAcceptor != nil && !av.kindAcceptor.Accepts(attrs.GetKind().Kind) {
		telemetry.Admission(ctx, "unmatched_kind", 0)
		return nil
	}
	if attrs.GetObject() == nil {
		telemetry.Admission(ctx, "empty", 0)
		return nil
	}

	select {
	case av.jobs <- evalJob{attrs: attrs}:
		telemetry.Admission(ctx, "queued", 0)
	default:
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
			av.evaluate(ctx, job.attrs)
		}
	}
}

// drainJobs processes every job currently in the queue, then returns. Multiple
// workers may call this concurrently; the channel reads are safe and they
// race to empty the queue cooperatively.
func (av *AdmissionValidator) drainJobs() {
	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	defer cancel()
	for {
		select {
		case <-drainCtx.Done():
			remaining := len(av.jobs)
			if remaining > 0 {
				logger.L().Warning("admission validator drain timed out; abandoning queued jobs",
					helpers.Int("remaining", remaining))
			}
			return
		case job := <-av.jobs:
			av.evaluate(drainCtx, job.attrs)
		default:
			return
		}
	}
}

// evaluate runs the full match + alert pipeline for a single admission event.
// Errors are logged and swallowed — alert export is best-effort.
func (av *AdmissionValidator) evaluate(ctx context.Context, attrs admission.Attributes) {
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
		un, ok := attrs.GetObject().(*unstructured.Unstructured)
		if !ok {
			logger.L().Warning("admission worker: object is not unstructured",
				helpers.String("kind", attrs.GetKind().Kind))
			return
		}
		object = un
	}

	outcome = "evaluated"
	matchedRules := av.ruleBindingCache.ListRulesForObject(ctx, object)
	for _, rule := range matchedRules {
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
