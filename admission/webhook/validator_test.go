package webhook

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/operator/admission/rulebinding"
	"github.com/kubescape/operator/admission/rules"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// countingRuleBindingCache records how many times ListRulesForObject is called.
// Used by worker-pool tests to confirm enqueued jobs eventually reach evaluation.
type countingRuleBindingCache struct {
	calls atomic.Int64
}

func (c *countingRuleBindingCache) ListRulesForObject(_ context.Context, _ *unstructured.Unstructured) []rules.RuleEvaluator {
	c.calls.Add(1)
	return nil
}

// newTestValidator builds an AdmissionValidator with a small jobs channel so
// queue-depth assertions are easy to make. Workers are not started — pre-filter
// tests inspect the channel directly.
func newTestValidator(cache rulebinding.RuleBindingCache) *AdmissionValidator {
	return &AdmissionValidator{
		ruleBindingCache: cache,
		jobs:             make(chan evalJob, 8),
		workerCount:      1,
	}
}

func newSelfTestAttributes(username string) admission.Attributes {
	// Use NetworkPolicy CREATE — this avoids the special pods/exec fetchResource
	// branch in evaluate which would require a mocked dynamic client.
	gvk := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
	}}
	userInfo := &user.DefaultInfo{Name: username}
	return admission.NewAttributesRecord(obj, nil, gvk, "default", "test-netpol", gvr, "",
		admission.Create, nil, false, userInfo)
}

func TestValidator_SelfPodShortCircuit(t *testing.T) {
	const selfSubject = "system:serviceaccount:kubescape:operator"

	tests := []struct {
		name            string
		configuredSubj  string
		requestUsername string
		wantEnqueued    bool
	}{
		{
			name:            "request from operator SA is short-circuited",
			configuredSubj:  selfSubject,
			requestUsername: selfSubject,
			wantEnqueued:    false,
		},
		{
			name:            "request from kubernetes-admin enqueues",
			configuredSubj:  selfSubject,
			requestUsername: "kubernetes-admin",
			wantEnqueued:    true,
		},
		{
			name:            "request from a different SA enqueues",
			configuredSubj:  selfSubject,
			requestUsername: "system:serviceaccount:default:builder",
			wantEnqueued:    true,
		},
		{
			name:            "empty self subject disables the short-circuit",
			configuredSubj:  "",
			requestUsername: selfSubject,
			wantEnqueued:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			av := newTestValidator(&countingRuleBindingCache{})
			av.SetSelfSubject(tt.configuredSubj)

			attrs := newSelfTestAttributes(tt.requestUsername)
			if err := av.Validate(context.Background(), attrs, nil); err != nil {
				t.Fatalf("Validate returned error: %v", err)
			}

			gotEnqueued := len(av.jobs) == 1
			if gotEnqueued != tt.wantEnqueued {
				t.Errorf("enqueued=%v, want %v (queue len=%d)",
					gotEnqueued, tt.wantEnqueued, len(av.jobs))
			}
		})
	}
}

// stubKindAcceptor accepts only the kinds in the set.
type stubKindAcceptor struct {
	accepted map[string]struct{}
}

func (s stubKindAcceptor) Accepts(kind string) bool {
	_, ok := s.accepted[kind]
	return ok
}

func TestValidator_KindAcceptorPreFilter(t *testing.T) {
	tests := []struct {
		name         string
		acceptor     KindAcceptor
		wantEnqueued bool
	}{
		{
			name:         "nil acceptor — every Kind enqueues",
			acceptor:     nil,
			wantEnqueued: true,
		},
		{
			name:         "acceptor includes NetworkPolicy — enqueues",
			acceptor:     stubKindAcceptor{accepted: map[string]struct{}{"NetworkPolicy": {}}},
			wantEnqueued: true,
		},
		{
			name:         "acceptor excludes NetworkPolicy — short-circuited",
			acceptor:     stubKindAcceptor{accepted: map[string]struct{}{"Pod": {}}},
			wantEnqueued: false,
		},
		{
			name:         "empty acceptor — short-circuited",
			acceptor:     stubKindAcceptor{accepted: map[string]struct{}{}},
			wantEnqueued: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			av := newTestValidator(&countingRuleBindingCache{})
			av.SetKindAcceptor(tt.acceptor)

			attrs := newSelfTestAttributes("kubernetes-admin")
			if err := av.Validate(context.Background(), attrs, nil); err != nil {
				t.Fatalf("Validate returned error: %v", err)
			}

			gotEnqueued := len(av.jobs) == 1
			if gotEnqueued != tt.wantEnqueued {
				t.Errorf("enqueued=%v, want %v", gotEnqueued, tt.wantEnqueued)
			}
		})
	}
}

func TestValidator_SelfPodShortCircuit_NilUserInfo(t *testing.T) {
	av := newTestValidator(&countingRuleBindingCache{})
	av.SetSelfSubject("system:serviceaccount:kubescape:operator")

	gvk := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
	}}
	// Pass nil userInfo — should not short-circuit, should enqueue.
	attrs := admission.NewAttributesRecord(obj, nil, gvk, "default", "test-netpol", gvr, "",
		admission.Create, nil, false, nil)

	if err := av.Validate(context.Background(), attrs, nil); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if len(av.jobs) != 1 {
		t.Errorf("request with nil UserInfo was short-circuited; expected to enqueue (queue len=%d)", len(av.jobs))
	}
}

// signalingRuleBindingCache notifies a channel each time ListRulesForObject is
// called. Lets worker-pool tests block until evaluation has actually happened.
type signalingRuleBindingCache struct {
	calls atomic.Int64
	done  chan struct{}
}

func (c *signalingRuleBindingCache) ListRulesForObject(_ context.Context, _ *unstructured.Unstructured) []rules.RuleEvaluator {
	c.calls.Add(1)
	select {
	case c.done <- struct{}{}:
	default:
	}
	return nil
}

func TestValidator_WorkerPool_ProcessesEnqueuedJobs(t *testing.T) {
	cache := &signalingRuleBindingCache{done: make(chan struct{}, 4)}
	av := newTestValidator(cache)
	av.SetWorkerPool(2, 16)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	av.Start(ctx)

	for i := 0; i < 3; i++ {
		if err := av.Validate(ctx, newSelfTestAttributes("kubernetes-admin"), nil); err != nil {
			t.Fatalf("Validate returned error: %v", err)
		}
	}

	deadline := time.After(2 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case <-cache.done:
		case <-deadline:
			t.Fatalf("timed out waiting for evaluation %d; cache calls=%d", i+1, cache.calls.Load())
		}
	}

	if got := cache.calls.Load(); got != 3 {
		t.Errorf("cache calls = %d, want 3", got)
	}
	if got := av.DropCount(); got != 0 {
		t.Errorf("DropCount = %d, want 0", got)
	}
}

// blockingRuleBindingCache holds workers inside ListRulesForObject until release.
// Used to force the queue into a "full" state.
type blockingRuleBindingCache struct {
	release chan struct{}
	entered chan struct{}
	count   atomic.Int64
}

func (c *blockingRuleBindingCache) ListRulesForObject(_ context.Context, _ *unstructured.Unstructured) []rules.RuleEvaluator {
	c.count.Add(1)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	<-c.release
	return nil
}

func TestValidator_WorkerPool_DropsWhenQueueFull(t *testing.T) {
	cache := &blockingRuleBindingCache{
		release: make(chan struct{}),
		entered: make(chan struct{}, 1),
	}
	defer close(cache.release)

	const workers = 1
	const queueSize = 2

	av := newTestValidator(cache)
	av.SetWorkerPool(workers, queueSize)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	av.Start(ctx)

	// Step 1: submit one job, wait until the worker has entered the cache
	// call. After this barrier the worker is parked and the channel is empty,
	// so subsequent submissions either fill the channel or drop.
	if err := av.Validate(ctx, newSelfTestAttributes("kubernetes-admin"), nil); err != nil {
		t.Fatalf("Validate returned error on first submission: %v", err)
	}
	select {
	case <-cache.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never entered the blocking cache call")
	}

	// Step 2: submit queueSize jobs to fill the channel.
	for i := 0; i < queueSize; i++ {
		if err := av.Validate(ctx, newSelfTestAttributes("kubernetes-admin"), nil); err != nil {
			t.Fatalf("Validate returned error on queue-fill submission %d: %v", i, err)
		}
	}
	if got := av.DropCount(); got != 0 {
		t.Fatalf("DropCount = %d after queue fill, want 0", got)
	}

	// Step 3: submit additional jobs — every one must drop.
	const expectedDrops = 5
	for i := 0; i < expectedDrops; i++ {
		if err := av.Validate(ctx, newSelfTestAttributes("kubernetes-admin"), nil); err != nil {
			t.Fatalf("Validate returned error on drop submission %d: %v", i, err)
		}
	}

	if got := av.DropCount(); got != expectedDrops {
		t.Errorf("DropCount = %d, want %d", got, expectedDrops)
	}
}

// TestValidator_WorkerPool_DrainsQueuedJobsOnShutdown verifies that jobs
// enqueued before context cancellation are processed by the drain path on
// worker exit rather than abandoned.
func TestValidator_WorkerPool_DrainsQueuedJobsOnShutdown(t *testing.T) {
	cache := &blockingRuleBindingCache{
		release: make(chan struct{}),
		entered: make(chan struct{}, 1),
	}

	const workers = 1
	const queueSize = 4

	av := newTestValidator(cache)
	av.SetWorkerPool(workers, queueSize)

	ctx, cancel := context.WithCancel(context.Background())
	av.Start(ctx)

	// Step 1: submit one job and wait until the worker has actually entered
	// the blocked cache call. After this barrier the channel is empty and
	// the worker is parked.
	if err := av.Validate(ctx, newSelfTestAttributes("kubernetes-admin"), nil); err != nil {
		t.Fatalf("Validate returned error on first submission: %v", err)
	}
	select {
	case <-cache.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never entered the blocking cache call")
	}

	// Step 2: fill the queue with queueSize additional jobs — these must
	// survive the cancel-and-drain handoff.
	for i := 0; i < queueSize; i++ {
		if err := av.Validate(ctx, newSelfTestAttributes("kubernetes-admin"), nil); err != nil {
			t.Fatalf("Validate returned error on queue-fill submission %d: %v", i, err)
		}
	}
	if got := av.DropCount(); got != 0 {
		t.Fatalf("DropCount = %d after queue fill, want 0", got)
	}
	const total = 1 + queueSize

	// Cancel mid-flight. The worker, currently parked in the cache, won't
	// see the cancel until ListRulesForObject returns. Release the cache so
	// the worker continues; it must then enter the drain path and process
	// every queued job before exiting.
	cancel()
	close(cache.release)

	done := make(chan struct{})
	go func() {
		av.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not exit after cancel + drain")
	}

	if got := cache.count.Load(); got != int64(total) {
		t.Errorf("evaluated %d jobs, want %d (queued jobs were not drained)", got, total)
	}
	if got := av.DropCount(); got != 0 {
		t.Errorf("DropCount = %d during drain test, want 0", got)
	}
}

func TestValidator_WorkerPool_StopsOnContextCancel(t *testing.T) {
	av := newTestValidator(&countingRuleBindingCache{})
	av.SetWorkerPool(3, 4)

	ctx, cancel := context.WithCancel(context.Background())
	av.Start(ctx)

	cancel()

	done := make(chan struct{})
	go func() {
		av.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("workers did not exit after context cancel")
	}
}

func TestValidator_NilObjectIsDropped(t *testing.T) {
	av := newTestValidator(&countingRuleBindingCache{})

	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	// nil object — Validate should drop it without enqueuing.
	attrs := admission.NewAttributesRecord(nil, nil, gvk, "default", "p", gvr, "",
		admission.Create, nil, false, nil)

	if err := av.Validate(context.Background(), attrs, nil); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if len(av.jobs) != 0 {
		t.Errorf("expected nil-object request to be dropped; queue len=%d", len(av.jobs))
	}
}

func TestValidator_TypedObjectIsConvertedToUnstructured(t *testing.T) {
	cache := &recordingRuleBindingCache{objects: make(chan *unstructured.Unstructured, 1)}
	av := newTestValidator(cache)
	av.SetWorkerPool(1, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	av.Start(ctx)

	gvk := schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	typed := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
	}
	attrs := admission.NewAttributesRecord(typed, nil, gvk, "default", "web", gvr, "",
		admission.Create, nil, false, &user.DefaultInfo{Name: "kubernetes-admin"})

	if err := av.Validate(ctx, attrs, nil); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	select {
	case object := <-cache.objects:
		if object.GetName() != "web" {
			t.Errorf("got object name %q, want 'web'", object.GetName())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("typed object evaluation timed out; was likely dropped")
	}
}
