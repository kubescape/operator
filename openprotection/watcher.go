// Package openprotection keeps the storage apiserver's collapse-protection in
// sync with the cluster's active runtime rules.
//
// The operator watches RuntimeRuleAlertBinding objects, resolves the rules they
// activate against the versioned rule library (armosec/rulelibrary), computes the
// union of those rules' profileDataRequired.opens (armotypes.OpenMatchers), and
// publishes it as a single ConfigMap. The storage apiserver polls that ConfigMap
// and pins the matched sensitive prefixes to literal during profile collapse, so
// anomaly rules such as R0010 ("unexpected /etc/shadow access") keep working.
//
// This is the producer side of the "operator writes one object, storage refreshes
// periodically" design; the reader lives in kubescape/storage.
package openprotection

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	rulelib "github.com/armosec/rulelibrary/pkg/rules"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	nodeagentutils "github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// DefaultDebounce coalesces bursts of binding events (e.g. the initial LIST that
// fires one Add per existing binding) into a single reconcile.
const DefaultDebounce = 2 * time.Second

var _ watcher.Adaptor = (*Watcher)(nil)

// Watcher is a watcher.Adaptor over RuntimeRuleAlertBinding. It maintains the set
// of rule selectors contributed by every binding and, on change, reconciles the
// published open-protection union (debounced).
type Watcher struct {
	publisher Publisher
	debounce  time.Duration

	mu       sync.Mutex
	bindings map[string]rulelib.RuleSelector // binding uniqueName -> its selectors

	dirty chan struct{}

	// lastApplied is the last payload we published; reconcile skips the publish
	// when the recomputed payload is unchanged.
	lastApplied string
	haveApplied bool
}

func NewWatcher(publisher Publisher, debounce time.Duration) *Watcher {
	if debounce <= 0 {
		debounce = DefaultDebounce
	}
	return &Watcher{
		publisher: publisher,
		debounce:  debounce,
		bindings:  map[string]rulelib.RuleSelector{},
		dirty:     make(chan struct{}, 1),
	}
}

// ----------------- watcher.WatchResources -----------------

func (w *Watcher) WatchResources() []watcher.WatchResource {
	return []watcher.WatchResource{
		watcher.NewWatchResource(typesv1.RuleBindingAlertGvr, metav1.ListOptions{}),
	}
}

// ----------------- watcher.Watcher (event handlers) -----------------

func (w *Watcher) AddHandler(_ context.Context, obj runtime.Object) { w.upsert(obj) }

func (w *Watcher) ModifyHandler(_ context.Context, obj runtime.Object) { w.upsert(obj) }

func (w *Watcher) DeleteHandler(_ context.Context, obj runtime.Object) {
	un, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	key := nodeagentutils.CreateK8sPodID(un.GetNamespace(), un.GetName())
	w.mu.Lock()
	_, existed := w.bindings[key]
	delete(w.bindings, key)
	w.mu.Unlock()
	if existed {
		w.markDirty()
	}
}

func (w *Watcher) upsert(obj runtime.Object) {
	un, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	rb := &typesv1.RuntimeAlertRuleBinding{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, rb); err != nil {
		logger.L().Error("openprotection: failed to convert rule binding", helpers.Error(err))
		return
	}
	key := nodeagentutils.CreateK8sPodID(rb.GetNamespace(), rb.GetName())
	sel := bindingSelector(rb)
	w.mu.Lock()
	w.bindings[key] = sel
	w.mu.Unlock()
	w.markDirty()
}

// bindingSelector extracts the (ids, names, tags) a binding activates. A binding
// rule references a library rule by id, name, or tags; we collect all of them so
// the union below resolves exactly the rules this binding turns on.
func bindingSelector(rb *typesv1.RuntimeAlertRuleBinding) rulelib.RuleSelector {
	var sel rulelib.RuleSelector
	for _, r := range rb.Spec.Rules {
		if r.RuleID != "" {
			sel.IDs = append(sel.IDs, r.RuleID)
		}
		if r.RuleName != "" {
			sel.Names = append(sel.Names, r.RuleName)
		}
		sel.Tags = append(sel.Tags, r.RuleTags...)
	}
	return sel
}

// ----------------- reconcile loop -----------------

func (w *Watcher) markDirty() {
	select {
	case w.dirty <- struct{}{}:
	default: // already pending — coalesce
	}
}

// Run drives the debounced reconcile loop until ctx is cancelled. It performs an
// initial reconcile after the first debounce window so an empty cluster (no
// bindings) deterministically publishes an empty union, then reconciles whenever
// bindings change.
func (w *Watcher) Run(ctx context.Context) {
	timer := time.NewTimer(w.debounce)
	defer timer.Stop()
	pending := true // schedule an initial reconcile even with no events
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.dirty:
			if !pending {
				pending = true
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(w.debounce)
			}
		case <-timer.C:
			if pending {
				pending = false
				w.reconcile(ctx)
			}
			timer.Reset(w.debounce)
		}
	}
}

// reconcile recomputes the union across all bindings and publishes it if changed.
func (w *Watcher) reconcile(ctx context.Context) {
	w.mu.Lock()
	merged := mergeSelectors(w.bindings)
	w.mu.Unlock()

	m, err := rulelib.OpenProtectionForSelectors(merged)
	if err != nil {
		logger.L().Ctx(ctx).Error("openprotection: failed to resolve open protection", helpers.Error(err))
		return
	}
	payload, err := marshalCanonical(m)
	if err != nil {
		logger.L().Ctx(ctx).Error("openprotection: failed to marshal open matchers", helpers.Error(err))
		return
	}

	w.mu.Lock()
	unchanged := w.haveApplied && w.lastApplied == payload
	w.mu.Unlock()
	if unchanged {
		return
	}

	if err := w.publisher.Publish(ctx, payload); err != nil {
		logger.L().Ctx(ctx).Error("openprotection: failed to publish configmap", helpers.Error(err))
		return
	}
	w.mu.Lock()
	w.lastApplied = payload
	w.haveApplied = true
	w.mu.Unlock()
	logger.L().Info("openprotection: published open-protection union", helpers.Int("bytes", len(payload)))
}

// mergeSelectors flattens every binding's selectors into one selector; the
// library unions across all rules any binding activates.
func mergeSelectors(bindings map[string]rulelib.RuleSelector) rulelib.RuleSelector {
	var out rulelib.RuleSelector
	for _, s := range bindings {
		out.IDs = append(out.IDs, s.IDs...)
		out.Names = append(out.Names, s.Names...)
		out.Tags = append(out.Tags, s.Tags...)
	}
	return out
}

// marshalCanonical produces a stable JSON encoding (sorted, de-duplicated slices)
// so an unchanged active-rule set always yields byte-identical output — that is
// what lets reconcile and the publisher skip no-op writes.
func marshalCanonical(m armotypes.OpenMatchers) (string, error) {
	m.Exact = sortedUnique(m.Exact)
	m.Prefix = sortedUnique(m.Prefix)
	m.Suffix = sortedUnique(m.Suffix)
	m.Contains = sortedUnique(m.Contains)
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
