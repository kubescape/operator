package openprotection

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	rulelib "github.com/armosec/rulelibrary/pkg/rules"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

type capturePublisher struct {
	payloads []string
}

func (c *capturePublisher) Publish(_ context.Context, payload string) error {
	c.payloads = append(c.payloads, payload)
	return nil
}

func (c *capturePublisher) last() string {
	if len(c.payloads) == 0 {
		return ""
	}
	return c.payloads[len(c.payloads)-1]
}

func bindingUnstructured(t *testing.T, namespace, name string, rules []typesv1.RuntimeAlertRuleBindingRule) *unstructured.Unstructured {
	t.Helper()
	rb := &typesv1.RuntimeAlertRuleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       typesv1.RuntimeAlertRuleBindingSpec{Rules: rules},
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(rb)
	if err != nil {
		t.Fatalf("to unstructured: %v", err)
	}
	return &unstructured.Unstructured{Object: m}
}

func TestBindingSelector(t *testing.T) {
	rb := &typesv1.RuntimeAlertRuleBinding{
		Spec: typesv1.RuntimeAlertRuleBindingSpec{
			Rules: []typesv1.RuntimeAlertRuleBindingRule{
				{RuleID: "R0010"},
				{RuleName: "Unexpected process"},
				{RuleTags: []string{"sensitive", "files"}},
			},
		},
	}
	sel := bindingSelector(rb)
	if len(sel.IDs) != 1 || sel.IDs[0] != "R0010" {
		t.Errorf("IDs = %v", sel.IDs)
	}
	if len(sel.Names) != 1 || sel.Names[0] != "Unexpected process" {
		t.Errorf("Names = %v", sel.Names)
	}
	if len(sel.Tags) != 2 {
		t.Errorf("Tags = %v", sel.Tags)
	}
}

func TestMarshalCanonicalIsStableAndDeduped(t *testing.T) {
	a, err := marshalCanonical(armotypes.OpenMatchers{Prefix: []string{"/b", "/a", "/a"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := marshalCanonical(armotypes.OpenMatchers{Prefix: []string{"/a", "/b"}})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("canonical output not stable: %q vs %q", a, b)
	}
	var got armotypes.OpenMatchers
	if err := json.Unmarshal([]byte(a), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Prefix) != 2 || got.Prefix[0] != "/a" || got.Prefix[1] != "/b" {
		t.Errorf("expected sorted-unique [/a /b], got %v", got.Prefix)
	}
}

// TestReconcilePublishesUnionForBoundRule drives the watcher end-to-end against
// the real embedded rule library: binding R0010 must publish a union that keeps
// /etc/shadow detectable.
func TestReconcilePublishesUnionForBoundRule(t *testing.T) {
	pub := &capturePublisher{}
	w := NewWatcher(pub, 0)

	w.AddHandler(context.Background(), bindingUnstructured(t, "kubescape", "binding-1",
		[]typesv1.RuntimeAlertRuleBindingRule{{RuleID: "R0010"}}))
	w.reconcile(context.Background())

	if len(pub.payloads) != 1 {
		t.Fatalf("expected one publish, got %d", len(pub.payloads))
	}
	var m armotypes.OpenMatchers
	if err := json.Unmarshal([]byte(pub.last()), &m); err != nil {
		t.Fatal(err)
	}
	if !containsStr(m.Prefix, "/etc/shadow") {
		t.Errorf("expected /etc/shadow in published prefix union, got %+v", m)
	}

	// Reconcile again with no change: must NOT publish again (idempotent).
	w.reconcile(context.Background())
	if len(pub.payloads) != 1 {
		t.Errorf("expected no second publish for unchanged set, got %d", len(pub.payloads))
	}
}

// TestReconcileEmptyWhenNoBindings: with no bindings, the published union is empty
// (no over-pinning).
func TestReconcileEmptyWhenNoBindings(t *testing.T) {
	pub := &capturePublisher{}
	w := NewWatcher(pub, 0)
	w.reconcile(context.Background())
	if len(pub.payloads) != 1 {
		t.Fatalf("expected one publish, got %d", len(pub.payloads))
	}
	var m armotypes.OpenMatchers
	if err := json.Unmarshal([]byte(pub.last()), &m); err != nil {
		t.Fatal(err)
	}
	if !m.Empty() {
		t.Errorf("expected empty union with no bindings, got %+v", m)
	}
}

// TestDeleteRemovesContribution: deleting the only binding that pinned a prefix
// drops it from the next union.
func TestDeleteRemovesContribution(t *testing.T) {
	pub := &capturePublisher{}
	w := NewWatcher(pub, 0)
	bind := bindingUnstructured(t, "kubescape", "binding-1",
		[]typesv1.RuntimeAlertRuleBindingRule{{RuleID: "R0010"}})

	w.AddHandler(context.Background(), bind)
	w.reconcile(context.Background())
	var withRule armotypes.OpenMatchers
	_ = json.Unmarshal([]byte(pub.last()), &withRule)
	if !containsStr(withRule.Prefix, "/etc/shadow") {
		t.Fatalf("precondition: expected /etc/shadow while bound, got %+v", withRule)
	}

	w.DeleteHandler(context.Background(), bind)
	w.reconcile(context.Background())
	var afterDelete armotypes.OpenMatchers
	_ = json.Unmarshal([]byte(pub.last()), &afterDelete)
	if containsStr(afterDelete.Prefix, "/etc/shadow") {
		t.Errorf("expected /etc/shadow removed after unbinding, got %+v", afterDelete)
	}
}

func TestMergeSelectors(t *testing.T) {
	merged := mergeSelectors(map[string]rulelib.RuleSelector{
		"a": {IDs: []string{"R0001"}, Tags: []string{"x"}},
		"b": {IDs: []string{"R0010"}, Names: []string{"n"}},
	})
	if len(merged.IDs) != 2 || len(merged.Names) != 1 || len(merged.Tags) != 1 {
		t.Errorf("unexpected merge: %+v", merged)
	}
}

func containsStr(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
