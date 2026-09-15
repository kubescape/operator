package cache

import (
	"context"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/operator/admission/rules"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewCacheMock() *RBCache {
	return &RBCache{
		k8sClient:          k8sinterface.NewKubernetesApiMock(),
		ruleCreator:        &rules.RuleCreatorMock{},
		ignoreRuleBindings: false,
	}
}

func TestNewCache(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Initialize NewCache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sAPI := utils.NewK8sInterfaceFake(nil)
			cache := NewCache(k8sAPI, &rules.RuleCreatorMock{}, false)

			assert.NotNil(t, cache)
			assert.Equal(t, k8sAPI, cache.k8sClient)
			assert.NotNil(t, cache.ruleCreator)
			assert.NotNil(t, cache.watchResources)
		})
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	for _, newCache := range []struct {
		name string
		new  func() *RBCache
	}{
		{name: "constructor", new: func() *RBCache {
			return NewCache(nil, &rules.RuleCreatorMock{}, false)
		}},
		{name: "partial literal", new: func() *RBCache {
			return &RBCache{ruleCreator: &rules.RuleCreatorMock{}}
		}},
	} {
		t.Run(newCache.name, func(t *testing.T) {
			c := newCache.new()
			binding := &typesv1.RuntimeAlertRuleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "test"},
				Spec: typesv1.RuntimeAlertRuleBindingSpec{
					Rules: []typesv1.RuntimeAlertRuleBindingRule{{RuleID: "R2000"}},
				},
			}
			object := &unstructured.Unstructured{}
			object.SetNamespace("test")
			ctx := t.Context()
			start := make(chan struct{})
			var wg sync.WaitGroup
			for _, operation := range []func(){
				func() { c.addRuleBinding(binding) },
				func() { c.deleteRuleBinding(uniqueName(binding)) },
				func() { c.ListRulesForObject(ctx, object) },
				c.RefreshRules,
			} {
				wg.Go(func() {
					<-start
					for range 64 {
						operation()
					}
				})
			}
			close(start)
			wg.Wait()

			// Assert final behavior after the concurrent operations have finished.
			c.addRuleBinding(binding)
			beforeRefresh := c.ListRulesForObject(ctx, object)
			if !assert.Len(t, beforeRefresh, 1) {
				return
			}
			assert.Equal(t, "R2000", beforeRefresh[0].ID())
			c.RefreshRules()
			afterRefresh := c.ListRulesForObject(ctx, object)
			if assert.Len(t, afterRefresh, 1) {
				assert.Equal(t, "R2000", afterRefresh[0].ID())
				assert.NotSame(t, beforeRefresh[0], afterRefresh[0], "refresh should recreate the rule")
			}
			c.deleteRuleBinding(uniqueName(binding))
			assert.Empty(t, c.ListRulesForObject(ctx, object))
		})
	}
}

func TestRuntimeObjAddHandler(t *testing.T) {
	type rules struct {
		ruleID string
	}
	type args struct {
		c   *RBCache
		pod *unstructured.Unstructured
		rb  []typesv1.RuntimeAlertRuleBinding
	}
	tests := []struct {
		name          string
		args          args
		expectedRules []rules
	}{
		{
			name: "Add a pod to the cache",
			args: args{
				c: NewCacheMock(),
				pod: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"metadata": map[string]interface{}{
							"name":      "testPod",
							"namespace": "testNamespace",
							"labels": map[string]interface{}{
								"app": "testPod",
							},
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod",
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R2000",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleID: "R2000",
				},
			},
		},
		{
			name: "Pod with MatchExpressions",
			args: args{
				c: NewCacheMock(),
				pod: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"metadata": map[string]interface{}{
							"name":      "testPod",
							"namespace": "testNamespace",
							"labels": map[string]interface{}{
								"app": "testPod",
							},
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"testPod"},
									},
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R2000",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{
				{
					ruleID: "R2000",
				},
			},
		},
		{
			name: "Pod with mismatch labels",
			args: args{
				c: NewCacheMock(),
				pod: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"metadata": map[string]interface{}{
							"name":      "testPod",
							"namespace": "testNamespace",
							"labels": map[string]interface{}{
								"app": "testPod",
							},
						},
					},
				},
				rb: []typesv1.RuntimeAlertRuleBinding{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testRB",
							Namespace: "testNamespace",
						},
						Spec: typesv1.RuntimeAlertRuleBindingSpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "testPod1",
								},
							},
							Rules: []typesv1.RuntimeAlertRuleBindingRule{
								{
									RuleID: "R2000",
								},
							},
						},
					},
				},
			},
			expectedRules: []rules{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.args.rb {
				tt.args.c.addRuleBinding(&tt.args.rb[i])
			}
			tt.args.c.AddHandler(context.Background(), tt.args.pod)
			r := tt.args.c.ListRulesForObject(context.Background(), tt.args.pod)
			assert.Equal(t, len(tt.expectedRules), len(r))
			for i := range r {
				assert.Equal(t, tt.expectedRules[i].ruleID, r[i].ID())

			}
		})

	}
}

// TestHandlersIgnoreNonRuleBindingKinds verifies that AddHandler, ModifyHandler,
// and DeleteHandler silently drop events whose Kind is not RuntimeRuleAlertBinding.
// The dynamic watcher dispatches every event to every adaptor, so without this
// filter the RBCache would attempt to parse Rules CRD payloads as bindings and
// emit spurious "cannot convert int64 to string" errors.
func TestHandlersIgnoreNonRuleBindingKinds(t *testing.T) {
	rulesEvent := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubescape.io/v1",
			"kind":       "Rules",
			"metadata": map[string]interface{}{
				"name":      "admission-test-rules",
				"namespace": "kubescape",
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"id":       "R2000",
						"severity": int64(8), // would fail conversion to string
					},
				},
			},
		},
	}

	t.Run("AddHandler ignores Rules CRD", func(t *testing.T) {
		c := NewCacheMock()
		c.AddHandler(context.Background(), rulesEvent)
		assert.Len(t, c.rbNameToRB, 0, "no rule binding should be stored")
	})

	t.Run("ModifyHandler ignores Rules CRD", func(t *testing.T) {
		c := NewCacheMock()
		c.ModifyHandler(context.Background(), rulesEvent)
		assert.Len(t, c.rbNameToRB, 0)
	})

	t.Run("DeleteHandler ignores Rules CRD", func(t *testing.T) {
		c := NewCacheMock()
		// Seed a binding so we can detect spurious deletes.
		c.rbNameToRB = map[string]typesv1.RuntimeAlertRuleBinding{"kubescape/admission-test-rules": {}}
		c.DeleteHandler(context.Background(), rulesEvent)
		assert.Len(t, c.rbNameToRB, 1, "the seeded binding must not be deleted by a Rules CRD event")
	})
}

func TestListRulesForObjectIgnoreBindings(t *testing.T) {
	c := &RBCache{
		k8sClient:          k8sinterface.NewKubernetesApiMock(),
		ruleCreator:        &rules.RuleCreatorMock{},
		ignoreRuleBindings: true,
	}

	t.Run("namespaced object returns all rules", func(t *testing.T) {
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name":      "any",
					"namespace": "ns",
				},
			},
		}

		ruleEvaluators := c.ListRulesForObject(context.Background(), obj)
		assert.Len(t, ruleEvaluators, 2)
		assert.Equal(t, "rule-1", ruleEvaluators[0].ID())
		assert.Equal(t, "rule-2", ruleEvaluators[1].ID())
	})

	t.Run("cluster object respects includeClusterObjects=false", func(t *testing.T) {
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "cluster-obj",
					"labels": map[string]interface{}{
						"includeClusterObjects": "false",
					},
				},
			},
		}

		ruleEvaluators := c.ListRulesForObject(context.Background(), obj)
		assert.Len(t, ruleEvaluators, 0)
	})
}

func TestCreateRule(t *testing.T) {
	c := NewCacheMock()
	tests := []struct {
		name     string
		rule     *typesv1.RuntimeAlertRuleBindingRule
		expected []rules.RuleEvaluator
	}{
		{
			name: "Test with RuleID",
			rule: &typesv1.RuntimeAlertRuleBindingRule{
				RuleID:     "rule-1",
				Parameters: map[string]interface{}{"param1": "value1"},
			},
			expected: []rules.RuleEvaluator{&rules.RuleMock{RuleID: "rule-1", RuleParameters: map[string]interface{}{"param1": "value1"}}},
		},
		{
			name: "Test with RuleName",
			rule: &typesv1.RuntimeAlertRuleBindingRule{
				RuleName:   "rule-1",
				Parameters: map[string]interface{}{"param1": "value1"},
			},
			expected: []rules.RuleEvaluator{&rules.RuleMock{RuleName: "rule-1", RuleParameters: map[string]interface{}{"param1": "value1"}}},
		},
		{
			name: "Test with RuleTags",
			rule: &typesv1.RuntimeAlertRuleBindingRule{
				RuleTags:   []string{"tag1", "tag2"},
				Parameters: map[string]interface{}{"param1": "value1"},
			},
			expected: []rules.RuleEvaluator{&rules.RuleMock{RuleName: "tag1", RuleParameters: map[string]interface{}{"param1": "value1"}}, &rules.RuleMock{RuleName: "tag2", RuleParameters: map[string]interface{}{"param1": "value1"}}},
		},
		{
			name:     "Test with no RuleID, RuleName, or RuleTags",
			rule:     &typesv1.RuntimeAlertRuleBindingRule{},
			expected: []rules.RuleEvaluator{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.createRule(tt.rule)
			assert.Equal(t, len(tt.expected), len(result))
			for i := range result {
				assert.Equal(t, tt.expected[i].Name(), result[i].Name())
				assert.Equal(t, tt.expected[i].ID(), result[i].ID())
				assert.Equal(t, tt.expected[i].GetParameters(), result[i].GetParameters())
			}
		})
	}
}
