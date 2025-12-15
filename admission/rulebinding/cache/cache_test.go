package cache

import (
	"context"
	"testing"

	"github.com/goradd/maps"
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
		rbNameToRules:      maps.SafeMap[string, []rules.RuleEvaluator]{}, // rule binding name -> []created rules
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
			cache := NewCache(k8sAPI, false)

			assert.NotNil(t, cache)
			assert.Equal(t, k8sAPI, cache.k8sClient)
			assert.NotNil(t, cache.ruleCreator)
			assert.NotNil(t, cache.watchResources)
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

func TestListRulesForObjectIgnoreBindings(t *testing.T) {
	c := &RBCache{
		k8sClient:          k8sinterface.NewKubernetesApiMock(),
		ruleCreator:        &rules.RuleCreatorMock{},
		rbNameToRules:      maps.SafeMap[string, []rules.RuleEvaluator]{},
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
