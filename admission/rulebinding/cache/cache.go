package cache

import (
	"context"
	"strings"

	"node-agent/pkg/rulebindingmanager/types"
	typesv1 "node-agent/pkg/rulebindingmanager/types/v1"
	"node-agent/pkg/watcher"

	"node-agent/pkg/k8sclient"

	"node-agent/pkg/rulebindingmanager"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/admission/rulebinding"
	"github.com/kubescape/operator/admission/rules"
	rulesv1 "github.com/kubescape/operator/admission/rules/v1"
)

const (
	IncludeClusterObjects = "includeClusterObjects"
)

var _ rulebinding.RuleBindingCache = (*RBCache)(nil)
var _ watcher.Adaptor = (*RBCache)(nil)

type RBCache struct {
	k8sClient      k8sclient.K8sClientInterface
	rbNameToRB     maps.SafeMap[string, typesv1.RuntimeAlertRuleBinding] // rule binding name -> rule binding
	rbNameToRules  maps.SafeMap[string, []rules.RuleEvaluator]           // rule binding name -> []created rules
	ruleCreator    rules.RuleCreator
	watchResources []watcher.WatchResource
	notifiers      []*chan rulebindingmanager.RuleBindingNotify
}

func NewCache(k8sClient k8sclient.K8sClientInterface) *RBCache {
	return &RBCache{
		k8sClient:      k8sClient,
		ruleCreator:    rulesv1.NewRuleCreator(),
		rbNameToRB:     maps.SafeMap[string, typesv1.RuntimeAlertRuleBinding]{},
		watchResources: resourcesToWatch(),
	}
}

// ----------------- watcher.WatchResources methods -----------------

func (c *RBCache) WatchResources() []watcher.WatchResource {
	return c.watchResources
}

// ------------------ rulebindingmanager.RuleBindingCache methods -----------------------

func (c *RBCache) ListRulesForObject(ctx context.Context, object *unstructured.Unstructured) []rules.RuleEvaluator {
	var rulesSlice []rules.RuleEvaluator
	var rbNames []string

	for _, rb := range c.rbNameToRB.Values() {
		rbName := uniqueName(&rb)
		// check if the object is cluster object
		if object.GetNamespace() == "" {
			includeClusterObjects, ok := object.GetLabels()[IncludeClusterObjects]
			if !ok {
				includeClusterObjects = "true"
			}

			if includeClusterObjects == "false" {
				continue
			}

			// check if the object is cluster object
			rbNames = append(rbNames, rbName)
			continue
		}

		// check pod selectors
		podSelector, _ := metav1.LabelSelectorAsSelector(&rb.Spec.PodSelector)
		if !podSelector.Matches(labels.Set(object.GetLabels())) {
			// pod selectors doesnt match
			continue
		}

		// check namespace selectors
		nsSelector, _ := metav1.LabelSelectorAsSelector(&rb.Spec.NamespaceSelector)
		nsSelectorStr := nsSelector.String()
		if len(nsSelectorStr) != 0 {
			// get related namespaces
			namespaces, err := c.k8sClient.GetKubernetesClient().CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: nsSelectorStr})
			if err != nil {
				logger.L().Error("failed to list namespaces", helpers.String("ruleBiding", uniqueName(&rb)), helpers.String("nsSelector", nsSelectorStr), helpers.Error(err))
				continue
			}
			if !strings.Contains(namespaces.String(), object.GetNamespace()) {
				// namespace selectors dont match
				continue
			}
		}

		rbNames = append(rbNames, rbName)
	}

	for _, ruleName := range rbNames {
		if c.rbNameToRules.Has(ruleName) {
			rulesSlice = append(rulesSlice, c.rbNameToRules.Get(ruleName)...)
		}
	}

	return rulesSlice
}

func (c *RBCache) AddNotifier(n *chan rulebindingmanager.RuleBindingNotify) {
	c.notifiers = append(c.notifiers, n)
}

// ------------------ watcher.Watcher methods -----------------------

func (c *RBCache) AddHandler(ctx context.Context, obj *unstructured.Unstructured) {
	var rbs []rulebindingmanager.RuleBindingNotify

	switch obj.GetKind() {
	case types.RuntimeRuleBindingAlertKind:
		ruleBinding, err := unstructuredToRuleBinding(obj)
		if err != nil {
			logger.L().Error("failed to convert unstructured to rule binding", helpers.Error(err))
			return
		}
		rbs = c.addRuleBinding(ruleBinding)
	}
	// notify
	for n := range c.notifiers {
		for i := range rbs {
			*c.notifiers[n] <- rbs[i]
		}
	}
}
func (c *RBCache) ModifyHandler(ctx context.Context, obj *unstructured.Unstructured) {
	var rbs []rulebindingmanager.RuleBindingNotify

	switch obj.GetKind() {
	case types.RuntimeRuleBindingAlertKind:
		ruleBinding, err := unstructuredToRuleBinding(obj)
		if err != nil {
			logger.L().Error("failed to convert unstructured to rule binding", helpers.Error(err))
			return
		}
		rbs = c.modifiedRuleBinding(ruleBinding)
	}
	// notify
	for n := range c.notifiers {
		for i := range rbs {
			*c.notifiers[n] <- rbs[i]
		}
	}
}
func (c *RBCache) DeleteHandler(_ context.Context, obj *unstructured.Unstructured) {
	var rbs []rulebindingmanager.RuleBindingNotify
	switch obj.GetKind() {
	case types.RuntimeRuleBindingAlertKind:
		rbs = c.deleteRuleBinding(uniqueName(obj))
	}

	// notify
	for n := range c.notifiers {
		for i := range rbs {
			*c.notifiers[n] <- rbs[i]
		}
	}
}

// ----------------- RuleBinding manager methods -----------------

// AddRuleBinding adds a rule binding to the cache
func (c *RBCache) addRuleBinding(ruleBinding *typesv1.RuntimeAlertRuleBinding) []rulebindingmanager.RuleBindingNotify {
	var rbs []rulebindingmanager.RuleBindingNotify
	rbName := uniqueName(ruleBinding)
	logger.L().Info("RuleBinding added/modified", helpers.String("name", rbName))

	// add the rule binding to the cache
	c.rbNameToRB.Set(rbName, *ruleBinding)
	c.rbNameToRules.Set(rbName, c.createRules(ruleBinding.Spec.Rules))

	return rbs
}
func (c *RBCache) deleteRuleBinding(uniqueName string) []rulebindingmanager.RuleBindingNotify {
	logger.L().Info("RuleBinding deleted", helpers.String("name", uniqueName))
	var rbs []rulebindingmanager.RuleBindingNotify

	// remove the rule binding from the cache
	c.rbNameToRB.Delete(uniqueName)
	c.rbNameToRules.Delete(uniqueName)

	logger.L().Info("DeleteRuleBinding", helpers.String("name", uniqueName))
	return rbs
}

func (c *RBCache) modifiedRuleBinding(ruleBinding *typesv1.RuntimeAlertRuleBinding) []rulebindingmanager.RuleBindingNotify {
	rbsD := c.deleteRuleBinding(uniqueName(ruleBinding))
	rbsA := c.addRuleBinding(ruleBinding)

	return diff(rbsD, rbsA)
}

func (c *RBCache) createRules(rulesForPod []typesv1.RuntimeAlertRuleBindingRule) []rules.RuleEvaluator {
	var rules []rules.RuleEvaluator
	// Get the rules that are bound to the container
	for _, ruleParams := range rulesForPod {
		rules = append(rules, c.createRule(&ruleParams)...)
	}
	return rules
}

func (c *RBCache) createRule(r *typesv1.RuntimeAlertRuleBindingRule) []rules.RuleEvaluator {
	if r.RuleID != "" {
		if ruleDesc := c.ruleCreator.CreateRuleByID(r.RuleID); ruleDesc != nil {
			if r.Parameters != nil {
				ruleDesc.SetParameters(r.Parameters)
			}
			return []rules.RuleEvaluator{ruleDesc}
		}
	}
	if r.RuleName != "" {
		if ruleDesc := c.ruleCreator.CreateRuleByName(r.RuleName); ruleDesc != nil {
			if r.Parameters != nil {
				ruleDesc.SetParameters(r.Parameters)
			}
			return []rules.RuleEvaluator{ruleDesc}
		}
	}
	if len(r.RuleTags) > 0 {
		if ruleTagsDescs := c.ruleCreator.CreateRulesByTags(r.RuleTags); ruleTagsDescs != nil {
			for _, ruleDesc := range ruleTagsDescs {
				if r.Parameters != nil {
					ruleDesc.SetParameters(r.Parameters)
				}
			}
			return ruleTagsDescs
		}
	}
	return []rules.RuleEvaluator{}
}

func diff(a, b []rulebindingmanager.RuleBindingNotify) []rulebindingmanager.RuleBindingNotify {
	m := make(map[string]rulebindingmanager.RuleBindingNotify)
	diff := make([]rulebindingmanager.RuleBindingNotify, 0)

	for i := range a {
		m[uniqueName(&a[i].Pod)] = a[i]
	}

	for i := range b {
		n := uniqueName(&b[i].Pod)
		if _, found := m[n]; !found {
			diff = append(diff, b[i])
		} else {
			delete(m, n)
		}
	}

	for i := range m {
		diff = append(diff, m[i])
	}

	return diff
}
