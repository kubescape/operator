package rules

import (
	"github.com/kubescape/operator/objectcache"
	"k8s.io/apiserver/pkg/admission"
)

var _ RuleCreator = (*RuleCreatorMock)(nil)

type RuleCreatorMock struct {
}

func (r *RuleCreatorMock) CreateRulesByTags(tags []string) []RuleEvaluator {
	var rl []RuleEvaluator
	for _, t := range tags {
		rl = append(rl, &RuleMock{RuleName: t})
	}
	return rl
}
func (r *RuleCreatorMock) CreateRuleByID(id string) RuleEvaluator {
	return &RuleMock{RuleID: id}
}

func (r *RuleCreatorMock) CreateRuleByName(name string) RuleEvaluator {
	return &RuleMock{RuleName: name}
}

var _ RuleEvaluator = (*RuleMock)(nil)

type RuleMock struct {
	RuleParameters map[string]interface{}
	RuleName       string
	RuleID         string
}

func (rule *RuleMock) Name() string {
	return rule.RuleName
}

func (rule *RuleMock) ID() string {
	return rule.RuleID
}

func (rule *RuleMock) DeleteRule() {
}

func (rule *RuleMock) ProcessEvent(_ admission.Attributes, _ objectcache.KubernetesCache) RuleFailure {
	return nil
}

func (rule *RuleMock) GetParameters() map[string]interface{} {
	return rule.RuleParameters
}
func (rule *RuleMock) SetParameters(p map[string]interface{}) {
	rule.RuleParameters = p
}
