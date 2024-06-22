package rules

import (
	"github.com/kubescape/operator/admission/rules"
)

var _ rules.RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	ruleDescriptions []RuleDescriptor
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{
		ruleDescriptions: []RuleDescriptor{
			R2000ExecToPodRuleDescriptor,
		},
	}
}

func (r *RuleCreatorImpl) CreateRulesByTags(tags []string) []rules.RuleEvaluator {
	var rules []rules.RuleEvaluator
	for _, rule := range r.ruleDescriptions {
		if rule.HasTags(tags) {
			rules = append(rules, rule.RuleCreationFunc())
		}
	}
	return rules
}

func (r *RuleCreatorImpl) CreateRuleByID(id string) rules.RuleEvaluator {
	for _, rule := range r.ruleDescriptions {
		if rule.ID == id {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func (r *RuleCreatorImpl) CreateRuleByName(name string) rules.RuleEvaluator {
	for _, rule := range r.ruleDescriptions {
		if rule.Name == name {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func (r *RuleCreatorImpl) GetAllRuleDescriptors() []RuleDescriptor {
	return r.ruleDescriptions
}
