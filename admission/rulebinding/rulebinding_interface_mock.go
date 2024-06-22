package rulebinding

import (
	"node-agent/pkg/rulebindingmanager"

	"github.com/kubescape/operator/admission/rules"
)

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
}

func (r *RuleBindingCacheMock) ListRulesForPod(_, _ string) []rules.RuleEvaluator {
	return []rules.RuleEvaluator{}
}
func (r *RuleBindingCacheMock) AddNotifier(_ *chan rulebindingmanager.RuleBindingNotify) {
}
