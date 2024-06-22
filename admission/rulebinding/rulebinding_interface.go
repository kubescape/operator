package rulebinding

import (
	"node-agent/pkg/rulebindingmanager"

	"github.com/kubescape/operator/admission/rules"
)

type RuleBindingCache interface {
	ListRulesForPod(namespace, name string) []rules.RuleEvaluator
	AddNotifier(*chan rulebindingmanager.RuleBindingNotify)
}
