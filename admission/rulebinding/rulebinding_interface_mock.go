package rulebinding

import (
	"context"

	"github.com/kubescape/operator/admission/rules"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ RuleBindingCache = (*RuleBindingCacheMock)(nil)

type RuleBindingCacheMock struct {
}

func (r *RuleBindingCacheMock) ListRulesForObject(_ context.Context, _ *unstructured.Unstructured) []rules.RuleEvaluator {
	return []rules.RuleEvaluator{}
}
