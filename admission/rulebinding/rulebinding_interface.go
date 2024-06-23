package rulebinding

import (
	"context"

	"github.com/kubescape/operator/admission/rules"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type RuleBindingCache interface {
	ListRulesForObject(ctx context.Context, object *unstructured.Unstructured) []rules.RuleEvaluator
}
