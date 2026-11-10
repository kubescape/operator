package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/operator/admission/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// recordingRuleBindingCache keeps the object each evaluation asked rules for.
type recordingRuleBindingCache struct {
	objects chan *unstructured.Unstructured
}

func (c *recordingRuleBindingCache) ListRulesForObject(_ context.Context, object *unstructured.Unstructured) []rules.RuleEvaluator {
	c.objects <- object
	return nil
}

// TestValidator_DeleteIsEvaluatedWithTheDeletedObject checks that a DELETE request reaches
// rule evaluation. The API server sends the deleted object as the old object and no object,
// so dropping every request without an object dropped every DELETE, although the chart
// subscribes the webhook to DELETE and the CEL event exposes it as oldObject.
func TestValidator_DeleteIsEvaluatedWithTheDeletedObject(t *testing.T) {
	cache := &recordingRuleBindingCache{objects: make(chan *unstructured.Unstructured, 1)}
	av := newTestValidator(cache)
	av.SetWorkerPool(1, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	av.Start(ctx)

	gvk := schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"}
	gvr := schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}
	deleted := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]interface{}{"name": "admins"},
	}}
	attrs := admission.NewAttributesRecord(nil, deleted, gvk, "", "admins", gvr, "",
		admission.Delete, nil, false, &user.DefaultInfo{Name: "kubernetes-admin"})

	require.NoError(t, av.Validate(ctx, attrs, nil))

	select {
	case object := <-cache.objects:
		assert.Equal(t, "admins", object.GetName(), "rules must be looked up for the deleted object")
	case <-time.After(2 * time.Second):
		t.Fatal("the DELETE request never reached rule evaluation")
	}
}
