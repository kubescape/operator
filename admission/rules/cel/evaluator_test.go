package cel

import (
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/operator/objectcache"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// newEvalTestAttributes builds an admission.Attributes suitable for evaluator tests.
func newEvalTestAttributes(kind, name, namespace, operation, subresource string, obj map[string]interface{}) admission.Attributes {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: kind}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	var u *unstructured.Unstructured
	if obj != nil {
		u = &unstructured.Unstructured{Object: obj}
	}
	userInfo := &user.DefaultInfo{
		Name:   "test-user",
		Groups: []string{"system:masters"},
		UID:    "uid-123",
	}
	return admission.NewAttributesRecord(u, nil, gvk, namespace, name, gvr, subresource,
		admission.Operation(operation), nil, false, userInfo)
}

// newExecRule returns a RuntimeRule that matches PodExecOptions admission events.
func newExecRule() armotypes.RuntimeRule {
	return armotypes.RuntimeRule{
		ID:          "R3000",
		Name:        "Exec to pod",
		Description: "Detects exec to pod",
		Severity:    armotypes.RuleSeverityHigh,
		Tags:        []string{"exec"},
		Expressions: armotypes.RuleExpressions{
			Message:  `"Exec detected on pod: " + event.Name`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
			},
		},
	}
}

func TestIDAndName(t *testing.T) {
	engine := newTestCelEngine(t)
	rule := newExecRule()
	ev := newCelRuleEvaluator(rule, engine)

	if ev.ID() != "R3000" {
		t.Errorf("ID = %q, want R3000", ev.ID())
	}
	if ev.Name() != "Exec to pod" {
		t.Errorf("Name = %q, want 'Exec to pod'", ev.Name())
	}
}

func TestParameters(t *testing.T) {
	engine := newTestCelEngine(t)
	ev := newCelRuleEvaluator(newExecRule(), engine)

	if p := ev.GetParameters(); p != nil {
		t.Errorf("GetParameters before Set = %v, want nil", p)
	}

	params := map[string]interface{}{"threshold": 5}
	ev.SetParameters(params)

	got := ev.GetParameters()
	if len(got) != 1 {
		t.Fatalf("GetParameters len = %d, want 1", len(got))
	}
	if got["threshold"] != 5 {
		t.Errorf("GetParameters[threshold] = %v, want 5", got["threshold"])
	}
}

func TestProcessEvent_NoMatch(t *testing.T) {
	engine := newTestCelEngine(t)
	ev := newCelRuleEvaluator(newExecRule(), engine)

	// Send a Pod event, rule only fires on PodExecOptions.
	attrs := newEvalTestAttributes("Pod", "my-pod", "default", "CREATE", "", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
	})

	result := ev.ProcessEvent(attrs, nil)
	if result != nil {
		t.Errorf("expected nil for non-matching event, got %v", result)
	}
}

func TestProcessEvent_Match(t *testing.T) {
	engine := newTestCelEngine(t)
	ev := newCelRuleEvaluator(newExecRule(), engine)

	attrs := newEvalTestAttributes("PodExecOptions", "my-pod", "default", "CONNECT", "exec",
		map[string]interface{}{
			"command":   []interface{}{"/bin/sh"},
			"container": "main",
		})

	result := ev.ProcessEvent(attrs, nil)
	if result == nil {
		t.Fatal("expected non-nil RuleFailure for matching event")
	}

	// Rule ID
	if result.GetRuleId() != "R3000" {
		t.Errorf("GetRuleId = %q, want R3000", result.GetRuleId())
	}

	// BaseRuntimeAlert
	base := result.GetBaseRuntimeAlert()
	if base.AlertName != "Exec detected on pod: my-pod" {
		t.Errorf("AlertName = %q, want 'Exec detected on pod: my-pod'", base.AlertName)
	}
	if base.Severity != armotypes.RuleSeverityHigh {
		t.Errorf("Severity = %d, want %d", base.Severity, armotypes.RuleSeverityHigh)
	}
	if base.UniqueID != "default/my-pod" {
		t.Errorf("UniqueID = %q, want 'default/my-pod'", base.UniqueID)
	}
	if base.Timestamp.IsZero() {
		t.Error("Timestamp is zero, want non-zero")
	}

	// RuleAlert
	ruleAlert := result.GetRuleAlert()
	if ruleAlert.RuleDescription != "Detects exec to pod" {
		t.Errorf("RuleDescription = %q, want 'Detects exec to pod'", ruleAlert.RuleDescription)
	}

	// AdmissionAlert
	admAlert := result.GetAdmissionsAlert()
	if admAlert.ObjectName != "my-pod" {
		t.Errorf("AdmissionAlert.ObjectName = %q, want 'my-pod'", admAlert.ObjectName)
	}
	if admAlert.RequestNamespace != "default" {
		t.Errorf("AdmissionAlert.RequestNamespace = %q, want 'default'", admAlert.RequestNamespace)
	}
	if admAlert.Subresource != "exec" {
		t.Errorf("AdmissionAlert.Subresource = %q, want 'exec'", admAlert.Subresource)
	}
	if admAlert.Kind.Kind != "PodExecOptions" {
		t.Errorf("AdmissionAlert.Kind.Kind = %q, want 'PodExecOptions'", admAlert.Kind.Kind)
	}
	if admAlert.UserInfo == nil {
		t.Fatal("AdmissionAlert.UserInfo is nil")
	}
	if admAlert.UserInfo.Name != "test-user" {
		t.Errorf("AdmissionAlert.UserInfo.Name = %q, want 'test-user'", admAlert.UserInfo.Name)
	}
	if admAlert.Object == nil {
		t.Error("AdmissionAlert.Object is nil, want non-nil")
	}
}

func TestProcessEvent_NilAttrs(t *testing.T) {
	engine := newTestCelEngine(t)
	ev := newCelRuleEvaluator(newExecRule(), engine)

	result := ev.ProcessEvent(nil, nil)
	if result != nil {
		t.Errorf("expected nil for nil attrs, got %v", result)
	}
}

func TestProcessEvent_MessageFallback(t *testing.T) {
	engine := newTestCelEngine(t)

	// Rule with no Message expression — AlertName should fall back to rule name.
	rule := armotypes.RuntimeRule{
		ID:       "R4000",
		Name:     "Fallback Rule",
		Severity: armotypes.RuleSeverityLow,
		Expressions: armotypes.RuleExpressions{
			// No Message field.
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
			},
		},
	}

	ev := newCelRuleEvaluator(rule, engine)
	attrs := newEvalTestAttributes("PodExecOptions", "my-pod", "default", "CONNECT", "exec",
		map[string]interface{}{
			"kind":       "PodExecOptions",
			"apiVersion": "v1",
		})

	result := ev.ProcessEvent(attrs, nil)
	if result == nil {
		t.Fatal("expected non-nil RuleFailure")
	}
	if result.GetBaseRuntimeAlert().AlertName != "Fallback Rule" {
		t.Errorf("AlertName = %q, want 'Fallback Rule'", result.GetBaseRuntimeAlert().AlertName)
	}
}

func TestProcessEvent_WithK8sEnrichment(t *testing.T) {
	engine := newTestCelEngine(t)
	ev := newCelRuleEvaluator(newExecRule(), engine)

	attrs := newEvalTestAttributes("PodExecOptions", "test-pod", "test-namespace", "CONNECT", "exec",
		map[string]interface{}{
			"kind":       "PodExecOptions",
			"apiVersion": "v1",
			"command":    []interface{}{"bash"},
			"container":  "test-container",
		})

	// KubernetesCacheMockImpl pre-populates a pod named "test-pod" in "test-namespace".
	result := ev.ProcessEvent(attrs, objectcache.KubernetesCacheMockImpl{})
	if result == nil {
		t.Fatal("expected non-nil RuleFailure")
	}

	k8s := result.GetRuntimeAlertK8sDetails()
	if k8s.PodName != "test-pod" {
		t.Errorf("PodName = %q, want 'test-pod'", k8s.PodName)
	}
	if k8s.Namespace != "test-namespace" {
		t.Errorf("Namespace = %q, want 'test-namespace'", k8s.Namespace)
	}
	if k8s.NodeName != "test-node" {
		t.Errorf("NodeName = %q, want 'test-node'", k8s.NodeName)
	}
	if k8s.WorkloadName != "test-workload" {
		t.Errorf("WorkloadName = %q, want 'test-workload'", k8s.WorkloadName)
	}
	if k8s.WorkloadKind != "ReplicaSet" {
		t.Errorf("WorkloadKind = %q, want 'ReplicaSet'", k8s.WorkloadKind)
	}
	if k8s.ContainerName != "test-container" {
		t.Errorf("ContainerName = %q, want 'test-container'", k8s.ContainerName)
	}
	if k8s.ContainerID != "containerd://abcdef1234567890" {
		t.Errorf("ContainerID = %q, want 'containerd://abcdef1234567890'", k8s.ContainerID)
	}
}

// TestProcessEvent_UsesBindingParameters verifies that SetParameters values
// are reachable from CEL expressions via the "params" variable. Without this,
// per-binding overrides would be inert: parametrized rules would never see
// the parameter values supplied by their RuntimeAlertRuleBinding.
func TestProcessEvent_UsesBindingParameters(t *testing.T) {
	engine := newTestCelEngine(t)

	// Rule fires only when params["allowExec"] is false. Tests that:
	// (1) params is visible from CEL, (2) parameter overrides change behavior.
	rule := armotypes.RuntimeRule{
		ID:       "R7000",
		Name:     "Parameterized exec",
		Severity: armotypes.RuleSeverityHigh,
		Expressions: armotypes.RuleExpressions{
			Message:  `"exec blocked: " + event.Name`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{
					EventType:  armotypes.EventTypeK8sAdmission,
					Expression: `event.Kind == "PodExecOptions" && !(has(params.allowExec) && params.allowExec)`,
				},
			},
		},
	}

	attrs := newEvalTestAttributes("PodExecOptions", "test-pod", "default", "CONNECT", "exec",
		map[string]interface{}{
			"kind": "PodExecOptions",
		})

	t.Run("no parameters set — rule fires", func(t *testing.T) {
		ev := newCelRuleEvaluator(rule, engine)
		result := ev.ProcessEvent(attrs, nil)
		if result == nil {
			t.Fatal("expected non-nil RuleFailure when no parameters override")
		}
	})

	t.Run("allowExec=true via binding parameters — rule suppressed", func(t *testing.T) {
		ev := newCelRuleEvaluator(rule, engine)
		ev.SetParameters(map[string]interface{}{"allowExec": true})
		result := ev.ProcessEvent(attrs, nil)
		if result != nil {
			t.Errorf("expected nil RuleFailure when params.allowExec=true, got %+v", result)
		}
	})

	t.Run("allowExec=false via binding parameters — rule fires", func(t *testing.T) {
		ev := newCelRuleEvaluator(rule, engine)
		ev.SetParameters(map[string]interface{}{"allowExec": false})
		result := ev.ProcessEvent(attrs, nil)
		if result == nil {
			t.Fatal("expected non-nil RuleFailure when params.allowExec=false")
		}
	})
}

func TestEnrichmentApplicable(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		resource string
		want     bool
	}{
		{name: "Pod CRUD", kind: "Pod", resource: "pods", want: true},
		{name: "PodExecOptions subresource", kind: "PodExecOptions", resource: "pods", want: true},
		{name: "PodPortForwardOptions subresource", kind: "PodPortForwardOptions", resource: "pods", want: true},
		{name: "PodAttachOptions subresource", kind: "PodAttachOptions", resource: "pods", want: true},
		// Kind-only matches even if resource is wrong; this guards against
		// API-server quirks where a subresource arrives addressed differently.
		{name: "PodExec by kind alone", kind: "PodExecOptions", resource: "", want: true},
		{name: "NetworkPolicy CREATE", kind: "NetworkPolicy", resource: "networkpolicies", want: false},
		{name: "RoleBinding CREATE", kind: "RoleBinding", resource: "rolebindings", want: false},
		{name: "Secret CREATE", kind: "Secret", resource: "secrets", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: tt.kind}
			gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: tt.resource}
			attrs := admission.NewAttributesRecord(nil, nil, gvk, "ns", "n", gvr, "",
				admission.Create, nil, false, nil)
			if got := enrichmentApplicable(attrs); got != tt.want {
				t.Errorf("enrichmentApplicable(kind=%q, resource=%q) = %v, want %v",
					tt.kind, tt.resource, got, tt.want)
			}
		})
	}
}

// TestProcessEvent_SkipsEnrichmentForNonPodKind verifies that ProcessEvent does
// not populate RuntimeAlertK8sDetails when the admission event is not for a
// Pod or pod subresource. Calling enrichK8sDetails on, e.g., a NetworkPolicy
// would resolve a Pod by the NetworkPolicy's name — at best NotFound, at
// worst an unrelated Pod that shares the name.
func TestProcessEvent_SkipsEnrichmentForNonPodKind(t *testing.T) {
	engine := newTestCelEngine(t)
	rule := armotypes.RuntimeRule{
		ID:       "R6000",
		Name:     "NetworkPolicy created",
		Severity: armotypes.RuleSeverityMed,
		Expressions: armotypes.RuleExpressions{
			Message:  `"NetworkPolicy: " + event.Name`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "NetworkPolicy"`},
			},
		},
	}
	ev := newCelRuleEvaluator(rule, engine)

	gvk := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
	}}
	userInfo := &user.DefaultInfo{Name: "kubernetes-admin"}
	attrs := admission.NewAttributesRecord(obj, nil, gvk, "default", "test-netpol", gvr, "",
		admission.Create, nil, false, userInfo)

	// Pass a Kubernetes cache: even though one is available, the validator
	// must skip Pod-specific enrichment for a NetworkPolicy.
	result := ev.ProcessEvent(attrs, objectcache.KubernetesCacheMockImpl{})
	if result == nil {
		t.Fatal("expected non-nil RuleFailure")
	}

	k8s := result.GetRuntimeAlertK8sDetails()
	// Enrichment must NOT have populated Pod-derived fields.
	if k8s.PodName != "" {
		t.Errorf("PodName = %q, want empty (enrichment must be skipped for NetworkPolicy)", k8s.PodName)
	}
	if k8s.ContainerName != "" {
		t.Errorf("ContainerName = %q, want empty", k8s.ContainerName)
	}
	if k8s.NodeName != "" {
		t.Errorf("NodeName = %q, want empty", k8s.NodeName)
	}
}

func TestProcessEvent_WrongEventType(t *testing.T) {
	engine := newTestCelEngine(t)

	// Rule with an exec event type expression (not k8s-admission).
	rule := armotypes.RuntimeRule{
		ID:   "R5000",
		Name: "Wrong event type",
		Expressions: armotypes.RuleExpressions{
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeExec, Expression: `event.Kind == "PodExecOptions"`},
			},
		},
	}

	ev := newCelRuleEvaluator(rule, engine)
	attrs := newEvalTestAttributes("PodExecOptions", "my-pod", "default", "CONNECT", "exec",
		map[string]interface{}{
			"kind":       "PodExecOptions",
			"apiVersion": "v1",
		})

	// No k8s-admission expressions → should not match.
	result := ev.ProcessEvent(attrs, nil)
	if result != nil {
		t.Errorf("expected nil when no k8s-admission expressions exist, got %v", result)
	}
}

// newPodRule returns a RuntimeRule that matches Pod CREATE admission events.
func newPodRule() armotypes.RuntimeRule {
	return armotypes.RuntimeRule{
		ID:          "R3001",
		Name:        "Privileged pod",
		Description: "Detects privileged pod creation",
		Severity:    armotypes.RuleSeverityHigh,
		Expressions: armotypes.RuleExpressions{
			Message:  `"Privileged pod: " + event.Namespace`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "Pod" && event.Operation == "CREATE"`},
			},
		},
	}
}

// TestProcessEvent_PodCreateEnrichment verifies that a Pod CREATE alert carries
// pod identity and owner details taken from the admission object. The pod does
// not exist in the API yet at admission time, so a GET by name cannot be used;
// without this path the backend drops the alert for missing PodName.
func TestProcessEvent_PodCreateEnrichment(t *testing.T) {
	engine := newTestCelEngine(t)
	ev := newCelRuleEvaluator(newPodRule(), engine)

	// "brand-new-pod" is deliberately absent from KubernetesCacheMockImpl;
	// only the ReplicaSet "test-workload" exists there.
	attrs := newEvalTestAttributes("Pod", "brand-new-pod", "test-namespace", "CREATE", "",
		map[string]interface{}{
			"kind":       "Pod",
			"apiVersion": "v1",
			"metadata": map[string]interface{}{
				"name":      "brand-new-pod",
				"namespace": "test-namespace",
				"ownerReferences": []interface{}{
					map[string]interface{}{
						"apiVersion": "apps/v1",
						"kind":       "ReplicaSet",
						"name":       "test-workload",
						"uid":        "test-replicaset-uid-12345",
					},
				},
			},
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":            "app",
						"image":           "nginx",
						"securityContext": map[string]interface{}{"privileged": true},
					},
				},
			},
		})

	result := ev.ProcessEvent(attrs, objectcache.KubernetesCacheMockImpl{})
	if result == nil {
		t.Fatal("expected non-nil RuleFailure")
	}

	k8s := result.GetRuntimeAlertK8sDetails()
	if k8s.PodName != "brand-new-pod" {
		t.Errorf("PodName = %q, want 'brand-new-pod'", k8s.PodName)
	}
	if k8s.PodNamespace != "test-namespace" || k8s.Namespace != "test-namespace" {
		t.Errorf("PodNamespace/Namespace = %q/%q, want 'test-namespace'", k8s.PodNamespace, k8s.Namespace)
	}
	if k8s.WorkloadKind != "ReplicaSet" || k8s.WorkloadName != "test-workload" {
		t.Errorf("Workload = %s/%s, want ReplicaSet/test-workload", k8s.WorkloadKind, k8s.WorkloadName)
	}
	if k8s.WorkloadNamespace != "test-namespace" {
		t.Errorf("WorkloadNamespace = %q, want 'test-namespace'", k8s.WorkloadNamespace)
	}
	if k8s.WorkloadUID != "test-replicaset-uid-12345" {
		t.Errorf("WorkloadUID = %q, want 'test-replicaset-uid-12345'", k8s.WorkloadUID)
	}
	if k8s.ContainerName != "" {
		t.Errorf("ContainerName = %q, want empty for pod CREATE", k8s.ContainerName)
	}
	if result.GetBaseRuntimeAlert().UniqueID != "test-namespace/brand-new-pod" {
		t.Errorf("UniqueID = %q, want 'test-namespace/brand-new-pod'", result.GetBaseRuntimeAlert().UniqueID)
	}
}

// TestProcessEvent_PodCreateGenerateName verifies the generateName fallback:
// when the request carries no name yet, the object's generateName prefix is
// used so the alert still passes backend validation.
func TestProcessEvent_PodCreateGenerateName(t *testing.T) {
	engine := newTestCelEngine(t)
	ev := newCelRuleEvaluator(newPodRule(), engine)

	attrs := newEvalTestAttributes("Pod", "", "test-namespace", "CREATE", "",
		map[string]interface{}{
			"kind":       "Pod",
			"apiVersion": "v1",
			"metadata": map[string]interface{}{
				"generateName": "debug-",
				"namespace":    "test-namespace",
			},
			"spec": map[string]interface{}{
				"containers": []interface{}{map[string]interface{}{"name": "app", "image": "busybox"}},
			},
		})

	result := ev.ProcessEvent(attrs, objectcache.KubernetesCacheMockImpl{})
	if result == nil {
		t.Fatal("expected non-nil RuleFailure")
	}
	k8s := result.GetRuntimeAlertK8sDetails()
	if k8s.PodName != "debug-" {
		t.Errorf("PodName = %q, want 'debug-'", k8s.PodName)
	}
	if k8s.PodNamespace != "test-namespace" {
		t.Errorf("PodNamespace = %q, want 'test-namespace'", k8s.PodNamespace)
	}
	if k8s.WorkloadKind != "" {
		t.Errorf("WorkloadKind = %q, want empty for an unowned pod", k8s.WorkloadKind)
	}
}
