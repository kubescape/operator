package cel

import (
	"sort"
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
)

func makeRule(id string, exprs ...armotypes.RuleExpression) armotypes.RuntimeRule {
	return armotypes.RuntimeRule{
		ID: id,
		Expressions: armotypes.RuleExpressions{
			RuleExpression: exprs,
		},
	}
}

func admExpr(expr string) armotypes.RuleExpression {
	return armotypes.RuleExpression{
		EventType:  armotypes.EventTypeK8sAdmission,
		Expression: expr,
	}
}

func TestKindFilter_Accepts(t *testing.T) {
	tests := []struct {
		name      string
		rules     []armotypes.RuntimeRule
		wildcard  bool
		wantKinds []string
		// (kind, accept) probes
		probes []struct {
			kind   string
			accept bool
		}
	}{
		{
			name: "single rule with single Kind on the RHS",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "PodExecOptions"`)),
			},
			wantKinds: []string{"PodExecOptions"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"Pod", false},
				{"NetworkPolicy", false},
			},
		},
		{
			name: "Kind on the LHS",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`"PodExecOptions" == event.Kind`)),
			},
			wantKinds: []string{"PodExecOptions"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"Pod", false},
			},
		},
		{
			name: "single quotes",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == 'NetworkPolicy'`)),
			},
			wantKinds: []string{"NetworkPolicy"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"NetworkPolicy", true},
				{"Pod", false},
			},
		},
		{
			name: "conjunction with extra constraints (CREATE)",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "NetworkPolicy" && event.Operation == "CREATE"`)),
			},
			wantKinds: []string{"NetworkPolicy"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"NetworkPolicy", true},
				{"Pod", false},
			},
		},
		{
			name: "two rules cover two different Kinds",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "PodExecOptions"`)),
				makeRule("R2", admExpr(`event.Kind == "PodPortForwardOptions"`)),
			},
			wantKinds: []string{"PodExecOptions", "PodPortForwardOptions"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"PodPortForwardOptions", true},
				{"Pod", false},
			},
		},
		{
			name: "rule with disjunction => wildcard (conservative)",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "PodExecOptions" || event.Operation == "CREATE"`)),
			},
			wildcard: true,
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"AnythingElse", true},
			},
		},
		{
			name: "Kinds listed in an exists over Kind tests",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`[event.Kind == "ClusterRoleBinding", event.Kind == "RoleBinding"].exists(k, k) && event.Operation == "CREATE"`)),
			},
			wantKinds: []string{"ClusterRoleBinding", "RoleBinding"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"RoleBinding", true},
				{"Pod", false},
			},
		},
		{
			name: "disjunction beside a top-level Kind constraint",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "Pod" && (event.Operation == "CREATE" || event.Operation == "UPDATE")`)),
			},
			wantKinds: []string{"Pod"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"Pod", true},
				{"Deployment", false},
			},
		},
		{
			name: "rule with no Kind constraint => wildcard",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Operation == "CREATE"`)),
			},
			wildcard: true,
			probes: []struct {
				kind   string
				accept bool
			}{
				{"Pod", true},
				{"Secret", true},
			},
		},
		{
			name:     "empty rule set => wildcard",
			rules:    nil,
			wildcard: true,
			probes: []struct {
				kind   string
				accept bool
			}{
				{"Pod", true},
			},
		},
		{
			name: "non-admission expressions are ignored",
			rules: []armotypes.RuntimeRule{
				{
					ID: "R1",
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{
							{EventType: armotypes.EventTypeExec, Expression: `true`},
							{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "Pod"`},
						},
					},
				},
			},
			wantKinds: []string{"Pod"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"Pod", true},
				{"NetworkPolicy", false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := buildKindFilter(tt.rules)

			if f.IsWildcard() != tt.wildcard {
				t.Errorf("IsWildcard = %v, want %v", f.IsWildcard(), tt.wildcard)
			}

			if !tt.wildcard {
				got := f.Kinds()
				sort.Strings(got)
				want := append([]string(nil), tt.wantKinds...)
				sort.Strings(want)
				if !equalSlices(got, want) {
					t.Errorf("Kinds = %v, want %v", got, want)
				}
			}

			for _, p := range tt.probes {
				if f.Accepts(p.kind) != p.accept {
					t.Errorf("Accepts(%q) = %v, want %v", p.kind, f.Accepts(p.kind), p.accept)
				}
			}
		})
	}
}

// A Kind test that isn't a conjunct of the top-level && chain doesn't limit the
// Kinds a rule fires for, so the filter must not drop the other Kinds.
func TestKindFilter_AcceptsEveryKindARuleFiresFor(t *testing.T) {
	engine := newTestCelEngine(t)
	tests := []struct {
		name, expr, kind, operation, subresource string
	}{
		{
			name:        "negated Kind test",
			expr:        `!(event.Kind == "PodExecOptions") && event.Operation == "CONNECT"`,
			kind:        "PodAttachOptions",
			operation:   "CONNECT",
			subresource: "attach",
		},
		{
			name:      "Kind test as a ternary condition",
			expr:      `event.Operation == "CREATE" && (event.Kind == "Secret" ? event.Namespace != "kube-system" : true)`,
			kind:      "ConfigMap",
			operation: "CREATE",
		},
		{
			name:        "Kind test beside another condition in an exists",
			expr:        `[event.Kind == "PodExecOptions", event.Subresource == "attach"].exists(b, b)`,
			kind:        "PodAttachOptions",
			operation:   "CONNECT",
			subresource: "attach",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := makeRule("R1", admExpr(tt.expr))
			attrs := newEvalTestAttributes(tt.kind, "web", "default", tt.operation, tt.subresource,
				map[string]interface{}{"kind": tt.kind})
			if newCelRuleEvaluator(rule, engine).ProcessEvent(attrs, nil) == nil {
				t.Fatalf("rule %q doesn't fire for a %s event", tt.expr, tt.kind)
			}
			f := buildKindFilter([]armotypes.RuntimeRule{rule})
			if !f.Accepts(tt.kind) {
				t.Errorf("Accepts(%q) = false for rule %q, which fires for it (filter kinds %v)", tt.kind, tt.expr, f.Kinds())
			}
		})
	}
}

func TestKindFilter_NilSafety(t *testing.T) {
	var f *KindFilter
	if !f.Accepts("AnyKind") {
		t.Error("nil KindFilter should accept all kinds")
	}
	if !f.IsWildcard() {
		t.Error("nil KindFilter should report wildcard")
	}
	if f.Kinds() != nil {
		t.Error("nil KindFilter Kinds() should return nil")
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
