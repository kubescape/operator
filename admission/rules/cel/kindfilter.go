package cel

import (
	armotypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/parser"
)

// KindFilter is the set of admission Kinds that at least one currently-loaded
// rule could match. It is built from the loaded rule expressions at SyncRules
// time and used by the validator to skip CEL evaluation for events no rule
// targets.
//
// The filter is *conservative*: if an expression cannot be statically resolved
// to a finite set of Kinds (e.g. no conjunct of its top-level && chain is an
// event.Kind == constraint, or it uses set membership / regex), the filter
// falls back to wildcard mode and accepts every Kind. Correctness is preserved
// at the cost of skipping the optimization.
type KindFilter struct {
	wildcard bool
	kinds    map[string]struct{}
}

// Accepts reports whether at least one loaded rule could match an admission
// event of the given Kind. Wildcard filters accept every Kind.
func (f *KindFilter) Accepts(kind string) bool {
	if f == nil || f.wildcard {
		return true
	}
	_, ok := f.kinds[kind]
	return ok
}

// IsWildcard reports whether the filter accepts every Kind.
func (f *KindFilter) IsWildcard() bool {
	return f == nil || f.wildcard
}

// Kinds returns the set of admission Kinds this filter explicitly accepts.
// Returns nil for wildcard filters.
func (f *KindFilter) Kinds() []string {
	if f == nil || f.wildcard {
		return nil
	}
	out := make([]string, 0, len(f.kinds))
	for k := range f.kinds {
		out = append(out, k)
	}
	return out
}

// buildKindFilter returns a KindFilter covering the admission expressions of
// the given rules. Only RuleExpression entries with EventType k8s-admission
// are considered (other event types are not evaluated by this operator).
func buildKindFilter(rs []armotypes.RuntimeRule) *KindFilter {
	f := &KindFilter{kinds: map[string]struct{}{}}

	for _, r := range rs {
		for _, expr := range r.Expressions.RuleExpression {
			if expr.EventType != armotypes.EventTypeK8sAdmission {
				continue
			}
			if f.absorbExpression(expr.Expression) {
				// One unresolvable expression poisons the whole filter.
				return &KindFilter{wildcard: true}
			}
		}
	}

	// If no expression contributed any kind constraints, the filter would
	// match nothing — which is wrong. Treat as wildcard.
	if len(f.kinds) == 0 {
		return &KindFilter{wildcard: true}
	}
	return f
}

// absorbExpression adds the Kinds one CEL expression can match to the filter.
// Returns true if the expression is unresolvable and the caller should fall
// back to wildcard mode.
//
// The expression is parsed, and only the conjuncts of its top-level && chain
// can bound it, because it is true only where each of them is. A conjunct
// bounds it when it is true for a fixed set of Kinds alone (see kindsOf). An
// event.Kind test anywhere else, such as under !, in a ternary or in a list
// beside other conditions, doesn't limit the Kinds the expression matches.
func (f *KindFilter) absorbExpression(expr string) (unresolvable bool) {
	// No macros are registered, so a list's .exists(v, v) stays a call that
	// kindsOf can read. The admission CEL environment enables optional syntax.
	p, err := parser.NewParser(parser.EnableOptionalSyntax(true))
	if err != nil {
		return true
	}
	parsed, errs := p.Parse(common.NewTextSource(expr))
	if len(errs.GetErrors()) != 0 {
		return true
	}
	for _, conjunct := range conjuncts(parsed.Expr()) {
		if kinds, ok := kindsOf(conjunct); ok {
			for _, kind := range kinds {
				f.kinds[kind] = struct{}{}
			}
			return false
		}
	}
	return true
}

// conjuncts flattens the top-level && chain of e.
func conjuncts(e ast.Expr) []ast.Expr {
	if e.Kind() != ast.CallKind || e.AsCall().FunctionName() != operators.LogicalAnd {
		return []ast.Expr{e}
	}
	var out []ast.Expr
	for _, arg := range e.AsCall().Args() {
		out = append(out, conjuncts(arg)...)
	}
	return out
}

// kindsOf returns the Kinds e can be true for when e is event.Kind == "X"
// (either way round), or a list of such tests checked with .exists(v, v), as
// in [event.Kind == "X", event.Kind == "Y"].exists(k, k). ok is false for any
// other expression.
func kindsOf(e ast.Expr) (kinds []string, ok bool) {
	if kind, ok := kindEquality(e); ok {
		return []string{kind}, true
	}
	if e.Kind() != ast.CallKind {
		return nil, false
	}
	call := e.AsCall()
	if call.FunctionName() != "exists" || !call.IsMemberFunction() ||
		call.Target().Kind() != ast.ListKind || len(call.Args()) != 2 {
		return nil, false
	}
	v, pred := call.Args()[0], call.Args()[1]
	if v.Kind() != ast.IdentKind || pred.Kind() != ast.IdentKind || v.AsIdent() != pred.AsIdent() {
		return nil, false
	}
	for _, element := range call.Target().AsList().Elements() {
		kind, ok := kindEquality(element)
		if !ok {
			return nil, false
		}
		kinds = append(kinds, kind)
	}
	return kinds, true
}

// kindEquality returns X when e is event.Kind == "X" or "X" == event.Kind.
func kindEquality(e ast.Expr) (string, bool) {
	if e.Kind() != ast.CallKind || e.AsCall().FunctionName() != operators.Equals {
		return "", false
	}
	args := e.AsCall().Args()
	if len(args) != 2 {
		return "", false
	}
	for i, side := range args {
		if !isEventKind(side) {
			continue
		}
		other := args[1-i]
		if other.Kind() != ast.LiteralKind {
			return "", false
		}
		kind, ok := other.AsLiteral().(types.String)
		return string(kind), ok
	}
	return "", false
}

// isEventKind reports whether e is the selection event.Kind.
func isEventKind(e ast.Expr) bool {
	if e.Kind() != ast.SelectKind {
		return false
	}
	sel := e.AsSelect()
	return !sel.IsTestOnly() && sel.FieldName() == "Kind" &&
		sel.Operand().Kind() == ast.IdentKind && sel.Operand().AsIdent() == "event"
}
