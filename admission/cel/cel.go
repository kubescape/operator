package cel

import (
	"fmt"
	"reflect"
	"sync"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// cachedProgram stores either a compiled CEL program or the compilation error
// that prevented it. The error is cached intentionally so repeated evaluation
// of a broken expression re-surfaces the failure rather than silently treating
// it as "no match" — a misconfigured rule must be loud, not invisible.
type cachedProgram struct {
	prog cel.Program
	err  error
}

// AdmissionCEL owns a CEL environment configured for evaluating expressions
// against AdmissionCelEvent values. Compiled programs are cached so repeated
// evaluation of the same expression avoids re-compilation.
type AdmissionCEL struct {
	env          *cel.Env
	programCache map[string]cachedProgram
	cacheMu      sync.RWMutex
}

// NewAdmissionCEL creates a CEL environment with the AdmissionCelEvent and
// AdmissionCelUserInfo types registered as native Go types, standard CEL
// extensions enabled (sets, lists, math, bindings, encoders, regex, network,
// two-variable comprehensions), and optional types support. The resulting
// environment exposes variables:
//
//	event     — cel.AdmissionCelEvent
//	eventType — string
//	object    — map[string]dyn
//	oldObject — map[string]dyn
//	options   — map[string]dyn
//	params    — map[string]dyn
func NewAdmissionCEL() (*AdmissionCEL, error) {
	env, err := cel.NewEnv(
		// Optional types and Network must precede NativeTypes because NativeTypes
		// composes over whichever type adapter and provider is configured in
		// cel.Env at the time it is invoked. Adding custom types afterwards is
		// rejected by ext.nativeTypeProvider.
		cel.OptionalTypes(),
		ext.Network(),
		ext.NativeTypes(
			reflect.TypeOf(&AdmissionCelEvent{}),
			reflect.TypeOf(&AdmissionCelUserInfo{}),
		),
		cel.Variable("event", cel.ObjectType("cel.AdmissionCelEvent")),
		cel.Variable("eventType", cel.StringType),
		// Map fields are injected as top-level variables because cel-go's
		// NativeTypes does not support map[string]interface{} struct fields.
		cel.Variable("object", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("oldObject", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("options", cel.MapType(cel.StringType, cel.DynType)),
		// Per-binding parameter overrides (RuntimeAlertRuleBindingRule.Parameters).
		// Rules can reference these as params["key"]. Always present (empty map
		// when no binding parameters apply) so expressions remain compilable.
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
		ext.Strings(),
		ext.Sets(),
		ext.Lists(),
		ext.Math(),
		ext.TwoVarComprehensions(),
		ext.Bindings(),
		ext.Encoders(),
		ext.Regex(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}
	return &AdmissionCEL{
		env:          env,
		programCache: make(map[string]cachedProgram),
	}, nil
}

// CreateEvalContext builds a map suitable for passing to program.Eval.
// The returned map is safe to reuse across sequential EvaluateRuleWithContext
// calls for the same event. The map fields (Object, OldObject, Options) are
// injected as separate top-level variables because cel-go's native type system
// does not support map[string]interface{} struct fields.
//
// The "params" key is initialized to an empty map. The evaluator overrides it
// with the active binding's parameters before evaluating each rule, so a
// single context can serve multiple rules with different parameter sets.
func (c *AdmissionCEL) CreateEvalContext(event *AdmissionCelEvent) map[string]any {
	ctx := map[string]any{
		"event":     event,
		"eventType": string(armotypes.EventTypeK8sAdmission),
		"params":    map[string]any{},
	}
	if event.Object != nil {
		ctx["object"] = event.Object
	} else {
		ctx["object"] = map[string]any{}
	}
	if event.OldObject != nil {
		ctx["oldObject"] = event.OldObject
	} else {
		ctx["oldObject"] = map[string]any{}
	}
	if event.Options != nil {
		ctx["options"] = event.Options
	} else {
		ctx["options"] = map[string]any{}
	}
	return ctx
}

// EvaluateRuleWithContext evaluates all expressions whose EventType matches the
// provided eventType. Returns true only when every matching expression
// evaluates to true (AND semantics). If no expressions match the provided
// eventType, returns false — the rule has no opinion for this event type, so
// it should not fire.
func (c *AdmissionCEL) EvaluateRuleWithContext(evalContext map[string]any, eventType armotypes.EventType, expressions []armotypes.RuleExpression) (bool, error) {
	matched := false
	for _, expr := range expressions {
		if expr.EventType != eventType {
			continue
		}
		matched = true

		out, err := c.evaluateProgram(expr.Expression, evalContext)
		if err != nil {
			return false, err
		}

		boolVal, ok := out.Value().(bool)
		if !ok {
			return false, fmt.Errorf("expression returned %T, expected bool", out.Value())
		}
		if !boolVal {
			return false, nil // short-circuit
		}
	}

	if !matched {
		return false, nil
	}
	return true, nil
}

// EvaluateStringExpression compiles and evaluates a CEL expression that is
// expected to return a string (e.g. a message template).
func (c *AdmissionCEL) EvaluateStringExpression(evalContext map[string]any, expression string) (string, error) {
	out, err := c.evaluateProgram(expression, evalContext)
	if err != nil {
		return "", err
	}
	strVal, ok := out.Value().(string)
	if !ok {
		return "", fmt.Errorf("expression returned %T, expected string", out.Value())
	}
	return strVal, nil
}

// ProgramCacheSize returns the number of entries in the program cache
// (including nil entries for compile failures).
func (c *AdmissionCEL) ProgramCacheSize() int {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	return len(c.programCache)
}

// RetainOnly drops every cached program whose expression is not in the
// provided active set. Call this from the rule sync path after replacing the
// rule list so programs compiled for now-removed rules are released — the
// cache grows monotonically otherwise.
//
// Passing nil or an empty slice clears the entire cache.
func (c *AdmissionCEL) RetainOnly(activeExpressions []string) {
	active := make(map[string]struct{}, len(activeExpressions))
	for _, expr := range activeExpressions {
		active[expr] = struct{}{}
	}

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	for expr := range c.programCache {
		if _, keep := active[expr]; !keep {
			delete(c.programCache, expr)
		}
	}
}

// evaluateProgram compiles (or retrieves from cache) and evaluates a CEL
// expression against the provided context. Cached compile failures are
// returned as errors on every call — never silently swallowed.
func (c *AdmissionCEL) evaluateProgram(expression string, evalContext map[string]any) (ref.Val, error) {
	prog, err := c.getOrCreateProgram(expression)
	if err != nil {
		return nil, err
	}

	out, _, err := prog.Eval(evalContext)
	if err != nil {
		return nil, fmt.Errorf("evaluating expression %q: %w", expression, err)
	}
	return out, nil
}

// getOrCreateProgram returns a cached program or compiles one. Compile errors
// are cached and re-returned on every subsequent call for the same expression:
// a broken rule should fail loudly on every event, not be silently ignored
// after the first attempt.
func (c *AdmissionCEL) getOrCreateProgram(expression string) (cel.Program, error) {
	c.cacheMu.RLock()
	if cp, exists := c.programCache[expression]; exists {
		c.cacheMu.RUnlock()
		return cp.prog, cp.err
	}
	c.cacheMu.RUnlock()

	return c.compileAndCache(expression)
}

func (c *AdmissionCEL) compileAndCache(expression string) (cel.Program, error) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// Double-check after acquiring write lock.
	if cp, exists := c.programCache[expression]; exists {
		return cp.prog, cp.err
	}

	ast, issues := c.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		err := fmt.Errorf("compiling expression %q: %w", expression, issues.Err())
		c.programCache[expression] = cachedProgram{err: err}
		return nil, err
	}

	prog, err := c.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		wrapped := fmt.Errorf("creating program for %q: %w", expression, err)
		c.programCache[expression] = cachedProgram{err: wrapped}
		return nil, wrapped
	}

	c.programCache[expression] = cachedProgram{prog: prog}
	return prog, nil
}
