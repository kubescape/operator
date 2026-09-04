package remediators

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// OperatorActionPatch is a generic Strategic Merge Patch / JSON Merge Patch
// action: the backend sends a targeted patch body instead of the full desired
// object. It is not yet part of armoapi-go's OperatorActionType enum, so it is
// defined locally as a plain string constant of that type — comparisons and
// map lookups against apis.OperatorActionType work the same either way.
const OperatorActionPatch apis.OperatorActionType = "patch"

// Patch type names accepted in Command.Args' "patchType" field. Strategic is
// the default when patchType is omitted.
const (
	PatchTypeStrategic = "strategic"
	PatchTypeMerge     = "merge"
)

// patchCaveat records the patch action's one operational precondition, echoed
// into every Plan's Description so it survives into the OperatorCommand status
// payload and the KubescapeRemediation audit event: a patch cannot be
// automatically reverted because the operator does not record pre-patch state.
const patchCaveat = "this patch cannot be automatically reverted (no prior state is recorded)"

// maxPatchBytes bounds the accepted patch body. A remediation patch touches a
// handful of fields (e.g. a seccompProfile); this is generous headroom while
// still bounding the JSON/YAML decode cost of a hostile payload.
const maxPatchBytes = 256 << 10 // 256 KiB

// escalationPaths are podSpec-relative field paths a remediation patch must
// never touch: each is independently sufficient to escalate from "patch a
// workload's config" to node/cluster compromise (host namespaces, host
// filesystem access via a hostPath volume, running as a different, possibly
// more privileged, ServiceAccount, or pinning the workload to an attacker-
// chosen node). This is defense-in-depth, not the primary control — the
// primary control is that only an authorized caller should be able to reach
// this action at all (RBAC on OperatorCommand / the trigger endpoint's own
// authorization, both outside this package's scope).
var escalationPaths = [][]string{
	{"hostNetwork"},
	{"hostPID"},
	{"hostIPC"},
	{"serviceAccountName"},
	{"serviceAccount"},
	{"volumes"},
	{"nodeName"},
}

// escalationMetadataPaths are metadata-relative field paths a remediation
// patch must never touch: a forged ownerReference lets a later garbage
// collection delete the workload, and a finalizer can block its deletion.
var escalationMetadataPaths = [][]string{
	{"ownerReferences"},
	{"finalizers"},
}

// patchTypeName maps a client-go patch media type back to the short vocabulary
// used in Command.Args and error messages ("strategic"/"merge"), so a single
// vocabulary is used throughout patch's user-visible strings.
func patchTypeName(t types.PatchType) string {
	switch t {
	case types.MergePatchType:
		return PatchTypeMerge
	default:
		return PatchTypeStrategic
	}
}

// validatePatchType resolves patchType to its default (Strategic Merge Patch)
// when empty and rejects anything other than the two types this action
// supports.
func validatePatchType(patchType types.PatchType) (types.PatchType, error) {
	if patchType == "" {
		patchType = types.StrategicMergePatchType
	}
	if patchType != types.StrategicMergePatchType && patchType != types.MergePatchType {
		return "", fmt.Errorf("patch: unsupported patchType %q (supported: %s, %s)", patchType, PatchTypeStrategic, PatchTypeMerge)
	}
	return patchType, nil
}

// PatchRemediator applies an arbitrary caller-supplied patch to a single
// workload. Unlike the other actions, the operator does not know the patch's
// semantics up front — it is opaque, backend-authored content — so Plan only
// validates shape (target kind/namespace, JSON/YAML well-formedness), and
// Revert cannot reconstruct the pre-patch state.
type PatchRemediator struct {
	client kubernetes.Interface
}

// NewPatchRemediator returns a patch remediator backed by client.
func NewPatchRemediator(client kubernetes.Interface) *PatchRemediator {
	return &PatchRemediator{client: client}
}

// Plan validates the target and patch payload and returns the canonical
// (JSON-encoded) patch body Apply would send.
func (r *PatchRemediator) Plan(ctx context.Context, req Request) (Plan, error) {
	if err := validateTarget(req.Target); err != nil {
		return Plan{}, err
	}
	if !IsNamespacedKind(req.Target.Kind) {
		return Plan{}, fmt.Errorf("patch: unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", req.Target.Kind)
	}

	patchType, err := validatePatchType(req.PatchType)
	if err != nil {
		return Plan{}, err
	}

	canonical, err := canonicalizePatch(req.Target.Kind, req.Patch)
	if err != nil {
		return Plan{}, fmt.Errorf("patch: invalid patch payload: %w", err)
	}

	return Plan{
		Action:      string(OperatorActionPatch),
		Target:      req.Target,
		Description: fmt.Sprintf("patch %s (%s); %s", req.Target, patchTypeName(patchType), patchCaveat),
		Patch:       canonical,
		PatchType:   string(patchType),
	}, nil
}

// Apply sends the planned patch. With dryRun=true it is a server-side dry-run
// (validated against admission, never persisted); only dryRun=false writes.
func (r *PatchRemediator) Apply(ctx context.Context, p Plan, dryRun bool) (Result, error) {
	if err := validateTarget(p.Target); err != nil {
		return Result{}, err
	}
	patchType, err := validatePatchType(types.PatchType(p.PatchType))
	if err != nil {
		return Result{}, err
	}
	if _, err := canonicalizePatch(p.Target.Kind, p.Patch); err != nil {
		return Result{}, fmt.Errorf("patch: invalid patch payload: %w", err)
	}

	opts := metav1.PatchOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	if err := r.patch(ctx, p.Target, patchType, []byte(p.Patch), opts); err != nil {
		return Result{}, err
	}
	return Result{
		Action:      p.Action,
		Target:      p.Target,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: p.Description,
		Patch:       p.Patch,
		PatchType:   p.PatchType,
	}, nil
}

// Revert is not supported for arbitrary patches: the operator does not record
// the pre-patch state, so there is nothing to reconstruct. Returning an error
// (rather than a silent no-op) keeps the audit trail honest about the fact
// that the target was not restored.
func (r *PatchRemediator) Revert(ctx context.Context, t Target, dryRun bool) (Result, error) {
	return Result{}, fmt.Errorf("patch: arbitrary patches on %s cannot be automatically reverted (no prior state is recorded)", t)
}

// patch applies a patch to the target object using the typed client for its
// kind, with the given patch type and options.
func (r *PatchRemediator) patch(ctx context.Context, t Target, patchType types.PatchType, patch []byte, opts metav1.PatchOptions) error {
	switch strings.ToLower(t.Kind) {
	case "deployment":
		_, err := r.client.AppsV1().Deployments(t.Namespace).Patch(ctx, t.Name, patchType, patch, opts)
		return err
	case "statefulset":
		_, err := r.client.AppsV1().StatefulSets(t.Namespace).Patch(ctx, t.Name, patchType, patch, opts)
		return err
	case "daemonset":
		_, err := r.client.AppsV1().DaemonSets(t.Namespace).Patch(ctx, t.Name, patchType, patch, opts)
		return err
	case "pod":
		_, err := r.client.CoreV1().Pods(t.Namespace).Patch(ctx, t.Name, patchType, patch, opts)
		return err
	default:
		return fmt.Errorf("patch: unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", t.Kind)
	}
}

// canonicalizePatch validates that raw is a well-formed, size-bounded JSON or
// YAML object that does not touch an escalation-relevant field for the given
// target kind, and returns its canonical JSON encoding. A patch body must be
// an object (not a scalar or array): Strategic Merge Patch and JSON Merge
// Patch are both object-shaped (unlike RFC 6902 JSON Patch, which this action
// does not support).
func canonicalizePatch(kind, raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("patch is empty")
	}
	if len(trimmed) > maxPatchBytes {
		return "", fmt.Errorf("patch is too large (%d bytes, max %d)", len(trimmed), maxPatchBytes)
	}
	// YAML is a JSON superset, so this also accepts plain JSON input without
	// needing to sniff the format first.
	jsonBytes, err := yaml.YAMLToJSON([]byte(trimmed))
	if err != nil {
		return "", err
	}
	var obj map[string]any
	if err := json.Unmarshal(jsonBytes, &obj); err != nil {
		return "", fmt.Errorf("patch must be a JSON/YAML object: %w", err)
	}
	// json.Unmarshal accepts a literal "null" (or YAML "~") into a nil map
	// without error, which would otherwise be applied as a guaranteed no-op
	// reported as Applied: true.
	if len(obj) == 0 {
		return "", fmt.Errorf("patch must be a non-empty JSON/YAML object")
	}
	if err := rejectEscalation(kind, obj); err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// podSpecPath is the patch-relative path to the pod spec for kind: nested
// under spec.template.spec for the three controller kinds, or spec directly
// for a bare Pod.
func podSpecPath(kind string) []string {
	if strings.EqualFold(kind, "pod") {
		return []string{"spec"}
	}
	return []string{"spec", "template", "spec"}
}

// rejectEscalation rejects a patch that touches a field this action treats as
// escalation-relevant (see escalationPaths/escalationMetadataPaths), at either
// the pod-spec level (hostNetwork, volumes, serviceAccountName, ...) or the
// container level (privileged, added capabilities, image).
func rejectEscalation(kind string, obj map[string]any) error {
	for _, p := range escalationMetadataPaths {
		if hasPath(obj, append([]string{"metadata"}, p...)) {
			return fmt.Errorf("patch: field %q is not allowed in a remediation patch", "metadata."+strings.Join(p, "."))
		}
	}
	podSpec := podSpecPath(kind)
	for _, p := range escalationPaths {
		if hasPath(obj, append(append([]string{}, podSpec...), p...)) {
			return fmt.Errorf("patch: field %q is not allowed in a remediation patch", strings.Join(podSpec, ".")+"."+strings.Join(p, "."))
		}
	}
	for _, containersField := range []string{"containers", "initContainers"} {
		containers, ok := valueAtPath(obj, append(append([]string{}, podSpec...), containersField))
		if !ok {
			continue
		}
		list, ok := containers.([]any)
		if !ok {
			continue
		}
		for _, c := range list {
			container, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if err := rejectContainerEscalation(container); err != nil {
				return err
			}
		}
	}
	return nil
}

// rejectContainerEscalation rejects an image change (a remediation patch
// fixes configuration, not workload content) and container-level
// securityContext escalations (privileged, added capabilities, or explicitly
// enabling privilege escalation).
func rejectContainerEscalation(container map[string]any) error {
	if _, ok := container["image"]; ok {
		return fmt.Errorf("patch: field \"image\" is not allowed in a remediation patch")
	}
	sc, ok := container["securityContext"].(map[string]any)
	if !ok {
		return nil
	}
	if privileged, ok := sc["privileged"].(bool); ok && privileged {
		return fmt.Errorf("patch: securityContext.privileged=true is not allowed in a remediation patch")
	}
	if allowEscalation, ok := sc["allowPrivilegeEscalation"].(bool); ok && allowEscalation {
		return fmt.Errorf("patch: securityContext.allowPrivilegeEscalation=true is not allowed in a remediation patch")
	}
	if capabilities, ok := sc["capabilities"].(map[string]any); ok {
		if _, ok := capabilities["add"]; ok {
			return fmt.Errorf("patch: securityContext.capabilities.add is not allowed in a remediation patch")
		}
	}
	return nil
}

// hasPath reports whether path resolves to any value (including null) in m.
func hasPath(m map[string]any, path []string) bool {
	_, ok := valueAtPath(m, path)
	return ok
}

// valueAtPath walks path through nested maps and returns the value found at
// its end, if any. It stops (returning false) as soon as an intermediate
// segment is missing or is not itself a map.
func valueAtPath(m map[string]any, path []string) (any, bool) {
	cur := m
	for i, k := range path {
		v, ok := cur[k]
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			return v, true
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return nil, false
}
