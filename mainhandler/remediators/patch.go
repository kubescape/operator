package remediators

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

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

	liveSpec, _, err := r.getLivePodSpecAndResourceVersion(ctx, req.Target)
	if err != nil && !apierrors.IsNotFound(err) {
		return Plan{}, fmt.Errorf("patch: reading live target: %w", err)
	}
	if liveSpec != nil {
		if err := validateLivePodCapabilities(req.Target.Kind, liveSpec, canonical); err != nil {
			return Plan{}, err
		}
	}

	return Plan{
		Action:      string(apis.OperatorActionPatch),
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
	canonicalPatch, err := canonicalizePatch(p.Target.Kind, p.Patch)
	if err != nil {
		return Result{}, fmt.Errorf("patch: invalid patch payload: %w", err)
	}

	liveSpec, liveRV, err := r.getLivePodSpecAndResourceVersion(ctx, p.Target)
	if err != nil {
		return Result{}, fmt.Errorf("patch: reading live target: %w", err)
	}
	if liveSpec != nil {
		if err := validateLivePodCapabilities(p.Target.Kind, liveSpec, canonicalPatch); err != nil {
			return Result{}, err
		}
	}

	patchToSend, err := withResourceVersionPrecondition(canonicalPatch, liveRV)
	if err != nil {
		return Result{}, err
	}

	opts := metav1.PatchOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	if err := r.patch(ctx, p.Target, patchType, []byte(patchToSend), opts); err != nil {
		return Result{}, err
	}
	return Result{
		Action:      p.Action,
		Target:      p.Target,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: p.Description,
		Patch:       patchToSend,
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
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return "", fmt.Errorf("patch must be a JSON/YAML object: %w", err)
	}
	if dec.More() {
		return "", fmt.Errorf("patch must contain exactly one JSON/YAML object")
	}
	// json.Unmarshal/Decode accepts a literal "null" (or YAML "~") into a nil map
	// without error, which would otherwise be applied as a guaranteed no-op
	// reported as Applied: true.
	if len(obj) == 0 {
		return "", fmt.Errorf("patch must be a non-empty JSON/YAML object")
	}
	if err := rejectEscalation(kind, obj); err != nil {
		return "", err
	}
	canonicalizeCapabilitiesDrop(kind, obj)
	canonBytes, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(canonBytes), nil
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
// container level (privileged, added capabilities, image). It also rejects
// strategic-merge patch directives ($-prefixed keys such as $patch or
// $retainKeys) on pod-spec and container ancestors that could replace or clear
// securityContext or other protected settings.
func rejectEscalation(kind string, obj map[string]any) error {
	for _, p := range escalationMetadataPaths {
		if hasPath(obj, append([]string{"metadata"}, p...)) {
			return fmt.Errorf("patch: field %q is not allowed in a remediation patch", "metadata."+strings.Join(p, "."))
		}
	}
	podSpec := podSpecPath(kind)
	for i := 1; i <= len(podSpec); i++ {
		prefix := podSpec[:i]
		if val, ok := valueAtPath(obj, prefix); ok {
			if m, ok := val.(map[string]any); ok {
				for key := range m {
					if strings.HasPrefix(key, "$") {
						return fmt.Errorf("patch: pod spec directive %q is not allowed in a remediation patch", key)
					}
				}
			}
		}
	}
	if podSpecVal, ok := valueAtPath(obj, podSpec); ok {
		if podSpecMap, ok := podSpecVal.(map[string]any); ok {
			if pscVal, ok := podSpecMap["securityContext"]; ok {
				if psc, ok := pscVal.(map[string]any); ok {
					if d, found := hasDirective(psc); found {
						return fmt.Errorf("patch: securityContext directive %q is not allowed in a remediation patch", d)
					}
				}
			}
		}
	}
	for _, p := range escalationPaths {
		if hasPath(obj, append(append([]string{}, podSpec...), p...)) {
			return fmt.Errorf("patch: field %q is not allowed in a remediation patch", strings.Join(podSpec, ".")+"."+strings.Join(p, "."))
		}
	}
	if podSpecVal, ok := valueAtPath(obj, podSpec); ok {
		if podSpecMap, ok := podSpecVal.(map[string]any); ok {
			if err := rejectPodSecurityContextEscalation(podSpecMap, strings.Join(podSpec, ".")); err != nil {
				return err
			}
		}
	}
	// ephemeralContainers shares the container escalation checks. The API server
	// only accepts them through the pods/ephemeralcontainers subresource (never
	// a strategic/merge patch of the object), so this is defense-in-depth that
	// keeps the denylist complete rather than relying on that server-side rule.
	for _, containersField := range []string{"containers", "initContainers", "ephemeralContainers"} {
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
// fixes configuration, not workload content), container-level
// securityContext escalations (privileged, added capabilities, or explicitly
// enabling privilege escalation), and root-execution configurations
// (runAsUser: 0 or runAsNonRoot: false).
//
// Under a JSON Merge Patch, a field set to null deletes that field from the
// live object rather than setting it to null — so nulling out an explicit
// allowPrivilegeEscalation: false (or the whole securityContext) reverts the
// container to its unset/permissive default just as effectively as setting
// the field to true would. A plain `sc["x"].(bool)` type assertion silently
// lets that through (a JSON null decodes to a Go nil, which fails the
// assertion with ok=false), so presence-with-null is checked explicitly for
// every field this function protects, not just its value.
//
// Similarly, strategic-merge patch directives (such as "$patch": "replace",
// "$patch": "delete", or "$retainKeys") inside securityContext or on the
// container itself can replace or clear the map without naming protected
// fields, dropping existing protections (like runAsUser or runAsNonRoot).
// Any $-prefixed directive keys are therefore rejected.
func rejectContainerEscalation(container map[string]any) error {
	for key := range container {
		if strings.HasPrefix(key, "$") {
			return fmt.Errorf("patch: container directive %q is not allowed in a remediation patch", key)
		}
	}

	if _, ok := container["image"]; ok {
		return fmt.Errorf("patch: field \"image\" is not allowed in a remediation patch")
	}

	scVal, scPresent := container["securityContext"]
	if !scPresent {
		return nil
	}
	if scVal == nil {
		return fmt.Errorf("patch: securityContext=null is not allowed in a remediation patch")
	}
	sc, ok := scVal.(map[string]any)
	if !ok {
		return nil
	}
	if d, found := hasDirective(sc); found {
		return fmt.Errorf("patch: securityContext directive %q is not allowed in a remediation patch", d)
	}
	if privileged, ok := sc["privileged"].(bool); ok && privileged {
		return fmt.Errorf("patch: securityContext.privileged=true is not allowed in a remediation patch")
	}
	if v, present := sc["allowPrivilegeEscalation"]; present {
		if v == nil {
			return fmt.Errorf("patch: securityContext.allowPrivilegeEscalation=null is not allowed in a remediation patch")
		}
		if b, ok := v.(bool); ok && b {
			return fmt.Errorf("patch: securityContext.allowPrivilegeEscalation=true is not allowed in a remediation patch")
		}
	}
	if v, present := sc["capabilities"]; present {
		if v == nil {
			return fmt.Errorf("patch: securityContext.capabilities=null is not allowed in a remediation patch")
		}
		if capabilities, ok := v.(map[string]any); ok {
			if _, ok := capabilities["add"]; ok {
				return fmt.Errorf("patch: securityContext.capabilities.add is not allowed in a remediation patch")
			}
			// The drop list is replaced whole under either patch type, so a
			// null (deleted) or empty drop gives back every capability the
			// container dropped, just as capabilities: null does.
			if drop, present := capabilities["drop"]; present {
				if list, ok := drop.([]any); drop == nil || (ok && len(list) == 0) {
					return fmt.Errorf("patch: an empty or null securityContext.capabilities.drop is not allowed in a remediation patch")
				}
			}
		}
	}
	// A container's runAsGroup and seLinuxOptions take precedence over the pod's,
	// so they are refused here for the same reasons the pod-level check
	// (rejectPodSecurityContextEscalation) refuses them.
	for _, idField := range []string{"runAsUser", "runAsGroup"} {
		if v, present := sc[idField]; present {
			if v == nil {
				return fmt.Errorf("patch: securityContext.%s=null is not allowed in a remediation patch", idField)
			}
			if isZeroUID(v) {
				return fmt.Errorf("patch: securityContext.%s=0 is not allowed in a remediation patch", idField)
			}
		}
	}
	if _, present := sc["seLinuxOptions"]; present {
		return fmt.Errorf("patch: securityContext.seLinuxOptions is not allowed in a remediation patch")
	}
	if v, present := sc["runAsNonRoot"]; present {
		if v == nil {
			return fmt.Errorf("patch: securityContext.runAsNonRoot=null is not allowed in a remediation patch")
		}
		if b, ok := v.(bool); ok && !b {
			return fmt.Errorf("patch: securityContext.runAsNonRoot=false is not allowed in a remediation patch")
		}
	}
	return rejectUnconfinedProfiles(sc, "securityContext.")
}

// rejectUnconfinedProfiles refuses a seccompProfile or appArmorProfile that a patch
// sets to Unconfined, or deletes (null), which leaves the workload without the
// profile it had: the kubelet's default for seccomp is Unconfined unless it runs with
// --seccomp-default. The Pod Security Standards' baseline level does not allow
// either profile to be Unconfined. RuntimeDefault and Localhost are left to the patch.
// prefix is the path of the securityContext the profiles are in, for the error.
func rejectUnconfinedProfiles(sc map[string]any, prefix string) error {
	for _, name := range []string{"seccompProfile", "appArmorProfile"} {
		v, present := sc[name]
		if !present {
			continue
		}
		if v == nil {
			return fmt.Errorf("patch: field %q=null is not allowed in a remediation patch", prefix+name)
		}
		if profile, ok := v.(map[string]any); ok {
			if t, ok := profile["type"].(string); ok && t == "Unconfined" {
				return fmt.Errorf("patch: field %q=Unconfined is not allowed in a remediation patch", prefix+name+".type")
			}
		}
	}
	return nil
}

func isZeroUID(v any) bool {
	switch val := v.(type) {
	case float64:
		return val == 0
	case float32:
		return val == 0
	case int:
		return val == 0
	case int64:
		return val == 0
	case int32:
		return val == 0
	case uint:
		return val == 0
	case uint64:
		return val == 0
	case uint32:
		return val == 0
	case json.Number:
		n, err := val.Int64()
		return err == nil && n == 0
	case string:
		return strings.TrimSpace(val) == "0"
	default:
		return false
	}
}

// hasDirective reports whether m or any nested map contains a key prefixed
// with "$", which indicates a strategic-merge patch directive (e.g. $patch,
// $retainKeys). If found, it returns the directive key.
func hasDirective(m map[string]any) (string, bool) {
	for k, v := range m {
		if strings.HasPrefix(k, "$") {
			return k, true
		}
		if nested, ok := v.(map[string]any); ok {
			if d, found := hasDirective(nested); found {
				return d, true
			}
		}
	}
	return "", false
}

// rejectPodSecurityContextEscalation rejects a patch to the pod-level
// securityContext that would relax the workload's run-as identity or its
// mandatory-access-control confinement. specPath is the patch-relative pod-spec
// path, used only to build a readable error (e.g. "spec.template.spec").
//
// Only escalating values are rejected, so legitimate hardening patches still
// apply: runAsNonRoot: true, a non-root runAsUser/runAsGroup, and
// seccompProfile.type: RuntimeDefault are all accepted. As with the
// container-level checks, a field set to null is treated as a deletion (JSON
// Merge Patch semantics) that reverts the live object to its permissive
// default, and is rejected for the fields this guards. Strategic-merge $-prefixed
// directives on the block are already rejected by rejectEscalation.
//
// sysctls are deliberately NOT rejected: the kubelet already enforces an
// unsafe-sysctl allowlist, so a patch cannot set a dangerous sysctl this way,
// and blocking safe sysctls would needlessly break legitimate tuning.
func rejectPodSecurityContextEscalation(spec map[string]any, specPath string) error {
	scVal, present := spec["securityContext"]
	if !present {
		return nil
	}
	field := func(name string) string { return specPath + ".securityContext." + name }
	if scVal == nil {
		return fmt.Errorf("patch: field %q=null is not allowed in a remediation patch", specPath+".securityContext")
	}
	sc, ok := scVal.(map[string]any)
	if !ok {
		return nil
	}
	if v, present := sc["runAsNonRoot"]; present {
		if v == nil {
			return fmt.Errorf("patch: field %q=null is not allowed in a remediation patch", field("runAsNonRoot"))
		}
		if b, ok := v.(bool); ok && !b {
			return fmt.Errorf("patch: field %q=false is not allowed in a remediation patch", field("runAsNonRoot"))
		}
	}
	for _, idField := range []string{"runAsUser", "runAsGroup"} {
		if v, present := sc[idField]; present {
			if v == nil {
				return fmt.Errorf("patch: field %q=null is not allowed in a remediation patch", field(idField))
			}
			if isZeroUID(v) {
				return fmt.Errorf("patch: field %q=0 (root) is not allowed in a remediation patch", field(idField))
			}
		}
	}
	// seLinuxOptions can select a less-confined domain (e.g. an unconfined or
	// spc_t type) and so weaken mandatory-access-control confinement; the
	// operator cannot tell a hardening change from a weakening one, so the whole
	// field is rejected, consistent with how volumes/serviceAccount are handled.
	if _, present := sc["seLinuxOptions"]; present {
		return fmt.Errorf("patch: field %q is not allowed in a remediation patch", field("seLinuxOptions"))
	}
	return rejectUnconfinedProfiles(sc, specPath+".securityContext.")
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

// getLivePodSpecAndResourceVersion retrieves the live PodSpec and ResourceVersion
// for the target object from the cluster. If r.client is nil, it returns nil, "", nil.
func (r *PatchRemediator) getLivePodSpecAndResourceVersion(ctx context.Context, t Target) (*corev1.PodSpec, string, error) {
	if r.client == nil {
		return nil, "", nil
	}
	switch strings.ToLower(t.Kind) {
	case "deployment":
		o, err := r.client.AppsV1().Deployments(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, "", err
		}
		return &o.Spec.Template.Spec, o.ResourceVersion, nil
	case "statefulset":
		o, err := r.client.AppsV1().StatefulSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, "", err
		}
		return &o.Spec.Template.Spec, o.ResourceVersion, nil
	case "daemonset":
		o, err := r.client.AppsV1().DaemonSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, "", err
		}
		return &o.Spec.Template.Spec, o.ResourceVersion, nil
	case "pod":
		o, err := r.client.CoreV1().Pods(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, "", err
		}
		return &o.Spec, o.ResourceVersion, nil
	default:
		return nil, "", fmt.Errorf("patch: unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", t.Kind)
	}
}

// getLivePodSpec retrieves the live PodSpec for the target object from the cluster.
// If r.client is nil, it returns nil, nil.
func (r *PatchRemediator) getLivePodSpec(ctx context.Context, t Target) (*corev1.PodSpec, error) {
	spec, _, err := r.getLivePodSpecAndResourceVersion(ctx, t)
	return spec, err
}

// withResourceVersionPrecondition injects metadata.resourceVersion into the
// canonical patch JSON as an optimistic concurrency precondition. If the patch
// already specifies a resourceVersion that differs from liveRV, it returns an
// error; if it matches or if liveRV is empty, it returns the patch unchanged.
func withResourceVersionPrecondition(patchJSON string, liveRV string) (string, error) {
	if liveRV == "" {
		return patchJSON, nil
	}
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(patchJSON))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return "", fmt.Errorf("patch: unmarshaling patch for resourceVersion precondition: %w", err)
	}
	if mdVal, ok := obj["metadata"]; ok {
		if md, ok := mdVal.(map[string]any); ok {
			if rvVal, ok := md["resourceVersion"]; ok {
				if rvStr, ok := rvVal.(string); ok && rvStr != "" {
					if rvStr != liveRV {
						return "", fmt.Errorf("patch: resourceVersion %q in patch does not match live object resourceVersion %q", rvStr, liveRV)
					}
					return patchJSON, nil
				}
			}
			md["resourceVersion"] = liveRV
			b, err := json.Marshal(obj)
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
	}
	if obj == nil {
		obj = make(map[string]any)
	}
	obj["metadata"] = map[string]any{
		"resourceVersion": liveRV,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// validateLivePodCapabilities ensures that the patch does not drop fewer
// capabilities than any existing container in the live object already drops.
func validateLivePodCapabilities(kind string, liveSpec *corev1.PodSpec, patchJSON string) error {
	if liveSpec == nil {
		return nil
	}
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(patchJSON))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return err
	}
	podSpec := podSpecPath(kind)
	for _, containersField := range []string{"containers", "initContainers", "ephemeralContainers"} {
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
			name, _ := container["name"].(string)
			liveSC := findLiveSecurityContext(liveSpec, containersField, name)
			if err := rejectCapabilitiesDropNarrowing(name, liveSC, container); err != nil {
				return err
			}
		}
	}
	return nil
}

// findLiveSecurityContext looks up the securityContext of a container by name
// in the live PodSpec's containers, initContainers, or ephemeralContainers list.
func findLiveSecurityContext(spec *corev1.PodSpec, listField, name string) *corev1.SecurityContext {
	if spec == nil {
		return nil
	}
	switch listField {
	case "containers":
		if name == "" && len(spec.Containers) == 1 {
			return spec.Containers[0].SecurityContext
		}
		for i := range spec.Containers {
			if spec.Containers[i].Name == name {
				return spec.Containers[i].SecurityContext
			}
		}
	case "initContainers":
		if name == "" && len(spec.InitContainers) == 1 {
			return spec.InitContainers[0].SecurityContext
		}
		for i := range spec.InitContainers {
			if spec.InitContainers[i].Name == name {
				return spec.InitContainers[i].SecurityContext
			}
		}
	case "ephemeralContainers":
		if name == "" && len(spec.EphemeralContainers) == 1 {
			return spec.EphemeralContainers[0].SecurityContext
		}
		for i := range spec.EphemeralContainers {
			if spec.EphemeralContainers[i].Name == name {
				return spec.EphemeralContainers[i].SecurityContext
			}
		}
	}
	return nil
}

// canonicalizeCapabilitiesDrop canonicalizes capability drop names to their
// standard uppercase, prefix-stripped forms (e.g. "CAP_NET_RAW" -> "NET_RAW",
// "all" -> "ALL") so that emitted patches use canonical Kubernetes names that
// container runtimes match reliably.
func canonicalizeCapabilitiesDrop(kind string, obj map[string]any) {
	podSpec := podSpecPath(kind)
	for _, containersField := range []string{"containers", "initContainers", "ephemeralContainers"} {
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
			scVal, scPresent := container["securityContext"]
			if !scPresent || scVal == nil {
				continue
			}
			sc, ok := scVal.(map[string]any)
			if !ok {
				continue
			}
			capVal, capPresent := sc["capabilities"]
			if !capPresent || capVal == nil {
				continue
			}
			capabilities, ok := capVal.(map[string]any)
			if !ok {
				continue
			}
			dropVal, dropPresent := capabilities["drop"]
			if !dropPresent || dropVal == nil {
				continue
			}
			rawDrops, ok := dropVal.([]any)
			if !ok {
				continue
			}
			canonicalDrops := make([]any, 0, len(rawDrops))
			for _, d := range rawDrops {
				s, ok := d.(string)
				if !ok {
					canonicalDrops = append(canonicalDrops, d)
					continue
				}
				canonicalDrops = append(canonicalDrops, normalizeCapability(s))
			}
			capabilities["drop"] = canonicalDrops
		}
	}
}

// normalizeCapability returns a canonical uppercase capability name stripped of
// any "CAP_" prefix, preserving "ALL" as "ALL".
func normalizeCapability(c string) string {
	upper := strings.ToUpper(strings.TrimSpace(c))
	if upper == "ALL" {
		return "ALL"
	}
	return strings.TrimPrefix(upper, "CAP_")
}

// rejectCapabilitiesDropNarrowing checks whether patchContainer defines a drop
// list that drops fewer capabilities than liveSC already drops.
func rejectCapabilitiesDropNarrowing(containerName string, liveSC *corev1.SecurityContext, patchContainer map[string]any) error {
	if liveSC == nil || liveSC.Capabilities == nil || len(liveSC.Capabilities.Drop) == 0 {
		return nil
	}
	scVal, scPresent := patchContainer["securityContext"]
	if !scPresent || scVal == nil {
		return nil
	}
	sc, ok := scVal.(map[string]any)
	if !ok {
		return nil
	}
	capVal, capPresent := sc["capabilities"]
	if !capPresent || capVal == nil {
		return nil
	}
	capabilities, ok := capVal.(map[string]any)
	if !ok {
		return nil
	}
	dropVal, dropPresent := capabilities["drop"]
	if !dropPresent || dropVal == nil {
		return nil
	}
	rawDrops, ok := dropVal.([]any)
	if !ok {
		return nil
	}

	displayName := containerName
	if displayName == "" {
		displayName = "<anonymous>"
	}

	var patchDrops []string
	patchHasAll := false
	for _, d := range rawDrops {
		s, ok := d.(string)
		if !ok {
			continue
		}
		norm := normalizeCapability(s)
		if norm == "ALL" {
			patchHasAll = true
		}
		patchDrops = append(patchDrops, norm)
	}

	// If the patch drops ALL, every capability is dropped — no narrowing occurs.
	if patchHasAll {
		return nil
	}

	liveDrops := make(map[string]struct{}, len(liveSC.Capabilities.Drop))
	liveHasAll := false
	for _, d := range liveSC.Capabilities.Drop {
		norm := normalizeCapability(string(d))
		if norm == "ALL" {
			liveHasAll = true
		}
		liveDrops[norm] = struct{}{}
	}

	// If the live container dropped ALL, any replacement drop list that does not include ALL narrows it.
	if liveHasAll {
		return fmt.Errorf("patch: container %q narrows dropped capabilities: live container drops ALL, but patch drop list does not include ALL", displayName)
	}

	patchDropSet := make(map[string]struct{}, len(patchDrops))
	for _, p := range patchDrops {
		patchDropSet[p] = struct{}{}
	}

	for liveCap := range liveDrops {
		if _, found := patchDropSet[liveCap]; !found {
			return fmt.Errorf("patch: container %q narrows dropped capabilities: live container drops %q, which is missing from patch drop list", displayName, liveCap)
		}
	}

	return nil
}
