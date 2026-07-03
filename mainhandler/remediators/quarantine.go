package remediators

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// LabelQuarantine marks the deny-all NetworkPolicy created by the quarantine
	// action, so it can be found and removed on revert.
	LabelQuarantine = "kubescape.io/quarantine"
	// AnnotationQuarantineTarget records, on the NetworkPolicy, the workload it
	// isolates — part of the audit trail.
	AnnotationQuarantineTarget = "kubescape.io/quarantine-target"

	// quarantineNPPrefix is the deterministic name prefix of the deny-all
	// NetworkPolicy, so revert can locate it from the target name alone.
	quarantineNPPrefix = "kubescape-quarantine-"
	// maxNameLen is the Kubernetes object-name length limit.
	maxNameLen = 253

	// quarantineCaveat records the two operational preconditions of a deny-all
	// NetworkPolicy in the plan/result audit trail: it is enforced only by a CNI
	// that implements NetworkPolicy (on a non-enforcing CNI the policy is created
	// but silently does nothing), and it isolates every pod matching the
	// workload's selector labels, which can be broader than the target itself when
	// other workloads share those labels.
	quarantineCaveat = "isolation is enforced only by a NetworkPolicy-capable CNI and applies to all pods matching the selector"
)

// QuarantineRemediator isolates a workload by creating a deny-all NetworkPolicy
// that selects the workload's pods (both ingress and egress denied). It does
// not mutate or recreate the pods, so container state is preserved for forensic
// investigation (the design's resolved default; scale-to-zero is a future,
// explicit opt-in). Revert deletes the NetworkPolicy.
//
// Isolation semantics and preconditions (surfaced in the plan/result via
// quarantineCaveat):
//   - CNI enforcement: a NetworkPolicy only isolates traffic on a CNI that
//     enforces NetworkPolicy. On a non-enforcing CNI the policy is created but
//     has no effect; the action still reports success because the desired object
//     was applied — enforcement is a cluster property the operator cannot verify.
//   - Blast radius: the policy selects by the workload's selector labels, so it
//     isolates every pod matching them — including pods owned by other workloads
//     that reuse the same labels (blue/green, canary, a second Deployment reusing
//     "app="). Quarantine assumes the selector identifies the intended pods.
//   - Pod targets: a NetworkPolicy selects pods by label, not by name. A
//     controller-managed pod's labels are shared by every replica of its template
//     (pod-template-hash, etc.), so quarantining a Pod isolates the whole
//     ReplicaSet/template, not the single named pod. Single-pod isolation is not
//     achievable with a NetworkPolicy.
type QuarantineRemediator struct {
	client kubernetes.Interface
}

// NewQuarantineRemediator returns a quarantine remediator backed by client.
func NewQuarantineRemediator(client kubernetes.Interface) *QuarantineRemediator {
	return &QuarantineRemediator{client: client}
}

// Plan reads the target workload's pod selector from the live object and
// computes the deny-all NetworkPolicy without creating it.
func (r *QuarantineRemediator) Plan(ctx context.Context, req Request) (Plan, error) {
	if err := validateTarget(req.Target); err != nil {
		return Plan{}, err
	}
	selector, err := r.resolvePodSelector(ctx, req.Target)
	if err != nil {
		return Plan{}, err
	}
	np := r.buildNetworkPolicy(req, selector)
	body, err := json.Marshal(np)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		Action:      string(apis.OperatorActionQuarantine),
		Target:      req.Target,
		Description: fmt.Sprintf("deny-all NetworkPolicy %q isolating %s (podSelector %s); %s", np.Name, req.Target, metav1.FormatLabelSelector(selector), quarantineCaveat),
		Patch:       string(body),
	}, nil
}

// Apply creates the planned deny-all NetworkPolicy. With dryRun=true it is sent
// as a server-side dry-run (validated against admission, never persisted); only
// dryRun=false performs a real write. If a policy already exists (a prior
// quarantine), it is reconciled to the freshly planned spec so that a selector
// that drifted since the first quarantine (the workload was edited/redeployed)
// still isolates the currently-running pods, rather than leaving a stale policy
// in place while reporting success.
func (r *QuarantineRemediator) Apply(ctx context.Context, p Plan, dryRun bool) (Result, error) {
	var np networkingv1.NetworkPolicy
	if err := json.Unmarshal([]byte(p.Patch), &np); err != nil {
		return Result{}, fmt.Errorf("quarantine: failed to decode planned NetworkPolicy: %w", err)
	}
	opts := metav1.CreateOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	_, err := r.client.NetworkingV1().NetworkPolicies(np.Namespace).Create(ctx, &np, opts)
	switch {
	case err == nil:
		// created — the workload is now isolated.
	case apierrors.IsAlreadyExists(err):
		// A prior quarantine policy exists; reconcile it to the planned spec so a
		// drifted selector does not silently leave the running pods unisolated.
		if err := r.reconcile(ctx, &np, dryRun); err != nil {
			return Result{}, err
		}
	default:
		return Result{}, fmt.Errorf("quarantine: failed to create NetworkPolicy %q: %w", np.Name, err)
	}
	return Result{
		Action:      p.Action,
		Target:      p.Target,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: p.Description,
	}, nil
}

// reconcile brings an already-existing quarantine NetworkPolicy in line with the
// desired spec, updating it when the selector or audit metadata drifted since it
// was created. An identical policy is left untouched (nothing to do). A policy
// that vanished between the failed Create and this Get (raced with a revert) is
// a clean no-op.
func (r *QuarantineRemediator) reconcile(ctx context.Context, desired *networkingv1.NetworkPolicy, dryRun bool) error {
	existing, err := r.client.NetworkingV1().NetworkPolicies(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("quarantine: failed to read existing NetworkPolicy %q: %w", desired.Name, err)
	}
	if reflect.DeepEqual(existing.Spec, desired.Spec) &&
		reflect.DeepEqual(existing.Labels, desired.Labels) &&
		reflect.DeepEqual(existing.Annotations, desired.Annotations) {
		return nil // already isolating the current pods.
	}
	existing.Spec = desired.Spec
	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations
	opts := metav1.UpdateOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	if _, err := r.client.NetworkingV1().NetworkPolicies(desired.Namespace).Update(ctx, existing, opts); err != nil {
		return fmt.Errorf("quarantine: failed to reconcile NetworkPolicy %q: %w", desired.Name, err)
	}
	return nil
}

// Revert deletes the deny-all NetworkPolicy that quarantined the target. A
// missing policy is treated as success (nothing to undo). Like Apply, dryRun=true
// issues a server-side dry-run delete, so the safe-by-default contract holds for
// revert too.
func (r *QuarantineRemediator) Revert(ctx context.Context, t Target, dryRun bool) (Result, error) {
	if err := validateTarget(t); err != nil {
		return Result{}, err
	}
	name := quarantineNPName(t)
	opts := metav1.DeleteOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	err := r.client.NetworkingV1().NetworkPolicies(t.Namespace).Delete(ctx, name, opts)
	applied := !dryRun
	desc := fmt.Sprintf("deleted quarantine NetworkPolicy %q in namespace %q", name, t.Namespace)
	switch {
	case apierrors.IsNotFound(err):
		applied = false
		desc = fmt.Sprintf("no quarantine NetworkPolicy %q in namespace %q; nothing to revert", name, t.Namespace)
	case err != nil:
		return Result{}, fmt.Errorf("quarantine: failed to delete NetworkPolicy %q: %w", name, err)
	}
	return Result{
		Action:      string(apis.OperatorActionRevert),
		Target:      t,
		DryRun:      dryRun,
		Applied:     applied,
		Description: desc,
	}, nil
}

// resolvePodSelector returns the label selector that selects the target's
// running pods, read from the live object so quarantine isolates the existing
// pods without recreating them. The full selector (both matchLabels and
// matchExpressions) is preserved so workloads using set-based selectors are
// isolated correctly.
func (r *QuarantineRemediator) resolvePodSelector(ctx context.Context, t Target) (*metav1.LabelSelector, error) {
	var selector *metav1.LabelSelector
	switch strings.ToLower(t.Kind) {
	case "deployment":
		o, err := r.client.AppsV1().Deployments(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		selector = o.Spec.Selector
	case "statefulset":
		o, err := r.client.AppsV1().StatefulSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		selector = o.Spec.Selector
	case "daemonset":
		o, err := r.client.AppsV1().DaemonSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		selector = o.Spec.Selector
	case "pod":
		o, err := r.client.CoreV1().Pods(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		// The pod's full label set is used as the selector. For a
		// controller-managed pod those labels (pod-template-hash, etc.) are shared
		// by every replica of the template, so this isolates the whole
		// ReplicaSet/template — a NetworkPolicy cannot select one pod by name. See
		// the type doc for the isolation-semantics rationale.
		selector = &metav1.LabelSelector{MatchLabels: o.Labels}
	default:
		return nil, fmt.Errorf("quarantine: unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", t.Kind)
	}
	if selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0) {
		return nil, fmt.Errorf("quarantine: %s has no pod selector labels to isolate; cannot build a NetworkPolicy", t)
	}
	return selector, nil
}

// buildNetworkPolicy assembles the deny-all NetworkPolicy: it selects the
// target's pods and declares both policy types with no allow rules, which denies
// all ingress and egress. Audit context is recorded in its labels/annotations.
func (r *QuarantineRemediator) buildNetworkPolicy(req Request, selector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	annotations := map[string]string{AnnotationQuarantineTarget: req.Target.String()}
	if req.Reason != "" {
		annotations[AnnotationReason] = req.Reason
	}
	if req.FindingRef != "" {
		annotations[AnnotationFindingRef] = req.FindingRef
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        quarantineNPName(req.Target),
			Namespace:   req.Target.Namespace,
			Labels:      map[string]string{LabelQuarantine: "true"},
			Annotations: annotations,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: *selector,
			// Both policy types selected with no ingress/egress rules => deny all.
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// quarantineNPName derives the deterministic deny-all NetworkPolicy name for a
// target so revert can find it from the target identity alone. The name is keyed
// on both kind and name so different kinds sharing a name (e.g. Deployment/api
// and StatefulSet/api) do not collide on — or delete — each other's policy. It
// is kept within the object-name length limit; when truncation is needed a short
// hash of the full identity is appended to keep distinct targets distinct.
func quarantineNPName(t Target) string {
	base := quarantineNPPrefix + strings.ToLower(t.Kind) + "-" + t.Name
	if len(base) <= maxNameLen {
		return base
	}
	sum := sha256.Sum256([]byte(t.String()))
	suffix := "-" + hex.EncodeToString(sum[:])[:10]
	return strings.TrimRight(base[:maxNameLen-len(suffix)], "-.") + suffix
}
