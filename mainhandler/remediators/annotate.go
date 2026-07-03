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
)

// Annotation keys written by the annotate action. They mark a workload as
// having been acted on by Kubescape and carry the audit context (the reason and
// the finding that justified the action).
const (
	AnnotationRemediated = "kubescape.io/remediated"
	AnnotationReason     = "kubescape.io/remediation-reason"
	AnnotationFindingRef = "kubescape.io/remediation-finding-ref"
)

// AnnotateRemediator is the lowest-blast-radius action: it adds Kubescape
// remediation annotations to a workload. It is the first action shipped, to
// prove the CLI -> operator -> status pipeline end to end.
type AnnotateRemediator struct {
	client kubernetes.Interface
}

// NewAnnotateRemediator returns an annotate remediator backed by client.
func NewAnnotateRemediator(client kubernetes.Interface) *AnnotateRemediator {
	return &AnnotateRemediator{client: client}
}

// Plan computes the annotation patch without applying it.
func (r *AnnotateRemediator) Plan(ctx context.Context, req Request) (Plan, error) {
	if err := validateTarget(req.Target); err != nil {
		return Plan{}, err
	}
	annotations := r.desiredAnnotations(req)
	patch, err := annotationPatch(toInterfaceMap(annotations))
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		Action:      string(apis.OperatorActionAnnotate),
		Target:      req.Target,
		Description: fmt.Sprintf("annotate %s with %v", req.Target, annotations),
		Patch:       string(patch),
	}, nil
}

// Apply sends the planned patch. With dryRun=true it is a server-side dry-run
// (validated against admission, never persisted); only dryRun=false writes.
func (r *AnnotateRemediator) Apply(ctx context.Context, p Plan, dryRun bool) (Result, error) {
	if err := validateTarget(p.Target); err != nil {
		return Result{}, err
	}
	if err := r.patch(ctx, p.Target, []byte(p.Patch), dryRun); err != nil {
		return Result{}, err
	}
	return Result{
		Action:      p.Action,
		Target:      p.Target,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: p.Description,
	}, nil
}

// Revert removes the Kubescape remediation annotations from the target. Like
// Apply, dryRun=true issues a server-side dry-run (validated against admission,
// never persisted); only dryRun=false performs a real write — so the
// safe-by-default contract is honored for revert too.
//
// The contract's revert verb undoes every reversible action without naming which
// one was applied, so revert runs annotate even on a workload that was only
// quarantined. To keep the audit trail honest, a workload carrying none of the
// remediation annotations is reported as a no-op ("nothing to revert",
// Applied=false) rather than claiming annotations were removed.
func (r *AnnotateRemediator) Revert(ctx context.Context, t Target, dryRun bool) (Result, error) {
	if err := validateTarget(t); err != nil {
		return Result{}, err
	}
	annotations, err := r.getAnnotations(ctx, t)
	if err != nil {
		return Result{}, err
	}
	if !hasAnyKey(annotations, AnnotationRemediated, AnnotationReason, AnnotationFindingRef) {
		return Result{
			Action:      string(apis.OperatorActionRevert),
			Target:      t,
			DryRun:      dryRun,
			Applied:     false,
			Description: fmt.Sprintf("no kubescape remediation annotations on %s; nothing to revert", t),
		}, nil
	}
	// A JSON merge patch deletes a key by setting it to null.
	patch, err := annotationPatch(map[string]interface{}{
		AnnotationRemediated: nil,
		AnnotationReason:     nil,
		AnnotationFindingRef: nil,
	})
	if err != nil {
		return Result{}, err
	}
	if err := r.patch(ctx, t, patch, dryRun); err != nil {
		return Result{}, err
	}
	return Result{
		Action:      string(apis.OperatorActionRevert),
		Target:      t,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: fmt.Sprintf("removed kubescape remediation annotations from %s", t),
	}, nil
}

func (r *AnnotateRemediator) desiredAnnotations(req Request) map[string]string {
	annotations := map[string]string{AnnotationRemediated: "true"}
	if req.Reason != "" {
		annotations[AnnotationReason] = req.Reason
	}
	if req.FindingRef != "" {
		annotations[AnnotationFindingRef] = req.FindingRef
	}
	return annotations
}

// getAnnotations reads the live target's annotations so Revert can tell whether
// there is anything to undo. A NotFound is returned to the caller (the action
// handler skips a target that no longer exists).
func (r *AnnotateRemediator) getAnnotations(ctx context.Context, t Target) (map[string]string, error) {
	switch strings.ToLower(t.Kind) {
	case "deployment":
		o, err := r.client.AppsV1().Deployments(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Annotations, nil
	case "statefulset":
		o, err := r.client.AppsV1().StatefulSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Annotations, nil
	case "daemonset":
		o, err := r.client.AppsV1().DaemonSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Annotations, nil
	case "pod":
		o, err := r.client.CoreV1().Pods(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		return o.Annotations, nil
	default:
		return nil, fmt.Errorf("annotate: unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", t.Kind)
	}
}

// patch applies a JSON merge patch to the target object using the typed client
// for its kind. Server-side dry-run is requested when dryRun is true.
func (r *AnnotateRemediator) patch(ctx context.Context, t Target, patch []byte, dryRun bool) error {
	opts := metav1.PatchOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	switch strings.ToLower(t.Kind) {
	case "deployment":
		_, err := r.client.AppsV1().Deployments(t.Namespace).Patch(ctx, t.Name, types.MergePatchType, patch, opts)
		return err
	case "statefulset":
		_, err := r.client.AppsV1().StatefulSets(t.Namespace).Patch(ctx, t.Name, types.MergePatchType, patch, opts)
		return err
	case "daemonset":
		_, err := r.client.AppsV1().DaemonSets(t.Namespace).Patch(ctx, t.Name, types.MergePatchType, patch, opts)
		return err
	case "pod":
		_, err := r.client.CoreV1().Pods(t.Namespace).Patch(ctx, t.Name, types.MergePatchType, patch, opts)
		return err
	default:
		return fmt.Errorf("annotate: unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", t.Kind)
	}
}

// IsNamespacedKind reports whether kind is one of the namespaced workload kinds
// Phase-1 actions operate on. The action handler uses it to enforce the
// namespace safety rail up front: a namespaced target with no namespace would
// otherwise skip the excluded-namespace check and fail late at the API server.
func IsNamespacedKind(kind string) bool {
	switch strings.ToLower(kind) {
	case "deployment", "statefulset", "daemonset", "pod":
		return true
	default:
		return false
	}
}

// annotationPatch builds a JSON merge patch that sets metadata.annotations.
func annotationPatch(annotations map[string]interface{}) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotations,
		},
	})
}

func toInterfaceMap(in map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// hasAnyKey reports whether m contains at least one of keys.
func hasAnyKey(m map[string]string, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func validateTarget(t Target) error {
	if t.Kind == "" || t.Name == "" {
		return fmt.Errorf("target requires both kind and name (got %+v)", t)
	}
	return nil
}
