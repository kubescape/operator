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

const (
	// AnnotationCordon marks the node as cordoned by Kubescape remediation,
	// so the audit trail can distinguish Kubescape-initiated cordoning and
	// revert can clean up its own markers.
	AnnotationCordon = "kubescape.io/cordon"

	// cordonByKubescape is the AnnotationCordon value when Kubescape made the
	// node unschedulable. cordonPreexisting is the value when the node was
	// already unschedulable (cordoned by someone else) when Kubescape cordoned
	// it: revert then removes Kubescape's annotations and leaves the node
	// cordoned.
	cordonByKubescape = "true"
	cordonPreexisting = "preexisting"
)

// CordonRemediator marks a Kubernetes Node unschedulable (spec.unschedulable=true)
// to prevent new pods from being scheduled onto it (e.g., in response to an
// Indicator of Compromise or severe node-level security finding). It does not
// evict or terminate existing running pods (draining is a distinct operation).
// Revert restores the node to schedulable (spec.unschedulable=false) and removes
// the Kubescape audit annotations, unless the node was already cordoned before
// Kubescape cordoned it.
type CordonRemediator struct {
	client kubernetes.Interface
}

// NewCordonRemediator returns a cordon remediator backed by client.
func NewCordonRemediator(client kubernetes.Interface) *CordonRemediator {
	return &CordonRemediator{client: client}
}

// Plan checks the target node and prepares the Strategic Merge Patch that sets
// spec.unschedulable=true without modifying the cluster. If client is available,
// it inspects the live node to report whether it is already unschedulable.
func (r *CordonRemediator) Plan(ctx context.Context, req Request) (Plan, error) {
	if err := validateTarget(req.Target); err != nil {
		return Plan{}, err
	}
	if strings.ToLower(req.Target.Kind) != "node" {
		return Plan{}, fmt.Errorf("cordon: unsupported target kind %q (supported: Node)", req.Target.Kind)
	}

	desc := fmt.Sprintf("mark node %q unschedulable (cordon)", req.Target.Name)
	var resourceVersion string
	marker := cordonByKubescape
	if r.client != nil {
		node, err := r.client.CoreV1().Nodes().Get(ctx, req.Target.Name, metav1.GetOptions{})
		if err != nil {
			return Plan{}, fmt.Errorf("cordon: reading live node %q: %w", req.Target.Name, err)
		}
		// Bind the ownership decision to the node state used to make it.
		resourceVersion = node.ResourceVersion
		if node.Spec.Unschedulable {
			desc = fmt.Sprintf("node %q is already unschedulable (cordoned)", req.Target.Name)
			// Someone else cordoned this node, so a later revert must not
			// uncordon it. A cordon Kubescape made earlier keeps its marker.
			if node.Annotations[AnnotationCordon] != cordonByKubescape {
				marker = cordonPreexisting
			}
		}
	}

	patchBytes, err := buildCordonPatch(req.Reason, req.FindingRef, marker, resourceVersion)
	if err != nil {
		return Plan{}, fmt.Errorf("cordon: failed to build patch: %w", err)
	}

	return Plan{
		Action:      string(apis.OperatorActionCordon),
		Target:      req.Target,
		Description: desc,
		Patch:       string(patchBytes),
		PatchType:   string(types.StrategicMergePatchType),
	}, nil
}

// Apply executes the planned cordon patch against the target node. With dryRun=true
// it issues a server-side dry-run (validated against admission, never persisted);
// only dryRun=false performs a persistent cluster write.
func (r *CordonRemediator) Apply(ctx context.Context, p Plan, dryRun bool) (Result, error) {
	if err := validateTarget(p.Target); err != nil {
		return Result{}, err
	}
	if strings.ToLower(p.Target.Kind) != "node" {
		return Result{}, fmt.Errorf("cordon: unsupported target kind %q (supported: Node)", p.Target.Kind)
	}

	opts := metav1.PatchOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	if err := r.patch(ctx, p.Target.Name, []byte(p.Patch), opts); err != nil {
		return Result{}, err
	}

	return Result{
		Action:      string(apis.OperatorActionCordon),
		Target:      p.Target,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: p.Description,
		Patch:       p.Patch,
		PatchType:   p.PatchType,
	}, nil
}

// Revert restores the target node to schedulable (spec.unschedulable=false) and
// clears the Kubescape cordon annotations, provided the node was cordoned by
// Kubescape (has kubescape.io/cordon annotation). If the node was cordoned
// externally without this annotation, Revert is a no-op to avoid uncordoning
// nodes cordoned for maintenance or other external reasons. If it was already
// cordoned when Kubescape cordoned it (kubescape.io/cordon=preexisting), Revert
// only clears the annotations and leaves the node unschedulable.
func (r *CordonRemediator) Revert(ctx context.Context, t Target, dryRun bool) (Result, error) {
	if err := validateTarget(t); err != nil {
		return Result{}, err
	}
	if strings.ToLower(t.Kind) != "node" {
		return Result{}, fmt.Errorf("cordon: unsupported target kind %q (supported: Node)", t.Kind)
	}

	var rv string
	preexisting := false
	if r.client != nil {
		node, err := r.client.CoreV1().Nodes().Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return Result{}, err
		}
		if node.Annotations == nil || node.Annotations[AnnotationCordon] == "" {
			return Result{
				Action:      string(apis.OperatorActionRevert),
				Target:      t,
				DryRun:      dryRun,
				Applied:     false,
				Description: fmt.Sprintf("node %q was not cordoned by kubescape; nothing to revert", t.Name),
			}, nil
		}
		preexisting = node.Annotations[AnnotationCordon] == cordonPreexisting
		rv = node.ResourceVersion
	}

	patchBytes, err := buildUncordonPatch(rv, !preexisting)
	if err != nil {
		return Result{}, fmt.Errorf("cordon: failed to build uncordon patch: %w", err)
	}
	desc := fmt.Sprintf("marked node %q schedulable (uncordon)", t.Name)
	if preexisting {
		desc = fmt.Sprintf("removed kubescape cordon annotations from node %q; it was already cordoned before kubescape, so it stays unschedulable", t.Name)
	}

	opts := metav1.PatchOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	if err := r.patch(ctx, t.Name, patchBytes, opts); err != nil {
		return Result{}, err
	}

	return Result{
		Action:      string(apis.OperatorActionRevert),
		Target:      t,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: desc,
		Patch:       string(patchBytes),
		PatchType:   string(types.StrategicMergePatchType),
	}, nil
}

func (r *CordonRemediator) patch(ctx context.Context, nodeName string, patch []byte, opts metav1.PatchOptions) error {
	if r.client == nil {
		return nil
	}
	_, err := r.client.CoreV1().Nodes().Patch(ctx, nodeName, types.StrategicMergePatchType, patch, opts)
	return err
}

func buildCordonPatch(reason, findingRef, marker, resourceVersion string) ([]byte, error) {
	annotations := map[string]any{
		AnnotationCordon:     marker,
		AnnotationRemediated: "true",
	}
	if reason != "" {
		annotations[AnnotationReason] = reason
	}
	if findingRef != "" {
		annotations[AnnotationFindingRef] = findingRef
	}

	metadata := map[string]any{"annotations": annotations}
	if resourceVersion != "" {
		metadata["resourceVersion"] = resourceVersion
	}
	patchObj := map[string]any{
		"metadata": metadata,
		"spec": map[string]any{
			"unschedulable": true,
		},
	}
	return json.Marshal(patchObj)
}

// buildUncordonPatch removes Kubescape's cordon annotations and, when uncordon
// is true, makes the node schedulable again.
func buildUncordonPatch(resourceVersion string, uncordon bool) ([]byte, error) {
	metadata := map[string]any{
		"annotations": map[string]any{
			AnnotationCordon:     nil,
			AnnotationRemediated: nil,
			AnnotationReason:     nil,
			AnnotationFindingRef: nil,
		},
	}
	if resourceVersion != "" {
		metadata["resourceVersion"] = resourceVersion
	}
	patchObj := map[string]any{
		"metadata": metadata,
	}
	if uncordon {
		patchObj["spec"] = map[string]any{
			"unschedulable": false,
		}
	}
	return json.Marshal(patchObj)
}
