// Package remediators implements the individual cluster operations ("actions")
// that the operator performs in response to a TypeOperatorAction command.
//
// Each action is a Remediator: it can Plan a change (without touching the
// cluster), Apply it (optionally as a server-side dry-run), and Revert it.
// New actions are added by implementing Remediator and registering them in
// NewRegistry — the command pipeline in mainhandler does not change.
package remediators

import (
	"context"
	"fmt"

	"github.com/armosec/armoapi-go/apis"
	"k8s.io/client-go/kubernetes"
)

// Target identifies a single concrete object a remediation acts on.
type Target struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// String renders the target as kind/namespace/name (kind/name for cluster-scoped
// objects), used in plans, results, logs and events.
func (t Target) String() string {
	if t.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", t.Kind, t.Namespace, t.Name)
	}
	return fmt.Sprintf("%s/%s", t.Kind, t.Name)
}

// Request carries a single remediation's target plus the audit metadata that
// some actions (e.g. annotate) record on the mutated object.
type Request struct {
	Target     Target
	Reason     string
	FindingRef string
}

// Plan is the computed, not-yet-applied effect of a remediation. It is returned
// to the caller (CLI / OperatorCommand status) so a change can be previewed
// before any cluster write happens.
type Plan struct {
	Action      string `json:"action"`
	Target      Target `json:"target"`
	Description string `json:"description"`
	// Patch is the exact patch body Apply would send, included for transparency
	// in the dry-run preview.
	Patch string `json:"patch,omitempty"`
}

// Result is the outcome of Apply or Revert.
type Result struct {
	Action      string `json:"action"`
	Target      Target `json:"target"`
	DryRun      bool   `json:"dryRun"`
	Applied     bool   `json:"applied"`
	Description string `json:"description"`
}

// Remediator computes and performs a single class of cluster operation.
type Remediator interface {
	// Plan computes the intended change without mutating the cluster.
	Plan(ctx context.Context, req Request) (Plan, error)
	// Apply executes a plan. When dryRun is true the write is sent with
	// server-side dry-run (validated against admission, never persisted).
	Apply(ctx context.Context, p Plan, dryRun bool) (Result, error)
	// Revert undoes a previously applied action on the target. Like Apply, a
	// dryRun=true revert is a server-side dry-run (validated, never persisted),
	// so the safe-by-default contract holds for revert too.
	Revert(ctx context.Context, t Target, dryRun bool) (Result, error)
}

// NewRegistry builds the set of remediators backed by the given client. New
// actions are added by extending this map; the command pipeline does not change.
// cordon is added in a later phase.
func NewRegistry(client kubernetes.Interface) map[apis.OperatorActionType]Remediator {
	return map[apis.OperatorActionType]Remediator{
		apis.OperatorActionAnnotate:   NewAnnotateRemediator(client),
		apis.OperatorActionQuarantine: NewQuarantineRemediator(client),
	}
}
