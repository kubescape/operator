package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/mainhandler/remediators"
	"github.com/kubescape/operator/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// handleOperatorAction handles a TypeOperatorAction command. It parses the typed
// action args, enforces the Phase-1 safety rails, dispatches to the matching
// Remediator, and records the result on the OperatorCommand status plus a
// best-effort Kubernetes Event for audit.
//
// Safe-by-default: OperatorActionArgs.IsDryRun() returns true unless the caller
// set dryRun=false explicitly (the CLI's --confirm), so a missing flag can never
// silently perform a real cluster write.
func (actionHandler *ActionHandler) handleOperatorAction(ctx context.Context) error {
	cmd := actionHandler.sessionObj.Command

	args, err := apis.OperatorActionArgsFromMap(cmd.Args)
	if err != nil {
		return fmt.Errorf("operatorAction: failed to parse args: %w", err)
	}
	if args.Action == "" {
		return fmt.Errorf("operatorAction: missing 'action'")
	}

	// TTL drives automatic revert, which is a later phase. Don't silently accept
	// it: a caller that sets a ttl would wrongly assume an auto-revert is
	// scheduled, when Phase 1 does nothing with it.
	if args.TTL != "" {
		if _, err := time.ParseDuration(args.TTL); err != nil {
			return fmt.Errorf("operatorAction: invalid ttl %q: %w", args.TTL, err)
		}
		return fmt.Errorf("operatorAction: ttl/auto-revert is not supported yet (later phase); omit ttl")
	}

	// Phase 1 ships explicit-target actions only. Findings-driven Selector
	// targeting (reading the stored scan-result CRDs) arrives in phase 2.
	if args.Target == nil {
		if args.Selector != nil {
			return fmt.Errorf("operatorAction: findings-driven selector targeting is not supported yet (phase 2); provide an explicit target")
		}
		return fmt.Errorf("operatorAction: a target is required")
	}

	target := remediators.Target{
		Kind:      args.Target.Kind,
		Namespace: args.Target.Namespace,
		Name:      args.Target.Name,
	}

	// All Phase-1 target kinds are namespaced. Require the namespace up front so
	// the excluded-namespace rail below is actually enforced, instead of an empty
	// namespace slipping past it and failing late at the API server.
	if remediators.IsNamespacedKind(target.Kind) && target.Namespace == "" {
		return fmt.Errorf("operatorAction: target kind %q requires a namespace", target.Kind)
	}

	// Safety rail: never act on excluded / protected namespaces.
	if target.Namespace != "" && actionHandler.config.SkipNamespace(target.Namespace) {
		return fmt.Errorf("operatorAction: namespace %q is excluded from remediation", target.Namespace)
	}

	dryRun := args.IsDryRun()
	registry := remediators.NewRegistry(actionHandler.k8sAPI.KubernetesClient)

	logger.L().Info("handling operator action",
		helpers.String("action", string(args.Action)),
		helpers.String("target", target.String()),
		helpers.String("dryRun", fmt.Sprintf("%t", dryRun)))

	switch args.Action {
	case apis.OperatorActionAnnotate, apis.OperatorActionQuarantine:
		req := remediators.Request{Target: target, Reason: args.Reason, FindingRef: args.FindingRef}
		return actionHandler.applyRemediation(ctx, registry[args.Action], req, dryRun)

	case apis.OperatorActionRevert:
		// Pass dryRun so a default (no --confirm) revert previews instead of writing.
		return actionHandler.revertTarget(ctx, registry, target, dryRun)

	case apis.OperatorActionCordon:
		return fmt.Errorf("operatorAction: action %q is not implemented yet (planned for a later phase)", args.Action)

	default:
		return fmt.Errorf("operatorAction: unknown action %q", args.Action)
	}
}

// applyRemediation runs a remediator's Plan -> Apply and records the result.
func (actionHandler *ActionHandler) applyRemediation(ctx context.Context, r remediators.Remediator, req remediators.Request, dryRun bool) error {
	plan, err := r.Plan(ctx, req)
	if err != nil {
		return err
	}
	result, err := r.Apply(ctx, plan, dryRun)
	if err != nil {
		return err
	}
	return actionHandler.recordActionResult(ctx, result)
}

// revertTarget undoes every reversible action on the target. Each Revert is
// idempotent — a missing annotation or NetworkPolicy is a no-op — so revert is
// safe to call without knowing which action was originally applied. A target
// object that no longer exists (NotFound) is skipped, not treated as an error,
// so a leftover artifact (e.g. a NetworkPolicy whose workload was deleted) is
// still cleaned up.
func (actionHandler *ActionHandler) revertTarget(ctx context.Context, registry map[apis.OperatorActionType]remediators.Remediator, target remediators.Target, dryRun bool) error {
	reversible := []apis.OperatorActionType{apis.OperatorActionAnnotate, apis.OperatorActionQuarantine}
	var descriptions []string
	applied := false
	for _, action := range reversible {
		r, ok := registry[action]
		if !ok {
			continue
		}
		result, err := r.Revert(ctx, target, dryRun)
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return err
		}
		descriptions = append(descriptions, result.Description)
		applied = applied || result.Applied
	}
	return actionHandler.recordActionResult(ctx, remediators.Result{
		Action:      string(apis.OperatorActionRevert),
		Target:      target,
		DryRun:      dryRun,
		Applied:     applied,
		Description: strings.Join(descriptions, "; "),
	})
}

// recordActionResult writes the result to the OperatorCommand status payload
// (a no-op when the command did not originate from a CRD) and emits a
// best-effort Kubernetes Event.
//
// handleRequest sets the command status again to success after this returns;
// because OperatorCommandStatus.Payload is omitempty, that follow-up merge patch
// does not clear the payload written here.
func (actionHandler *ActionHandler) recordActionResult(ctx context.Context, result remediators.Result) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("operatorAction: failed to marshal result: %w", err)
	}

	actionHandler.sessionObj.SetOperatorCommandStatus(ctx, utils.WithSuccess(), utils.WithPayload(payload))
	actionHandler.emitActionEvent(ctx, result)

	logger.L().Info("operator action completed",
		helpers.String("action", result.Action),
		helpers.String("target", result.Target.String()),
		helpers.String("dryRun", fmt.Sprintf("%t", result.DryRun)),
		helpers.String("applied", fmt.Sprintf("%t", result.Applied)))
	return nil
}

// emitActionEvent records the action as a Kubernetes Event for audit. It is
// best-effort: a failure is logged but never fails the action.
func (actionHandler *ActionHandler) emitActionEvent(ctx context.Context, result remediators.Result) {
	if actionHandler.k8sAPI == nil || actionHandler.k8sAPI.KubernetesClient == nil {
		return
	}

	namespace := result.Target.Namespace
	if namespace == "" {
		namespace = actionHandler.config.Namespace()
	}

	outcome := "applied"
	if result.DryRun {
		outcome = "dry-run, no changes made"
	}

	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kubescape-remediation-",
			Namespace:    namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      result.Target.Kind,
			Namespace: result.Target.Namespace,
			Name:      result.Target.Name,
		},
		Reason:         "KubescapeRemediation",
		Message:        fmt.Sprintf("operator action %q (%s) on %s", result.Action, outcome, result.Target),
		Type:           corev1.EventTypeNormal,
		Source:         corev1.EventSource{Component: "kubescape-operator"},
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
		Count:          1,
	}

	if _, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Events(namespace).Create(ctx, event, metav1.CreateOptions{}); err != nil {
		logger.L().Ctx(ctx).Warning("operatorAction: failed to emit kubernetes event", helpers.Error(err))
	}
}
