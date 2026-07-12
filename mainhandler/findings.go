package mainhandler

import (
	"context"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/operator/mainhandler/remediators"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// severity ranks order findings from most to least severe so a MinSeverity
// filter ("act on High and above") is a simple >= comparison. Unknown is the
// weakest non-zero rank; 0 means "unrecognized severity".
const (
	rankUnknown  = 1
	rankLow      = 2
	rankMedium   = 3
	rankHigh     = 4
	rankCritical = 5
)

// severityRank maps a severity string (case-insensitive) to its rank. The bool
// is false for an unrecognized severity so callers can reject a bad MinSeverity
// rather than silently matching nothing.
func severityRank(severity string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return rankCritical, true
	case "high":
		return rankHigh, true
	case "medium":
		return rankMedium, true
	case "low":
		return rankLow, true
	case "unknown":
		return rankUnknown, true
	default:
		return 0, false
	}
}

// resolveSelectorTargets turns a findings-driven Selector into a concrete set of
// workload targets by reading the stored configuration-scan summaries
// (workloadconfigurationscansummaries in spdx.softwarecomposition.kubescape.io).
// No re-scan happens: it acts on findings already in the cluster.
//
// A summary matches when it fails the requested Control and/or carries a failing
// finding at or above MinSeverity (see summaryMatchesSelector). Targets in
// excluded/protected namespaces and non-remediable kinds are dropped here so
// they never reach a remediator, and duplicates are collapsed.
func (actionHandler *ActionHandler) resolveSelectorTargets(ctx context.Context, selector *apis.OperatorActionSelector) ([]remediators.Target, error) {
	// An empty selector would otherwise match every workload; require an explicit
	// axis so "remediate everything" can never be the accidental default.
	if selector.Control == "" && selector.MinSeverity == "" {
		return nil, fmt.Errorf("operatorAction: selector requires at least one of 'control' or 'minSeverity'")
	}

	minRank := 0
	if selector.MinSeverity != "" {
		r, ok := severityRank(selector.MinSeverity)
		if !ok {
			return nil, fmt.Errorf("operatorAction: invalid minSeverity %q (want Critical|High|Medium|Low|Unknown)", selector.MinSeverity)
		}
		minRank = r
	}

	if actionHandler.ksStorageClient == nil {
		return nil, fmt.Errorf("operatorAction: findings-driven targeting requires the storage client, which is not configured")
	}

	// namespace "" lists configuration-scan summaries across all namespaces.
	summaries, err := actionHandler.ksStorageClient.SpdxV1beta1().WorkloadConfigurationScanSummaries("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("operatorAction: failed to list configuration scan summaries: %w", err)
	}

	var targets []remediators.Target
	seen := make(map[string]struct{})
	for i := range summaries.Items {
		summary := &summaries.Items[i]
		if !summaryMatchesSelector(summary, selector.Control, minRank) {
			continue
		}
		target, ok := targetFromSummaryLabels(summary.Labels)
		if !ok {
			continue
		}
		// The remediators only act on namespaced workload kinds; skip anything
		// else (e.g. CronJob) rather than failing the whole batch later.
		if !remediators.IsNamespacedKind(target.Kind) {
			continue
		}
		// Protected/excluded namespaces are never remediated, even by a selector.
		if actionHandler.config.SkipNamespace(target.Namespace) {
			continue
		}
		key := target.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}

// summaryMatchesSelector reports whether a configuration-scan summary satisfies
// the selector. With a Control set, the named control must be present and
// failing (and, if MinSeverity is also set, at or above that severity). With
// only MinSeverity set, any failing finding at or above that severity matches.
func summaryMatchesSelector(summary *spdxv1beta1.WorkloadConfigurationScanSummary, control string, minRank int) bool {
	if control != "" {
		c, ok := findFailedControl(summary, control)
		if !ok {
			return false
		}
		if minRank > 0 {
			if r, _ := severityRank(c.Severity.Severity); r < minRank {
				return false
			}
		}
		return true
	}
	return summaryHasFailingSeverityAtLeast(summary, minRank)
}

// findFailedControl looks up a control by ID in the summary and returns it only
// if it failed. The controls map is keyed by control ID by convention, but the
// ControlID field is matched too so a differently-keyed map still resolves.
func findFailedControl(summary *spdxv1beta1.WorkloadConfigurationScanSummary, controlID string) (spdxv1beta1.ScannedControlSummary, bool) {
	want := strings.ToLower(strings.TrimSpace(controlID))
	for key, c := range summary.Spec.Controls {
		if strings.ToLower(key) != want && strings.ToLower(c.ControlID) != want {
			continue
		}
		if strings.EqualFold(c.Status.Status, string(reporthandlingapis.StatusFailed)) {
			return c, true
		}
	}
	return spdxv1beta1.ScannedControlSummary{}, false
}

// summaryHasFailingSeverityAtLeast reports whether the summary has at least one
// failed control at or above minRank. The Severities block counts failed
// controls per severity, so a non-zero count at a qualifying rank is a match.
func summaryHasFailingSeverityAtLeast(summary *spdxv1beta1.WorkloadConfigurationScanSummary, minRank int) bool {
	sev := summary.Spec.Severities
	byRank := map[int]int64{
		rankCritical: sev.Critical,
		rankHigh:     sev.High,
		rankMedium:   sev.Medium,
		rankLow:      sev.Low,
		rankUnknown:  sev.Unknown,
	}
	for rank, count := range byRank {
		if rank >= minRank && count > 0 {
			return true
		}
	}
	return false
}

// targetFromSummaryLabels extracts the workload identity a scan summary was
// produced for from its kubescape.io/workload-* labels. It reports false when
// the identifying labels are missing so an unidentifiable summary is skipped.
func targetFromSummaryLabels(labels map[string]string) (remediators.Target, bool) {
	kind := labels[helpers.KindMetadataKey]
	name := labels[helpers.NameMetadataKey]
	namespace := labels[helpers.NamespaceMetadataKey]
	if kind == "" || name == "" {
		return remediators.Target{}, false
	}
	return remediators.Target{Kind: kind, Namespace: namespace, Name: name}, true
}
