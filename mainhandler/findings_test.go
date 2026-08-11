package mainhandler

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler/remediators"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// scanSummary builds a WorkloadConfigurationScanSummary for a workload, carrying
// the kubescape.io/workload-* labels the resolver reads to recover the target.
func scanSummary(ns, kind, name string, controls map[string]spdxv1beta1.ScannedControlSummary, sev spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary) *spdxv1beta1.WorkloadConfigurationScanSummary {
	return &spdxv1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      kind + "-" + name,
			Labels: map[string]string{
				helpers.RelatedKindMetadataKey:      kind,
				helpers.RelatedNameMetadataKey:      name,
				helpers.RelatedNamespaceMetadataKey: ns,
			},
		},
		Spec: spdxv1beta1.WorkloadConfigurationScanSummarySpec{
			Controls:   controls,
			Severities: sev,
		},
	}
}

func failedControl(id, severity string) spdxv1beta1.ScannedControlSummary {
	return spdxv1beta1.ScannedControlSummary{
		ControlID: id,
		Severity:  spdxv1beta1.ControlSeverity{Severity: severity},
		Status:    spdxv1beta1.ScannedControlStatus{Status: "failed"},
	}
}

func passedControl(id, severity string) spdxv1beta1.ScannedControlSummary {
	return spdxv1beta1.ScannedControlSummary{
		ControlID: id,
		Severity:  spdxv1beta1.ControlSeverity{Severity: severity},
		Status:    spdxv1beta1.ScannedControlStatus{Status: "passed"},
	}
}

func newResolver(storageClient kssc.Interface, cfg config.IConfig) *ActionHandler {
	return &ActionHandler{ksStorageClient: storageClient, config: cfg}
}

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		in    string
		want  int
		valid bool
	}{
		{"Critical", rankCritical, true},
		{"high", rankHigh, true},
		{"  Medium  ", rankMedium, true},
		{"low", rankLow, true},
		{"Unknown", rankUnknown, true},
		{"bogus", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := severityRank(c.in)
		assert.Equal(t, c.valid, ok, "validity for %q", c.in)
		assert.Equal(t, c.want, got, "rank for %q", c.in)
	}
	// Ordering the whole feature depends on: Critical > High > Medium > Low > Unknown.
	assert.Greater(t, rankCritical, rankHigh)
	assert.Greater(t, rankHigh, rankMedium)
	assert.Greater(t, rankMedium, rankLow)
	assert.Greater(t, rankLow, rankUnknown)
}

func TestResolveSelectorTargets_ByControl(t *testing.T) {
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "Deployment", "api", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}),
		scanSummary("payments", "Deployment", "web", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": passedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{}),
		scanSummary("payments", "Deployment", "worker", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0055": failedControl("C-0055", "Medium"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{Medium: 1}),
	)
	ah := newResolver(storageClient, newTestConfig(config.Config{Namespace: "kubescape"}))

	targets, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{Control: "C-0016"})
	require.NoError(t, err)
	assert.Equal(t, []remediators.Target{{Kind: "Deployment", Namespace: "payments", Name: "api"}}, targets,
		"only the workload failing C-0016 must be selected")
}

func TestResolveSelectorTargets_ByMinSeverity(t *testing.T) {
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "Deployment", "critical-api", nil,
			spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{Critical: 2}),
		scanSummary("payments", "Deployment", "high-api", nil,
			spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}),
		scanSummary("payments", "Deployment", "low-only", nil,
			spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{Low: 3}),
	)
	ah := newResolver(storageClient, newTestConfig(config.Config{Namespace: "kubescape"}))

	targets, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{MinSeverity: "High"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []remediators.Target{
		{Kind: "Deployment", Namespace: "payments", Name: "critical-api"},
		{Kind: "Deployment", Namespace: "payments", Name: "high-api"},
	}, targets, "MinSeverity=High must match Critical and High, exclude Low-only")
}

// Control + MinSeverity together: the matched control must itself meet the
// severity floor, even if the control failed.
func TestResolveSelectorTargets_ControlBelowMinSeverityExcluded(t *testing.T) {
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "Deployment", "api", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "Medium"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{Medium: 1}),
	)
	ah := newResolver(storageClient, newTestConfig(config.Config{Namespace: "kubescape"}))

	targets, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{Control: "C-0016", MinSeverity: "High"})
	require.NoError(t, err)
	assert.Empty(t, targets, "a failing control below MinSeverity must not match")
}

// The #1 correctness trap: an empty selector must match nothing, not everything.
func TestResolveSelectorTargets_EmptySelectorRejected(t *testing.T) {
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "Deployment", "api", nil,
			spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}),
	)
	ah := newResolver(storageClient, newTestConfig(config.Config{Namespace: "kubescape"}))

	_, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one of 'control' or 'minSeverity'")
}

func TestResolveSelectorTargets_InvalidMinSeverityRejected(t *testing.T) {
	ah := newResolver(kssfake.NewSimpleClientset(), newTestConfig(config.Config{Namespace: "kubescape"}))
	_, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{MinSeverity: "banana"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid minSeverity")
}

func TestResolveSelectorTargets_SkipsExcludedNamespace(t *testing.T) {
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("kube-system", "Deployment", "api", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}),
	)
	cfg := newTestConfig(config.Config{Namespace: "kubescape", ExcludeNamespaces: []string{"kube-system"}})
	ah := newResolver(storageClient, cfg)

	targets, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{Control: "C-0016"})
	require.NoError(t, err)
	assert.Empty(t, targets, "a match in an excluded namespace must be dropped")
}

// Config-scan summaries exist for kinds the remediators cannot act on (e.g.
// CronJob); those must not become targets.
func TestResolveSelectorTargets_SkipsUnsupportedKind(t *testing.T) {
	storageClient := kssfake.NewSimpleClientset(
		scanSummary("payments", "CronJob", "nightly", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{High: 1}),
	)
	ah := newResolver(storageClient, newTestConfig(config.Config{Namespace: "kubescape"}))

	targets, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{Control: "C-0016"})
	require.NoError(t, err)
	assert.Empty(t, targets, "a non-remediable kind must be skipped")
}

func TestResolveSelectorTargets_SkipsSummaryMissingLabels(t *testing.T) {
	// A summary that fails the control but lacks the identifying labels can't be
	// resolved to a target and must be skipped, not panic.
	unlabeled := &spdxv1beta1.WorkloadConfigurationScanSummary{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "orphan"},
		Spec: spdxv1beta1.WorkloadConfigurationScanSummarySpec{
			Controls: map[string]spdxv1beta1.ScannedControlSummary{"C-0016": failedControl("C-0016", "High")},
		},
	}
	ah := newResolver(kssfake.NewSimpleClientset(unlabeled), newTestConfig(config.Config{Namespace: "kubescape"}))

	targets, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{Control: "C-0016"})
	require.NoError(t, err)
	assert.Empty(t, targets)
}

// Two summaries for the same workload (e.g. re-scans) must collapse to one target.
func TestResolveSelectorTargets_Dedup(t *testing.T) {
	storageClient := kssfake.NewSimpleClientset(
		scanSummaryNamed("payments", "Deployment", "api", "summary-1", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}),
		scanSummaryNamed("payments", "Deployment", "api", "summary-2", map[string]spdxv1beta1.ScannedControlSummary{
			"C-0016": failedControl("C-0016", "High"),
		}),
	)
	ah := newResolver(storageClient, newTestConfig(config.Config{Namespace: "kubescape"}))

	targets, err := ah.resolveSelectorTargets(context.Background(), &apis.OperatorActionSelector{Control: "C-0016"})
	require.NoError(t, err)
	assert.Equal(t, []remediators.Target{{Kind: "Deployment", Namespace: "payments", Name: "api"}}, targets)
}

// scanSummaryNamed is scanSummary with an explicit CR name so two summaries for
// the same workload can coexist in the fake store.
func scanSummaryNamed(ns, kind, name, crName string, controls map[string]spdxv1beta1.ScannedControlSummary) *spdxv1beta1.WorkloadConfigurationScanSummary {
	s := scanSummary(ns, kind, name, controls, spdxv1beta1.WorkloadConfigurationScanSeveritiesSummary{})
	s.Name = crName
	return s
}
