// +build integration

package nodeagentautoscaler

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"
)

// TestIntegration_HelmGeneratedTemplate tests rendering with the actual Helm-generated template
// Run with: go test -tags=integration -v -run TestIntegration_HelmGeneratedTemplate
// Requires the template file to be extracted first from Helm:
//   helm template test ../../helm-charts/charts/kubescape-operator \
//     --set nodeAgent.autoscaler.enabled=true --set clusterName=test \
//     | grep -A 300 "daemonset-template.yaml:" | tail -n +2 | sed 's/^    //' \
//     | awk '/^---/{exit} {print}' > /tmp/test-daemonset-template.yaml
func TestIntegration_HelmGeneratedTemplate(t *testing.T) {
	templatePath := "/tmp/test-daemonset-template.yaml"

	// Check if template file exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		t.Skip("Integration test requires template file. Run Helm extraction first. See test comments for instructions.")
	}

	// Create renderer
	renderer, err := NewTemplateRenderer(templatePath)
	require.NoError(t, err)

	// Test data simulating a node group
	group := NodeGroup{
		LabelValue:    "m5.large",
		SanitizedName: "m5-large",
	}
	resources := CalculatedResources{
		Requests: ResourcePair{
			CPU:    resource.MustParse("100m"),
			Memory: resource.MustParse("200Mi"),
		},
		Limits: ResourcePair{
			CPU:    resource.MustParse("500m"),
			Memory: resource.MustParse("1Gi"),
		},
	}

	// Render
	ds, err := renderer.RenderDaemonSet(group, resources)
	require.NoError(t, err, "Failed to render DaemonSet - check template YAML structure")

	// Verify basic fields
	assert.Equal(t, "node-agent-m5-large", ds.Name)
	assert.Equal(t, "kubescape", ds.Namespace)

	// Verify resources are correctly set
	require.Len(t, ds.Spec.Template.Spec.Containers, 1, "Expected exactly 1 container")
	container := ds.Spec.Template.Spec.Containers[0]
	assert.Equal(t, "node-agent", container.Name)

	// The resource values should be parsed correctly
	assert.Equal(t, "100m", container.Resources.Requests.Cpu().String())
	assert.Equal(t, "200Mi", container.Resources.Requests.Memory().String())
	assert.Equal(t, "500m", container.Resources.Limits.Cpu().String())
	assert.Equal(t, "1Gi", container.Resources.Limits.Memory().String())

	// Verify node selector includes the instance type
	assert.Equal(t, "linux", ds.Spec.Template.Spec.NodeSelector["kubernetes.io/os"])
	assert.Equal(t, "m5.large", ds.Spec.Template.Spec.NodeSelector["node.kubernetes.io/instance-type"])

	t.Logf("Successfully rendered DaemonSet: %s", ds.Name)
	t.Logf("Container resources: requests(%s CPU, %s mem), limits(%s CPU, %s mem)",
		container.Resources.Requests.Cpu().String(),
		container.Resources.Requests.Memory().String(),
		container.Resources.Limits.Cpu().String(),
		container.Resources.Limits.Memory().String())
}

