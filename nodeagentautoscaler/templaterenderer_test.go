package nodeagentautoscaler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestFormatMemory(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "200Mi",
			input:    "200Mi",
			expected: "200Mi",
		},
		{
			name:     "1Gi",
			input:    "1Gi",
			expected: "1Gi",
		},
		{
			name:     "1536Mi stays as Mi (preserves precision)",
			input:    "1536Mi",
			expected: "1536Mi", // Not an exact Gi multiple, so keeps Mi to preserve precision
		},
		{
			name:     "2Gi",
			input:    "2Gi",
			expected: "2Gi",
		},
		{
			name:     "bytes to Mi",
			input:    "661196472", // ~630Mi
			expected: "630Mi",
		},
		{
			name:     "bytes to Mi (preserves precision)",
			input:    "1652991180", // ~1576Mi, not an exact Gi multiple
			expected: "1576Mi",
		},
		{
			name:     "4Gi",
			input:    "4Gi",
			expected: "4Gi",
		},
		{
			name:     "small value in Ki",
			input:    "512Ki",
			expected: "512Ki",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := resource.MustParse(tt.input)
			result := formatMemory(q)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTemplateRenderer_RenderDaemonSet(t *testing.T) {
	// Create a test template file
	templateContent := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: "{{ .Name }}"
  namespace: kubescape
  labels:
    kubescape.io/managed-by: operator-autoscaler
    kubescape.io/node-group: "{{ .NodeGroupLabel }}"
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: node-agent
      kubescape.io/node-group: "{{ .NodeGroupLabel }}"
  template:
    metadata:
      labels:
        app.kubernetes.io/name: node-agent
        kubescape.io/node-group: "{{ .NodeGroupLabel }}"
    spec:
      containers:
      - name: node-agent
        image: "quay.io/kubescape/node-agent:v0.3.3"
        resources:
          requests:
            cpu: "{{ .Resources.Requests.CPU }}"
            memory: "{{ .Resources.Requests.Memory }}"
          limits:
            cpu: "{{ .Resources.Limits.CPU }}"
            memory: "{{ .Resources.Limits.Memory }}"
      nodeSelector:
        kubernetes.io/os: linux
        node.kubernetes.io/instance-type: "{{ .NodeGroupLabel }}"
`

	// Create temp file
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "daemonset-template.yaml")
	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	// Create renderer
	renderer, err := NewTemplateRenderer(templatePath)
	require.NoError(t, err)

	// Test data
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
	require.NoError(t, err)

	// Verify
	assert.Equal(t, "node-agent-m5-large", ds.Name)
	assert.Equal(t, "kubescape", ds.Namespace)
	assert.Equal(t, "operator-autoscaler", ds.Labels["kubescape.io/managed-by"])
	assert.Equal(t, "m5.large", ds.Labels["kubescape.io/node-group"])

	// Verify node selector
	assert.Equal(t, "linux", ds.Spec.Template.Spec.NodeSelector["kubernetes.io/os"])
	assert.Equal(t, "m5.large", ds.Spec.Template.Spec.NodeSelector["node.kubernetes.io/instance-type"])

	// Verify container resources
	container := ds.Spec.Template.Spec.Containers[0]
	assert.Equal(t, "node-agent", container.Name)
	assert.Equal(t, "100m", container.Resources.Requests.Cpu().String())
	assert.Equal(t, "200Mi", container.Resources.Requests.Memory().String())
	assert.Equal(t, "500m", container.Resources.Limits.Cpu().String())
	assert.Equal(t, "1Gi", container.Resources.Limits.Memory().String())
}

func TestTemplateRenderer_RenderDaemonSet_InvalidTemplate(t *testing.T) {
	// Create an invalid template
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "invalid-template.yaml")
	err := os.WriteFile(templatePath, []byte("{{ .InvalidField"), 0644)
	require.NoError(t, err)

	// Should fail to create renderer
	_, err = NewTemplateRenderer(templatePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse template")
}

func TestTemplateRenderer_ReloadTemplate(t *testing.T) {
	templateContent1 := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: "{{ .Name }}"
  namespace: kubescape
spec:
  selector:
    matchLabels:
      app: node-agent
  template:
    metadata:
      labels:
        app: node-agent
    spec:
      containers:
      - name: node-agent
        image: "quay.io/kubescape/node-agent:v0.3.3"
        resources:
          requests:
            cpu: "{{ .Resources.Requests.CPU }}"
            memory: "{{ .Resources.Requests.Memory }}"
          limits:
            cpu: "{{ .Resources.Limits.CPU }}"
            memory: "{{ .Resources.Limits.Memory }}"
`

	templateContent2 := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: "{{ .Name }}-v2"
  namespace: kubescape
spec:
  selector:
    matchLabels:
      app: node-agent
  template:
    metadata:
      labels:
        app: node-agent
    spec:
      containers:
      - name: node-agent
        image: "quay.io/kubescape/node-agent:v0.3.4"
        resources:
          requests:
            cpu: "{{ .Resources.Requests.CPU }}"
            memory: "{{ .Resources.Requests.Memory }}"
          limits:
            cpu: "{{ .Resources.Limits.CPU }}"
            memory: "{{ .Resources.Limits.Memory }}"
`

	// Create temp file with first template
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "daemonset-template.yaml")
	err := os.WriteFile(templatePath, []byte(templateContent1), 0644)
	require.NoError(t, err)

	// Create renderer
	renderer, err := NewTemplateRenderer(templatePath)
	require.NoError(t, err)

	group := NodeGroup{
		LabelValue:    "test",
		SanitizedName: "test",
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

	// First render
	ds1, err := renderer.RenderDaemonSet(group, resources)
	require.NoError(t, err)
	assert.Equal(t, "node-agent-test", ds1.Name)

	// Update template file
	err = os.WriteFile(templatePath, []byte(templateContent2), 0644)
	require.NoError(t, err)

	// Reload
	err = renderer.ReloadTemplate()
	require.NoError(t, err)

	// Second render with updated template
	ds2, err := renderer.RenderDaemonSet(group, resources)
	require.NoError(t, err)
	assert.Equal(t, "node-agent-test-v2", ds2.Name)
}


