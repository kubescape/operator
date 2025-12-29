package nodeagentautoscaler

import (
	"bytes"
	"fmt"
	"os"
	"text/template"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"
)

// TemplateData holds the data used to render the DaemonSet template
type TemplateData struct {
	// Name is the DaemonSet name (e.g., "node-agent-m5-large")
	Name string
	// NodeGroupLabel is the value of the node group label
	NodeGroupLabel string
	// Resources contains the calculated resource requests and limits
	Resources TemplateResources
}

// TemplateResources holds the resource values for template rendering
type TemplateResources struct {
	Requests TemplateResourcePair
	Limits   TemplateResourcePair
}

// TemplateResourcePair holds CPU and Memory as strings for template rendering
type TemplateResourcePair struct {
	CPU    string
	Memory string
}

// TemplateRenderer loads and renders DaemonSet templates
type TemplateRenderer struct {
	templatePath string
	template     *template.Template
}

// NewTemplateRenderer creates a new TemplateRenderer
func NewTemplateRenderer(templatePath string) (*TemplateRenderer, error) {
	tr := &TemplateRenderer{
		templatePath: templatePath,
	}

	if err := tr.loadTemplate(); err != nil {
		return nil, err
	}

	return tr, nil
}

// loadTemplate loads the template from the file system
func (tr *TemplateRenderer) loadTemplate() error {
	content, err := os.ReadFile(tr.templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template file %s: %w", tr.templatePath, err)
	}

	tmpl, err := template.New("daemonset").Parse(string(content))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	tr.template = tmpl
	logger.L().Debug("loaded DaemonSet template", helpers.String("path", tr.templatePath))

	return nil
}

// ReloadTemplate reloads the template from disk
func (tr *TemplateRenderer) ReloadTemplate() error {
	return tr.loadTemplate()
}

// formatMemory formats a memory quantity to a human-readable string with proper units (Mi, Gi)
func formatMemory(q resource.Quantity) string {
	bytes := q.Value()

	// Use Gi for values >= 1Gi
	if bytes >= 1024*1024*1024 {
		gi := bytes / (1024 * 1024 * 1024)
		return fmt.Sprintf("%dGi", gi)
	}

	// Use Mi for most values
	mi := bytes / (1024 * 1024)
	if mi > 0 {
		return fmt.Sprintf("%dMi", mi)
	}

	// Use Ki for small values
	ki := bytes / 1024
	if ki > 0 {
		return fmt.Sprintf("%dKi", ki)
	}

	// Fall back to bytes
	return fmt.Sprintf("%d", bytes)
}

// RenderDaemonSet renders a DaemonSet for the given node group and resources
func (tr *TemplateRenderer) RenderDaemonSet(group NodeGroup, resources CalculatedResources) (*appsv1.DaemonSet, error) {
	data := TemplateData{
		Name:           fmt.Sprintf("node-agent-%s", group.SanitizedName),
		NodeGroupLabel: group.LabelValue,
		Resources: TemplateResources{
			Requests: TemplateResourcePair{
				CPU:    resources.Requests.CPU.String(),
				Memory: formatMemory(resources.Requests.Memory),
			},
			Limits: TemplateResourcePair{
				CPU:    resources.Limits.CPU.String(),
				Memory: formatMemory(resources.Limits.Memory),
			},
		},
	}

	var buf bytes.Buffer
	if err := tr.template.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to render template: %w", err)
	}

	// Parse the rendered YAML into a DaemonSet
	ds := &appsv1.DaemonSet{}
	if err := yaml.Unmarshal(buf.Bytes(), ds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rendered template: %w", err)
	}

	logger.L().Debug("rendered DaemonSet",
		helpers.String("name", ds.Name),
		helpers.String("nodeGroup", group.LabelValue),
		helpers.String("requestCPU", data.Resources.Requests.CPU),
		helpers.String("requestMemory", data.Resources.Requests.Memory),
		helpers.String("limitCPU", data.Resources.Limits.CPU),
		helpers.String("limitMemory", data.Resources.Limits.Memory))

	return ds, nil
}

// GenerateDaemonSetName generates a DaemonSet name for a node group
func GenerateDaemonSetName(group NodeGroup) string {
	return fmt.Sprintf("node-agent-%s", group.SanitizedName)
}

