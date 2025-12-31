package nodeagentautoscaler

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"text/template"

	"github.com/fsnotify/fsnotify"
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
	mu           sync.RWMutex // Protects template during reload
	watcher      *fsnotify.Watcher
	stopCh       chan struct{}
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

	tr.mu.Lock()
	tr.template = tmpl
	tr.mu.Unlock()

	logger.L().Debug("loaded DaemonSet template", helpers.String("path", tr.templatePath))

	return nil
}

// ReloadTemplate reloads the template from disk
func (tr *TemplateRenderer) ReloadTemplate() error {
	return tr.loadTemplate()
}

// StartWatching starts watching the template file for changes
// When the ConfigMap is updated, Kubernetes updates the mounted file, triggering a reload
func (tr *TemplateRenderer) StartWatching(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	tr.watcher = watcher
	tr.stopCh = make(chan struct{})

	// Watch the directory containing the template (ConfigMap mount point)
	// Kubernetes ConfigMaps are mounted as symlinks, so we watch the directory
	dir := filepath.Dir(tr.templatePath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch directory %s: %w", dir, err)
	}

	logger.L().Info("started watching template file for changes",
		helpers.String("path", tr.templatePath),
		helpers.String("directory", dir))

	go tr.watchLoop(ctx)
	return nil
}

// watchLoop watches for file changes and reloads the template
func (tr *TemplateRenderer) watchLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			logger.L().Debug("template watcher stopped due to context cancellation")
			return
		case <-tr.stopCh:
			logger.L().Debug("template watcher stopped")
			return
		case event, ok := <-tr.watcher.Events:
			if !ok {
				return
			}
			// ConfigMaps are updated via symlink swaps, which show as CREATE events
			// Also handle WRITE events for direct file modifications
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				// Check if the changed file is our template
				// For ConfigMap mounts, the actual file is ..data/<filename> linked to <filename>
				basename := filepath.Base(event.Name)
				templateBasename := filepath.Base(tr.templatePath)
				if basename == templateBasename || basename == "..data" {
					logger.L().Info("template file changed, reloading",
						helpers.String("event", event.Name),
						helpers.String("operation", event.Op.String()))
					if err := tr.ReloadTemplate(); err != nil {
						logger.L().Error("failed to reload template after file change", helpers.Error(err))
					} else {
						logger.L().Info("template reloaded successfully")
					}
				}
			}
		case err, ok := <-tr.watcher.Errors:
			if !ok {
				return
			}
			logger.L().Error("template watcher error", helpers.Error(err))
		}
	}
}

// StopWatching stops the file watcher
func (tr *TemplateRenderer) StopWatching() {
	if tr.stopCh != nil {
		close(tr.stopCh)
		tr.stopCh = nil
	}
	if tr.watcher != nil {
		tr.watcher.Close()
		tr.watcher = nil
	}
}

// formatMemory formats a memory quantity to a human-readable string with proper units (Mi, Gi)
// Only uses Gi for exact multiples of 1Gi to preserve precision (e.g., 1536Mi stays as 1536Mi, not 1Gi)
func formatMemory(q resource.Quantity) string {
	bytes := q.Value()

	// Use Gi only for exact multiples of 1Gi to preserve precision
	gi := int64(1024 * 1024 * 1024)
	if bytes >= gi && bytes%gi == 0 {
		return fmt.Sprintf("%dGi", bytes/gi)
	}

	// Use Mi for most values (exact multiples of 1Mi)
	mi := int64(1024 * 1024)
	if bytes >= mi && bytes%mi == 0 {
		return fmt.Sprintf("%dMi", bytes/mi)
	}

	// Use Mi with rounding for non-exact values >= 1Mi
	if bytes >= mi {
		return fmt.Sprintf("%dMi", bytes/mi)
	}

	// Use Ki for small values
	ki := int64(1024)
	if bytes >= ki {
		return fmt.Sprintf("%dKi", bytes/ki)
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

	tr.mu.RLock()
	var buf bytes.Buffer
	err := tr.template.Execute(&buf, data)
	tr.mu.RUnlock()

	if err != nil {
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

