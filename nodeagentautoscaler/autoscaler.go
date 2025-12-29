package nodeagentautoscaler

import (
	"context"
	"reflect"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// ManagedByLabel is the label used to identify DaemonSets managed by the autoscaler
	ManagedByLabel = "kubescape.io/managed-by"
	// ManagedByValue is the value for the managed-by label
	ManagedByValue = "operator-autoscaler"
	// NodeGroupLabel is the label used to identify which node group a DaemonSet targets
	NodeGroupLabelKey = "kubescape.io/node-group"
)

// Autoscaler manages node-agent DaemonSets based on node groups
type Autoscaler struct {
	client           kubernetes.Interface
	config           config.NodeAgentAutoscalerConfig
	namespace        string
	nodeGrouper      *NodeGrouper
	templateRenderer *TemplateRenderer
	stopCh           chan struct{}
}

// NewAutoscaler creates a new Autoscaler instance
func NewAutoscaler(client kubernetes.Interface, cfg config.NodeAgentAutoscalerConfig, namespace string) (*Autoscaler, error) {
	templateRenderer, err := NewTemplateRenderer(cfg.TemplatePath)
	if err != nil {
		return nil, err
	}

	return &Autoscaler{
		client:           client,
		config:           cfg,
		namespace:        namespace,
		nodeGrouper:      NewNodeGrouper(client, cfg, namespace),
		templateRenderer: templateRenderer,
		stopCh:           make(chan struct{}),
	}, nil
}

// Start begins the autoscaler reconciliation loop
func (a *Autoscaler) Start(ctx context.Context) {
	logger.L().Info("starting node agent autoscaler",
		helpers.String("namespace", a.namespace),
		helpers.String("nodeGroupLabel", a.config.NodeGroupLabel),
		helpers.String("reconcileInterval", a.config.ReconcileInterval.String()))

	// Run initial reconciliation
	if err := a.Reconcile(ctx); err != nil {
		logger.L().Error("initial reconciliation failed", helpers.Error(err))
	}

	// Start reconciliation loop
	ticker := time.NewTicker(a.config.ReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L().Info("stopping node agent autoscaler")
			return
		case <-a.stopCh:
			logger.L().Info("stopping node agent autoscaler")
			return
		case <-ticker.C:
			if err := a.Reconcile(ctx); err != nil {
				logger.L().Error("reconciliation failed", helpers.Error(err))
			}
		}
	}
}

// Stop stops the autoscaler
func (a *Autoscaler) Stop() {
	close(a.stopCh)
}

// Reconcile performs a single reconciliation cycle
func (a *Autoscaler) Reconcile(ctx context.Context) error {
	logger.L().Debug("starting reconciliation")

	// Get current node groups
	nodeGroups, err := a.nodeGrouper.GetNodeGroups(ctx)
	if err != nil {
		return err
	}

	// Get existing managed DaemonSets
	existingDaemonSets, err := a.getManagedDaemonSets(ctx)
	if err != nil {
		return err
	}

	// Build a map of existing DaemonSets by node group
	existingByNodeGroup := make(map[string]*appsv1.DaemonSet)
	for i := range existingDaemonSets {
		ds := &existingDaemonSets[i]
		if nodeGroup, ok := ds.Labels[NodeGroupLabelKey]; ok {
			existingByNodeGroup[nodeGroup] = ds
		}
	}

	// Track which node groups we've processed
	processedNodeGroups := make(map[string]bool)

	// Create or update DaemonSets for each node group
	for _, group := range nodeGroups {
		processedNodeGroups[group.LabelValue] = true

		// Calculate resources for this group
		resources, err := a.nodeGrouper.CalculateResources(group)
		if err != nil {
			logger.L().Error("failed to calculate resources",
				helpers.String("nodeGroup", group.LabelValue),
				helpers.Error(err))
			continue
		}

		// Render the DaemonSet
		desiredDS, err := a.templateRenderer.RenderDaemonSet(group, resources)
		if err != nil {
			logger.L().Error("failed to render DaemonSet",
				helpers.String("nodeGroup", group.LabelValue),
				helpers.Error(err))
			continue
		}

		// Ensure labels are set
		if desiredDS.Labels == nil {
			desiredDS.Labels = make(map[string]string)
		}
		desiredDS.Labels[ManagedByLabel] = ManagedByValue
		desiredDS.Labels[NodeGroupLabelKey] = group.LabelValue

		// Check if DaemonSet exists
		if existingDS, exists := existingByNodeGroup[group.LabelValue]; exists {
			// Update if needed
			if err := a.updateDaemonSetIfNeeded(ctx, existingDS, desiredDS); err != nil {
				logger.L().Error("failed to update DaemonSet",
					helpers.String("name", desiredDS.Name),
					helpers.Error(err))
			}
		} else {
			// Create new DaemonSet
			if err := a.createDaemonSet(ctx, desiredDS); err != nil {
				logger.L().Error("failed to create DaemonSet",
					helpers.String("name", desiredDS.Name),
					helpers.Error(err))
			}
		}
	}

	// Delete orphaned DaemonSets (node groups that no longer exist)
	for nodeGroup, ds := range existingByNodeGroup {
		if !processedNodeGroups[nodeGroup] {
			if err := a.deleteDaemonSet(ctx, ds); err != nil {
				logger.L().Error("failed to delete orphaned DaemonSet",
					helpers.String("name", ds.Name),
					helpers.Error(err))
			}
		}
	}

	logger.L().Debug("reconciliation completed",
		helpers.Int("nodeGroups", len(nodeGroups)),
		helpers.Int("existingDaemonSets", len(existingDaemonSets)))

	return nil
}

// getManagedDaemonSets returns all DaemonSets managed by the autoscaler
func (a *Autoscaler) getManagedDaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error) {
	labelSelector := ManagedByLabel + "=" + ManagedByValue

	dsList, err := a.client.AppsV1().DaemonSets(a.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, err
	}

	return dsList.Items, nil
}

// createDaemonSet creates a new DaemonSet
func (a *Autoscaler) createDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	logger.L().Info("creating DaemonSet",
		helpers.String("name", ds.Name),
		helpers.String("namespace", a.namespace))

	_, err := a.client.AppsV1().DaemonSets(a.namespace).Create(ctx, ds, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			logger.L().Debug("DaemonSet already exists, will update instead",
				helpers.String("name", ds.Name))
			return a.updateDaemonSet(ctx, ds)
		}
		return err
	}

	return nil
}

// updateDaemonSetIfNeeded updates a DaemonSet if the spec has changed
func (a *Autoscaler) updateDaemonSetIfNeeded(ctx context.Context, existing, desired *appsv1.DaemonSet) error {
	// Compare the relevant parts of the spec
	if a.daemonSetNeedsUpdate(existing, desired) {
		return a.updateDaemonSet(ctx, desired)
	}

	logger.L().Debug("DaemonSet is up to date",
		helpers.String("name", existing.Name))
	return nil
}

// daemonSetNeedsUpdate checks if the DaemonSet needs to be updated
func (a *Autoscaler) daemonSetNeedsUpdate(existing, desired *appsv1.DaemonSet) bool {
	// Compare resource requests and limits for the node-agent container
	existingContainer := findNodeAgentContainer(existing)
	desiredContainer := findNodeAgentContainer(desired)

	if existingContainer == nil || desiredContainer == nil {
		return true
	}

	// Compare resources
	if !reflect.DeepEqual(existingContainer.Resources, desiredContainer.Resources) {
		logger.L().Debug("DaemonSet resources changed",
			helpers.String("name", existing.Name))
		return true
	}

	// Compare node selector
	if !reflect.DeepEqual(existing.Spec.Template.Spec.NodeSelector, desired.Spec.Template.Spec.NodeSelector) {
		logger.L().Debug("DaemonSet nodeSelector changed",
			helpers.String("name", existing.Name))
		return true
	}

	return false
}

// findNodeAgentContainer finds the node-agent container in a DaemonSet
func findNodeAgentContainer(ds *appsv1.DaemonSet) *corev1.Container {
	for i := range ds.Spec.Template.Spec.Containers {
		c := &ds.Spec.Template.Spec.Containers[i]
		if c.Name == "node-agent" {
			return c
		}
	}
	return nil
}

// updateDaemonSet updates an existing DaemonSet
func (a *Autoscaler) updateDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	logger.L().Info("updating DaemonSet",
		helpers.String("name", ds.Name),
		helpers.String("namespace", a.namespace))

	// Get the current version to set ResourceVersion
	existing, err := a.client.AppsV1().DaemonSets(a.namespace).Get(ctx, ds.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	ds.ResourceVersion = existing.ResourceVersion
	_, err = a.client.AppsV1().DaemonSets(a.namespace).Update(ctx, ds, metav1.UpdateOptions{})
	return err
}

// deleteDaemonSet deletes a DaemonSet
func (a *Autoscaler) deleteDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	logger.L().Info("deleting orphaned DaemonSet",
		helpers.String("name", ds.Name),
		helpers.String("namespace", a.namespace))

	return a.client.AppsV1().DaemonSets(a.namespace).Delete(ctx, ds.Name, metav1.DeleteOptions{})
}

