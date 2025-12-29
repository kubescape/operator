package nodeagentautoscaler

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

const (
	// ManagedByLabel is the label used to identify DaemonSets managed by the autoscaler
	ManagedByLabel = "kubescape.io/managed-by"
	// ManagedByValue is the value for the managed-by label
	ManagedByValue = "operator-autoscaler"
	// NodeGroupLabel is the label used to identify which node group a DaemonSet targets
	NodeGroupLabelKey = "kubescape.io/node-group"

	// ArgoCD annotations to prevent pruning of operator-managed resources
	ArgoCDCompareOptionsAnnotation = "argocd.argoproj.io/compare-options"
	ArgoCDSyncOptionsAnnotation    = "argocd.argoproj.io/sync-options"
)

// Event reasons for Kubernetes events
const (
	EventReasonCreated = "Created"
	EventReasonDeleted = "Deleted"
	EventReasonFailed  = "Failed"
)

// Autoscaler manages node-agent DaemonSets based on node groups
type Autoscaler struct {
	client               kubernetes.Interface
	config               config.NodeAgentAutoscalerConfig
	namespace            string
	nodeGrouper          *NodeGrouper
	templateRenderer     *TemplateRenderer
	stopCh               chan struct{}
	operatorDeployment   string // Name of the operator deployment (for owner references)
	ownerRef             *metav1.OwnerReference
	eventRecorder        record.EventRecorder
}

// NewAutoscaler creates a new Autoscaler instance
func NewAutoscaler(client kubernetes.Interface, cfg config.NodeAgentAutoscalerConfig, namespace string, operatorDeploymentName string) (*Autoscaler, error) {
	templateRenderer, err := NewTemplateRenderer(cfg.TemplatePath)
	if err != nil {
		return nil, err
	}

	// Create event broadcaster and recorder
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{
		Interface: client.CoreV1().Events(namespace),
	})
	eventRecorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{
		Component: "node-agent-autoscaler",
	})

	return &Autoscaler{
		client:             client,
		config:             cfg,
		namespace:          namespace,
		nodeGrouper:        NewNodeGrouper(client, cfg, namespace),
		templateRenderer:   templateRenderer,
		stopCh:             make(chan struct{}),
		operatorDeployment: operatorDeploymentName,
		eventRecorder:      eventRecorder,
	}, nil
}

// initOwnerReference looks up the operator deployment and caches the owner reference
func (a *Autoscaler) initOwnerReference(ctx context.Context) error {
	if a.operatorDeployment == "" {
		logger.L().Warning("operator deployment name not set, owner references will not be added to managed DaemonSets")
		return nil
	}

	deployment, err := a.client.AppsV1().Deployments(a.namespace).Get(ctx, a.operatorDeployment, metav1.GetOptions{})
	if err != nil {
		return err
	}

	blockOwnerDeletion := true
	controller := true
	a.ownerRef = &metav1.OwnerReference{
		APIVersion:         "apps/v1",
		Kind:               "Deployment",
		Name:               deployment.Name,
		UID:                deployment.UID,
		BlockOwnerDeletion: &blockOwnerDeletion,
		Controller:         &controller,
	}

	logger.L().Debug("initialized owner reference",
		helpers.String("deployment", deployment.Name),
		helpers.String("uid", string(deployment.UID)))

	return nil
}

// Start begins the autoscaler reconciliation loop
func (a *Autoscaler) Start(ctx context.Context) {
	logger.L().Info("starting node agent autoscaler",
		helpers.String("namespace", a.namespace),
		helpers.String("nodeGroupLabel", a.config.NodeGroupLabel),
		helpers.String("reconcileInterval", a.config.ReconcileInterval.String()))

	// Initialize owner reference for garbage collection
	if err := a.initOwnerReference(ctx); err != nil {
		logger.L().Error("failed to initialize owner reference, DaemonSets will not be garbage collected on helm uninstall",
			helpers.Error(err))
	}

	// Start watching template file for changes (auto-reload on ConfigMap update)
	if err := a.templateRenderer.StartWatching(ctx); err != nil {
		logger.L().Error("failed to start template file watcher, template changes will require operator restart",
			helpers.Error(err))
	}

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
			a.templateRenderer.StopWatching()
			return
		case <-a.stopCh:
			logger.L().Info("stopping node agent autoscaler")
			a.templateRenderer.StopWatching()
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

		// Add ArgoCD annotations to prevent pruning
		if desiredDS.Annotations == nil {
			desiredDS.Annotations = make(map[string]string)
		}
		desiredDS.Annotations[ArgoCDCompareOptionsAnnotation] = "IgnoreExtraneous"
		desiredDS.Annotations[ArgoCDSyncOptionsAnnotation] = "Prune=false"

		// Set owner reference to operator deployment for garbage collection
		if a.ownerRef != nil {
			desiredDS.OwnerReferences = []metav1.OwnerReference{*a.ownerRef}
		}

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

	createdDS, err := a.client.AppsV1().DaemonSets(a.namespace).Create(ctx, ds, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Check if the existing DaemonSet is managed by us before updating
			existing, getErr := a.client.AppsV1().DaemonSets(a.namespace).Get(ctx, ds.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			// Only update if managed by us - don't overwrite user-managed resources
			if existing.Labels[ManagedByLabel] != ManagedByValue {
				logger.L().Warning("DaemonSet already exists but is not managed by autoscaler, skipping",
					helpers.String("name", ds.Name),
					helpers.String("existingManagedBy", existing.Labels[ManagedByLabel]))
				return fmt.Errorf("DaemonSet %s already exists but is not managed by autoscaler", ds.Name)
			}
			logger.L().Debug("DaemonSet already exists and is managed by us, will update",
				helpers.String("name", ds.Name))
			return a.updateDaemonSetIfNeeded(ctx, existing, ds)
		}
		a.recordEvent(ds, corev1.EventTypeWarning, EventReasonFailed,
			fmt.Sprintf("Failed to create DaemonSet: %v", err))
		return err
	}

	// Record success event on the created DaemonSet
	nodeGroup := ds.Labels[NodeGroupLabelKey]
	a.recordEvent(createdDS, corev1.EventTypeNormal, EventReasonCreated,
		fmt.Sprintf("Created DaemonSet for node group %q", nodeGroup))

	return nil
}

// updateDaemonSetIfNeeded updates a DaemonSet to match the desired state
// We always call Update() and let Kubernetes handle idempotency.
// This is simpler than comparing specs field-by-field, and Kubernetes
// won't restart pods unless the PodTemplateSpec actually changes.
func (a *Autoscaler) updateDaemonSetIfNeeded(ctx context.Context, existing, desired *appsv1.DaemonSet) error {
	// Preserve existing metadata (resourceVersion is required for update)
	desired.ObjectMeta.ResourceVersion = existing.ObjectMeta.ResourceVersion
	desired.ObjectMeta.UID = existing.ObjectMeta.UID
	desired.ObjectMeta.CreationTimestamp = existing.ObjectMeta.CreationTimestamp

	// Ensure our management labels are set
	if desired.Labels == nil {
		desired.Labels = make(map[string]string)
	}
	desired.Labels[ManagedByLabel] = ManagedByValue

	logger.L().Debug("updating DaemonSet",
		helpers.String("name", desired.Name),
		helpers.String("namespace", a.namespace))

	_, err := a.client.AppsV1().DaemonSets(a.namespace).Update(ctx, desired, metav1.UpdateOptions{})
	if err != nil {
		a.recordEvent(desired, corev1.EventTypeWarning, EventReasonFailed,
			fmt.Sprintf("Failed to update DaemonSet: %v", err))
		return err
	}

	// Note: We don't record "Updated" events here since we always call Update()
	// and can't easily tell if anything actually changed. Create/Delete events
	// are still recorded and provide meaningful audit trail.

	return nil
}


// deleteDaemonSet deletes a DaemonSet
func (a *Autoscaler) deleteDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	logger.L().Info("deleting orphaned DaemonSet",
		helpers.String("name", ds.Name),
		helpers.String("namespace", a.namespace))

	nodeGroup := ds.Labels[NodeGroupLabelKey]

	// Record event before deletion (since we can't record on a deleted object)
	a.recordEvent(ds, corev1.EventTypeNormal, EventReasonDeleted,
		fmt.Sprintf("Deleting DaemonSet for removed node group %q", nodeGroup))

	err := a.client.AppsV1().DaemonSets(a.namespace).Delete(ctx, ds.Name, metav1.DeleteOptions{})
	if err != nil {
		a.recordEvent(ds, corev1.EventTypeWarning, EventReasonFailed,
			fmt.Sprintf("Failed to delete DaemonSet: %v", err))
		return err
	}

	return nil
}

// recordEvent records a Kubernetes event on the given object
func (a *Autoscaler) recordEvent(obj runtime.Object, eventType, reason, message string) {
	if a.eventRecorder != nil {
		a.eventRecorder.Event(obj, eventType, reason, message)
	}
}

