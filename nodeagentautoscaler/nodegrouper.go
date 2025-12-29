package nodeagentautoscaler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NodeGroup represents a group of nodes with the same label value
type NodeGroup struct {
	// LabelValue is the value of the grouping label (e.g., "m5.large")
	LabelValue string
	// SanitizedName is a DNS-safe name derived from LabelValue
	SanitizedName string
	// AllocatableCPU is the representative allocatable CPU from nodes in this group
	AllocatableCPU resource.Quantity
	// AllocatableMemory is the representative allocatable memory from nodes in this group
	AllocatableMemory resource.Quantity
	// NodeCount is the number of nodes in this group
	NodeCount int
}

// CalculatedResources represents the calculated resource requests and limits
type CalculatedResources struct {
	Requests ResourcePair
	Limits   ResourcePair
}

// ResourcePair holds CPU and Memory quantities
type ResourcePair struct {
	CPU    resource.Quantity
	Memory resource.Quantity
}

// NodeGrouper groups nodes by label and calculates resources
type NodeGrouper struct {
	client    kubernetes.Interface
	config    config.NodeAgentAutoscalerConfig
	namespace string
}

// NewNodeGrouper creates a new NodeGrouper
func NewNodeGrouper(client kubernetes.Interface, cfg config.NodeAgentAutoscalerConfig, namespace string) *NodeGrouper {
	return &NodeGrouper{
		client:    client,
		config:    cfg,
		namespace: namespace,
	}
}

// GetNodeGroups returns all node groups based on the configured label
func (ng *NodeGrouper) GetNodeGroups(ctx context.Context) ([]NodeGroup, error) {
	nodes, err := ng.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Group nodes by label value
	groupMap := make(map[string]*NodeGroup)

	for _, node := range nodes.Items {
		// Skip nodes that are not ready
		if !isNodeReady(&node) {
			continue
		}

		labelValue, ok := node.Labels[ng.config.NodeGroupLabel]
		if !ok {
			// If label doesn't exist, log an error and skip this node
			// Cloud managed Kubernetes (AKS, EKS, GKE) populate this field automatically
			// For on-prem or custom clusters, the infrastructure must be configured to set this label
			logger.L().Ctx(ctx).Error("node missing required label for autoscaler, node-agent will not be deployed on this node",
				helpers.String("node", node.Name),
				helpers.String("requiredLabel", ng.config.NodeGroupLabel))
			continue
		}

		if group, exists := groupMap[labelValue]; exists {
			group.NodeCount++
		} else {
			groupMap[labelValue] = &NodeGroup{
				LabelValue:        labelValue,
				SanitizedName:     sanitizeName(labelValue),
				AllocatableCPU:    *node.Status.Allocatable.Cpu(),
				AllocatableMemory: *node.Status.Allocatable.Memory(),
				NodeCount:         1,
			}
		}
	}

	// Convert map to slice
	groups := make([]NodeGroup, 0, len(groupMap))
	for _, group := range groupMap {
		groups = append(groups, *group)
	}

	// Detect and resolve naming collisions
	groups = resolveNameCollisions(groups)

	logger.L().Debug("discovered node groups",
		helpers.Int("count", len(groups)),
		helpers.String("label", ng.config.NodeGroupLabel))

	return groups, nil
}

// CalculateResources calculates the resource requests and limits for a node group
func (ng *NodeGrouper) CalculateResources(group NodeGroup) (CalculatedResources, error) {
	// Parse min/max bounds
	minCPU, err := resource.ParseQuantity(ng.config.MinResources.CPU)
	if err != nil {
		return CalculatedResources{}, err
	}
	minMemory, err := resource.ParseQuantity(ng.config.MinResources.Memory)
	if err != nil {
		return CalculatedResources{}, err
	}
	maxCPU, err := resource.ParseQuantity(ng.config.MaxResources.CPU)
	if err != nil {
		return CalculatedResources{}, err
	}
	maxMemory, err := resource.ParseQuantity(ng.config.MaxResources.Memory)
	if err != nil {
		return CalculatedResources{}, err
	}

	// Calculate request CPU: nodeAllocatableCPU * requestCPUPercent / 100
	requestCPU := calculatePercentage(group.AllocatableCPU, ng.config.ResourcePercentages.RequestCPU)
	requestCPU = clampQuantity(requestCPU, minCPU, maxCPU)

	// Calculate request Memory
	requestMemory := calculatePercentage(group.AllocatableMemory, ng.config.ResourcePercentages.RequestMemory)
	requestMemory = clampQuantity(requestMemory, minMemory, maxMemory)

	// Calculate limit CPU
	limitCPU := calculatePercentage(group.AllocatableCPU, ng.config.ResourcePercentages.LimitCPU)
	limitCPU = clampQuantity(limitCPU, minCPU, maxCPU)

	// Calculate limit Memory
	limitMemory := calculatePercentage(group.AllocatableMemory, ng.config.ResourcePercentages.LimitMemory)
	limitMemory = clampQuantity(limitMemory, minMemory, maxMemory)

	return CalculatedResources{
		Requests: ResourcePair{
			CPU:    requestCPU,
			Memory: requestMemory,
		},
		Limits: ResourcePair{
			CPU:    limitCPU,
			Memory: limitMemory,
		},
	}, nil
}

// calculatePercentage calculates percentage of a quantity
func calculatePercentage(q resource.Quantity, percent int) resource.Quantity {
	// For memory (BinarySI format), work with raw values to preserve proper units
	if q.Format == resource.BinarySI {
		// Get value in bytes (or base unit)
		value := q.Value()
		result := value * int64(percent) / 100
		return *resource.NewQuantity(result, resource.BinarySI)
	}

	// For CPU and other formats, use milli-units for precision
	milliValue := q.MilliValue()
	result := milliValue * int64(percent) / 100
	return *resource.NewMilliQuantity(result, q.Format)
}

// clampQuantity ensures the quantity is within min and max bounds
func clampQuantity(q, min, max resource.Quantity) resource.Quantity {
	if q.Cmp(min) < 0 {
		return min
	}
	if q.Cmp(max) > 0 {
		return max
	}
	return q
}

// sanitizeName converts a label value to a DNS-safe name
func sanitizeName(name string) string {
	// Replace any non-alphanumeric characters with dashes
	reg := regexp.MustCompile("[^a-zA-Z0-9]+")
	sanitized := reg.ReplaceAllString(name, "-")

	// Convert to lowercase
	sanitized = strings.ToLower(sanitized)

	// Remove leading/trailing dashes
	sanitized = strings.Trim(sanitized, "-")

	// Ensure it's not empty
	if sanitized == "" {
		sanitized = "default"
	}

	// Truncate to max length (63 chars for DNS names, minus prefix)
	maxLen := 50 // Leave room for "node-agent-" prefix
	if len(sanitized) > maxLen {
		sanitized = sanitized[:maxLen]
	}

	return sanitized
}

// resolveNameCollisions detects sanitized name collisions and adds hash suffixes to resolve them
// For example, if "m5.large" and "m5_large" both sanitize to "m5-large", this function
// will rename them to "m5-large-a1b2c3" and "m5-large-d4e5f6" respectively
func resolveNameCollisions(groups []NodeGroup) []NodeGroup {
	// Build map of sanitized names to detect collisions
	sanitizedToIndices := make(map[string][]int)
	for i := range groups {
		sanitizedToIndices[groups[i].SanitizedName] = append(sanitizedToIndices[groups[i].SanitizedName], i)
	}

	// Add short hash suffix for collisions
	for sanitized, indices := range sanitizedToIndices {
		if len(indices) > 1 {
			logger.L().Warning("detected sanitized name collision, adding hash suffix to disambiguate",
				helpers.String("sanitizedName", sanitized),
				helpers.Int("collisionCount", len(indices)))

			for _, idx := range indices {
				hash := shortHash(groups[idx].LabelValue)
				groups[idx].SanitizedName = sanitized + "-" + hash
			}
		}
	}

	return groups
}

// shortHash returns a short (6 character) hash of the input string
func shortHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:6]
}

// isNodeReady checks if a node is in Ready condition
func isNodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

