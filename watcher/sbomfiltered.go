package watcher

import (
	"github.com/armosec/armoapi-go/apis"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	workloadNamespaceLabel = "kubescape.io/workload-namespace"
	workloadKindLabel      = "kubescape.io/workload-kind"
	workloadNameLabel      = "kubescape.io/workload-name"
)

func labelsToNamespaceKindName(s *spdxv1beta1.SBOMSPDXv2p3Filtered) (string, string, string, error) {
	labels := s.ObjectMeta.Labels

	namespace, namespaceOk := labels[workloadNamespaceLabel]
	kind, kindOk := labels[workloadKindLabel]
	name, nameOk := labels[workloadNameLabel]
	if !(namespaceOk && kindOk && nameOk) {
		return namespace, kind, name, ErrMissingWorkloadLabel
	}

	return namespace, kind, name, nil
}

// ClusterNameResolvery is an interface for objects that can resolve the name
// of a cluster we are currently running in
type ClusterNameResolver interface {
	// ResolveClusterName returns a name of a cluster we are currently running in
	ResolveClusterName() string
}

// SBOMFilteredHandler handles operations that concern Filtered SBOMs
type SBOMFilteredHandler struct {
	clusterNameResolver ClusterNameResolver
}

// NewSBOMFilteredHandler returns a new instance of an SBOMFilteredHandler
func NewSBOMFilteredHandler(cnr ClusterNameResolver) *SBOMFilteredHandler {
	return &SBOMFilteredHandler{clusterNameResolver: cnr}
}

// HandleAddedEvent handles events about adding a new Filtered SBOM
func (h *SBOMFilteredHandler) HandleAddedEvent(event watch.Event) (*apis.Command, error) {
	if event.Type != watch.Added {
		return nil, ErrUnsupportedEvent
	}

	clusterName := h.clusterNameResolver.ResolveClusterName()

	sbomFiltered, ok := event.Object.(*spdxv1beta1.SBOMSPDXv2p3Filtered)
	if !ok {
		return nil, ErrUnsupportedObject
	}
	namespace, kind, name, err := labelsToNamespaceKindName(sbomFiltered)
	if err != nil {
		return nil, err
	}

	wlid := pkgwlid.GetWLID(clusterName, namespace, kind, name)

	return getCVEScanCommand(wlid, map[string]string{}), nil
}

// HandleEvents continuously handles events about Filtered SBOMs
func (h *SBOMFilteredHandler) HandleEvents(inputEvents <-chan watch.Event, producedCommands chan<- *apis.Command, producedErrors chan<- error) {
	defer func() {
		close(producedCommands)
		close(producedErrors)
	}()

	for event := range inputEvents {
		if event.Type != watch.Added {
			continue
		}

		command, err := h.HandleAddedEvent(event)
		if err != nil {
			producedErrors <- err
		} else {
			producedCommands <- command
		}
	}
}
