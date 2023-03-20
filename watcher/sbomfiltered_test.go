package watcher

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type clusterNameResolverDummy struct {
	returnedName string
}

func (c *clusterNameResolverDummy) ResolveClusterName() string {
	return c.returnedName
}

func TestSBOMFilteredHandlerNew(t *testing.T) {
	cnr := &clusterNameResolverDummy{}
	sfh := NewSBOMFilteredHandler(cnr)

	assert.NotNilf(t, sfh, "The returned handler should not be nil")
	assert.Equalf(t, cnr, sfh.clusterNameResolver, "Cluster name resolvers should match")
}

func TestSBOMFilteredHandlerHandleAddedEvent(t *testing.T) {
	tt := []struct {
		name             string
		inputClusterName string
		inputEvent       watch.Event
		expectedCommand  *apis.Command
		expectedError    error
	}{
		{
			name:             "Valid event produces matching command",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type: watch.Added,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"kubescape.io/workload-namespace": "routing",
							"kubescape.io/workload-kind":      "deployment",
							"kubescape.io/workload-name":      "nginx-main-router",
						},
					},
				},
			},
			expectedCommand: &apis.Command{
				Wlid:        "wlid://cluster-relevantCluster/namespace-routing/deployment-nginx-main-router",
				CommandName: apis.TypeScanImages,
				Args: map[string]interface{}{
					utils.ContainerToImageIdsArg: map[string]string{},
				},
			},
		},
		{
			name:             "Valid event produces matching command",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type: watch.Added,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"kubescape.io/workload-namespace": "routing",
							"kubescape.io/workload-kind":      "Deployment",
							"kubescape.io/workload-name":      "nginx-router-replica",
						},
					},
				},
			},
			expectedCommand: &apis.Command{
				Wlid:        "wlid://cluster-relevantCluster/namespace-routing/deployment-nginx-router-replica",
				CommandName: apis.TypeScanImages,
				Args: map[string]interface{}{
					utils.ContainerToImageIdsArg: map[string]string{},
				},
			},
		},
		{
			name:             "Missing workload namespace label produces an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type: watch.Added,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"kubescape.io/workload-kind": "Deployment",
							"kubescape.io/workload-name": "nginx-router-replica",
						},
					},
				},
			},
			expectedCommand: nil,
			expectedError:   ErrMissingWorkloadLabel,
		},
		{
			name:             "Missing workload kind label produces an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type: watch.Added,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"kubescape.io/workload-namespace": "routing",
							"kubescape.io/workload-name":      "nginx-router-replica",
						},
					},
				},
			},
			expectedCommand: nil,
			expectedError:   ErrMissingWorkloadLabel,
		},
		{
			name:             "Missing workload name label produces an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type: watch.Added,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"kubescape.io/workload-namespace": "routing",
							"kubescape.io/workload-kind":      "Deployment",
						},
					},
				},
			},
			expectedCommand: nil,
			expectedError:   ErrMissingWorkloadLabel,
		},
		{
			name:             "Unsupported object type in event produces an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type:   watch.Added,
				Object: &spdxv1beta1.SBOMSPDXv2p3{},
			},
			expectedCommand: nil,
			expectedError:   ErrUnsupportedObject,
		},
		{
			name:             "Attempts to process a Bookmark event returns an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type:   watch.Bookmark,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{},
			},
			expectedCommand: nil,
			expectedError:   ErrUnsupportedEvent,
		},
		{
			name:             "Attempts to process a Deleted event returns an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type:   watch.Deleted,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{},
			},
			expectedCommand: nil,
			expectedError:   ErrUnsupportedEvent,
		},
		{
			name:             "Attempts to process a Modified event returns an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type:   watch.Modified,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{},
			},
			expectedCommand: nil,
			expectedError:   ErrUnsupportedEvent,
		},
		{
			name:             "Attempts to process an Error event returns an appropriate error",
			inputClusterName: "relevantCluster",
			inputEvent: watch.Event{
				Type:   watch.Error,
				Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{},
			},
			expectedCommand: nil,
			expectedError:   ErrUnsupportedEvent,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			clusterNameResolver := &clusterNameResolverDummy{tc.inputClusterName}
			sfh := NewSBOMFilteredHandler(clusterNameResolver)

			actualCommand, err := sfh.HandleAddedEvent(tc.inputEvent)

			assert.Equalf(t, tc.expectedCommand, actualCommand, "Commands should match")
			assert.Equalf(t, tc.expectedError, err, "Expected errors should match")
		})
	}
}

func TestSBOMFilteredHandlerHandleEvents(t *testing.T) {
	tt := []struct {
		name             string
		inputClusterName string
		inputEvents      []watch.Event
		expectedCommands []apis.Command
		expectedErrors   []error
	}{
		{
			name:             "Added event gets an appropriate result",
			inputClusterName: "relevancyCluster",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: metav1.ObjectMeta{
							Name: "testName",
							Labels: map[string]string{
								"kubescape.io/workload-namespace": "routing",
								"kubescape.io/workload-kind":      "Deployment",
								"kubescape.io/workload-name":      "edge-nginx",
							},
						},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-relevancyCluster/namespace-routing/deployment-edge-nginx",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{},
		},
		{
			name: "Bookmark event gets ignored",
			inputEvents: []watch.Event{
				{
					Type:   watch.Bookmark,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{},
				},
			},
			expectedCommands: []apis.Command{},
			expectedErrors:   []error{},
		},
		{
			name: "Deleted event gets ignored",
			inputEvents: []watch.Event{
				{
					Type:   watch.Deleted,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{},
				},
			},
			expectedCommands: []apis.Command{},
			expectedErrors:   []error{},
		},
		{
			name:             "Added event gets an appropriate result",
			inputClusterName: "relevancyCluster",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"kubescape.io/workload-namespace": "edge-routing",
								"kubescape.io/workload-kind":      "Deployment",
								"kubescape.io/workload-name":      "nginx-router",
							},
						},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-relevancyCluster/namespace-edge-routing/deployment-nginx-router",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{},
		},
		{
			name: "Mismatched object gets an appropriate error",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{},
					},
				},
			},
			expectedCommands: []apis.Command{},
			expectedErrors:   []error{ErrUnsupportedObject},
		},
		{
			name:             "Skipped event does not disrupt listeners",
			inputClusterName: "relevantCluster",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"kubescape.io/workload-namespace": "edge-routing",
								"kubescape.io/workload-kind":      "Deployment",
								"kubescape.io/workload-name":      "nginx-router",
							},
						},
					},
				},
				{
					Type: watch.Bookmark,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: metav1.ObjectMeta{},
					},
				},
				{
					Type: watch.Added,
					Object: &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-relevantCluster/namespace-edge-routing/deployment-nginx-router",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{ErrUnsupportedObject},
		},
		{
			name:             "Multiple added events produce matching commands",
			inputClusterName: "relevantCluster",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"kubescape.io/workload-namespace": "edge-routing",
								"kubescape.io/workload-kind":      "Deployment",
								"kubescape.io/workload-name":      "nginx-router",
							},
						},
					},
				},
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSPDXv2p3Filtered{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"kubescape.io/workload-namespace": "backbone",
								"kubescape.io/workload-kind":      "StatefulSet",
								"kubescape.io/workload-name":      "postgres-leader",
							},
						},
					},
				},
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-relevantCluster/namespace-edge-routing/deployment-nginx-router",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-relevantCluster/namespace-backbone/statefulset-postgres-leader",
					Args: map[string]interface{}{
						utils.ContainerToImageIdsArg: map[string]string{},
					},
				},
			},
			expectedErrors: []error{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			cnr := &clusterNameResolverDummy{tc.inputClusterName}
			sfh := NewSBOMFilteredHandler(cnr)

			commandsCh := make(chan *apis.Command)
			errCh := make(chan error)

			sbomFilteredEvents := make(chan watch.Event)

			go func() {
				for _, event := range tc.inputEvents {
					sbomFilteredEvents <- event
				}

				close(sbomFilteredEvents)
			}()

			go sfh.HandleEvents(sbomFilteredEvents, commandsCh, errCh)

			actualCommands := []apis.Command{}
			actualErrors := []error{}

			var done bool
			for !done {
				select {
				case command, ok := <-commandsCh:
					if ok {
						actualCommands = append(actualCommands, *command)
					} else {
						done = true
					}
				case err, ok := <-errCh:
					if ok {
						actualErrors = append(actualErrors, err)
					} else {
						done = true
					}
				}
			}

			assert.Equalf(t, tc.expectedCommands, actualCommands, "Commands should match")
			assert.Equalf(t, tc.expectedErrors, actualErrors, "Errors should match")
		})
	}
}

func TestSBOMFilteredHandlerHandle(t *testing.T) {
	tt := []struct {
		name string
	}{
		{
			name: "TODO",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
		})
	}
}
