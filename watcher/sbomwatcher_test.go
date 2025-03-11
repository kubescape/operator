package watcher

import (
	"context"
	_ "embed"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestHandleSBOMEvents(t *testing.T) {
	tt := []struct {
		name                string
		inputEvents         []watch.Event
		expectedObjectNames []string
		expectedCommands    []*apis.Command
		expectedErrors      []error
	}{
		{
			name: "Adding a new SBOM should produce a matching scan command",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSyft{
						ObjectMeta: metav1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							Annotations: map[string]string{
								helpersv1.ImageIDMetadataKey:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								helpersv1.ImageTagMetadataKey: "nginx:1.14.0",
							},
						},
					},
				},
				{
					Type: watch.Modified,
					Object: &spdxv1beta1.SBOMSyft{
						ObjectMeta: metav1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-e4ff-657a",
							Annotations: map[string]string{
								helpersv1.ImageIDMetadataKey:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								helpersv1.ImageTagMetadataKey: "nginx:1.14.0",
							},
						},
					},
				},
			},
			expectedCommands: []*apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							ImageID:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
							ImageTag: "nginx:1.14.0",
						},
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							ImageID:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
							ImageTag: "nginx:1.14.0",
						},
					},
				},
			},
			expectedObjectNames: []string{
				"replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
				"replicaset-nginx-6ccd565b7d-nginx-e4ff-657a",
			},
		},
		{
			name: "Missing image tag",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSyft{
						ObjectMeta: metav1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							Annotations: map[string]string{
								helpersv1.ImageIDMetadataKey:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								helpersv1.ImageTagMetadataKey: "", // missing image tag
							},
						},
					},
				},
			},
			expectedObjectNames: []string{"replicaset-nginx-6ccd565b7d-nginx-49d3-1861"},
			expectedErrors: []error{
				ErrMissingImageTag,
			},
		},
		{
			name: "Delete event",
			inputEvents: []watch.Event{
				{
					Type:   watch.Deleted,
					Object: &spdxv1beta1.SBOMSyft{},
				},
			},
			expectedObjectNames: []string{""},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare starting startingObjects for storage
			var startingObjects []runtime.Object
			for _, e := range tc.inputEvents {
				startingObjects = append(startingObjects, e.Object)
			}

			ctx := context.Background()
			clusterConfig := utilsmetadata.ClusterConfig{}
			cfg, err := config.LoadConfig("../configuration")
			assert.NoError(t, err)
			operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, "", cfg)

			k8sClient := k8sfake.NewSimpleClientset()
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset(startingObjects...)

			inputEvents := make(chan watch.Event)
			cmdCh := make(chan *apis.Command)
			errorCh := make(chan error)

			wh := NewWatchHandler(operatorConfig, k8sAPI, storageClient, nil)

			go wh.HandleSBOMEvents(inputEvents, cmdCh, errorCh)

			go func() {
				for _, e := range tc.inputEvents {
					inputEvents <- e
				}

				close(inputEvents)
			}()

			done := false
			var actualErrors []error
			var actualCommands []*apis.Command
			for !done {
				select {
				case err, ok := <-errorCh:
					if !ok {
						done = true
						break
					}
					actualErrors = append(actualErrors, err)
				case cmd, ok := <-cmdCh:
					if !ok {
						done = true
						break
					}
					actualCommands = append(actualCommands, cmd)
				}
			}

			actualObjects, _ := storageClient.SpdxV1beta1().SBOMSyfts("").List(ctx, metav1.ListOptions{})

			var actualObjectNames []string
			for _, obj := range actualObjects.Items {
				actualObjectNames = append(actualObjectNames, obj.ObjectMeta.Name)
			}

			assert.Equal(t, tc.expectedObjectNames, actualObjectNames, "Objects in the storage don’t match")
			assert.Equal(t, tc.expectedErrors, actualErrors, "Errors don’t match")
			assert.Equal(t, tc.expectedCommands, actualCommands, "Commands don’t match")
		})

	}
}
