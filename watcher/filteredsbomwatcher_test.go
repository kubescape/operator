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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestNewWatchHandlerProducesValidResult(t *testing.T) {
	tt := []struct {
		imageIDsToWLIDSsMap map[string][]string
		expectedIWMap       map[string][]string
		name                string
	}{
		{
			name:                "Creating with provided empty map returns matching empty map",
			imageIDsToWLIDSsMap: map[string][]string{},
			expectedIWMap:       map[string][]string{},
		},
		{
			name:                "Creating with provided nil map returns matching empty map",
			imageIDsToWLIDSsMap: nil,
			expectedIWMap:       map[string][]string{},
		},
		{
			name: "Creating with provided non-empty map returns matching map",
			imageIDsToWLIDSsMap: map[string][]string{
				"imageid-01": {"wlid-01"},
			},
			expectedIWMap: map[string][]string{
				"imageid-01": {"wlid-01"},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.TODO()
			clusterConfig := utilsmetadata.ClusterConfig{}
			cfg, err := config.LoadConfig("../configuration")
			assert.NoError(t, err)
			operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, "", cfg)

			k8sClient := k8sfake.NewSimpleClientset()
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset()

			wh := NewWatchHandler(ctx, operatorConfig, k8sAPI, storageClient, nil)

			assert.NotNilf(t, wh, "Constructing should create a non-nil object")
		})
	}
}

func TestHandleSBOMFilteredEvents(t *testing.T) {
	tt := []struct {
		name                      string
		inputEvents               []watch.Event
		expectedObjectNames       []string
		expectedCommands          []*apis.Command
		expectedErrors            []error
		expectedSlugToImageIDMap  map[string]string
		expectedWlidAndImageIDMap []string
	}{
		{
			name: "Adding a new Filtered SBOM should produce a matching scan command",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSyftFiltered{
						ObjectMeta: v1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey:    "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d/containerName-nginx",
								helpersv1.WlidMetadataKey:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
								helpersv1.ImageIDMetadataKey:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								helpersv1.ImageTagMetadataKey:      "nginx:1.14.0",
								helpersv1.ContainerNameMetadataKey: "nginx",
							},
						},
					},
				},
				{
					Type: watch.Modified,
					Object: &spdxv1beta1.SBOMSyftFiltered{
						ObjectMeta: v1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-e4ff-657a",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey:    "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d/initContainerName-nginx",
								helpersv1.WlidMetadataKey:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
								helpersv1.ImageIDMetadataKey:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								helpersv1.ImageTagMetadataKey:      "nginx:1.14.0",
								helpersv1.ContainerNameMetadataKey: "nginx",
							},
						},
					},
				},
			},
			expectedCommands: []*apis.Command{
				{
					CommandName: utils.CommandScanFilteredSBOM,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							ImageID:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
							ImageTag:      "nginx:1.14.0",
							ContainerName: "nginx",
							ContainerType: "container",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						},
					},
				},
				{
					CommandName: utils.CommandScanFilteredSBOM,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-nginx-6ccd565b7d-nginx-e4ff-657a",
							ImageID:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
							ImageTag:      "nginx:1.14.0",
							ContainerName: "nginx",
							ContainerType: "initContainer",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						},
					},
				},
			},
			expectedObjectNames: []string{
				"replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
				"replicaset-nginx-6ccd565b7d-nginx-e4ff-657a",
			},
			expectedSlugToImageIDMap: map[string]string{
				"replicaset-nginx-6ccd565b7d-nginx-49d3-1861": "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				"replicaset-nginx-6ccd565b7d-nginx-e4ff-657a": "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
			},
			expectedWlidAndImageIDMap: []string{
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx" + "nginx" + "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
			},
			expectedErrors: []error{},
		},
		{
			name: "Missing image tag",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.SBOMSyftFiltered{
						ObjectMeta: v1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey:    "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d/containerName-nginx",
								helpersv1.WlidMetadataKey:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
								helpersv1.ImageIDMetadataKey:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								helpersv1.ImageTagMetadataKey:      "", // missing image tag
								helpersv1.ContainerNameMetadataKey: "nginx",
							},
						},
					},
				},
			},
			expectedCommands:          []*apis.Command{},
			expectedObjectNames:       []string{"replicaset-nginx-6ccd565b7d-nginx-49d3-1861"},
			expectedSlugToImageIDMap:  map[string]string{},
			expectedWlidAndImageIDMap: []string{},
			expectedErrors: []error{
				ErrMissingImageTag,
			},
		},
		{
			name: "Delete event",
			inputEvents: []watch.Event{
				{
					Type:   watch.Deleted,
					Object: &spdxv1beta1.SBOMSyftFiltered{},
				},
			},
			expectedCommands:          []*apis.Command{},
			expectedObjectNames:       []string{""},
			expectedSlugToImageIDMap:  map[string]string{},
			expectedWlidAndImageIDMap: []string{},
			expectedErrors:            []error{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare starting startingObjects for storage
			startingObjects := []runtime.Object{}
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

			wh := NewWatchHandler(ctx, operatorConfig, k8sAPI, storageClient, nil)

			go wh.HandleSBOMFilteredEvents(inputEvents, cmdCh, errorCh)

			go func() {
				for _, e := range tc.inputEvents {
					inputEvents <- e
				}

				close(inputEvents)
			}()

			done := false
			actualErrors := []error{}
			actualCommands := []*apis.Command{}
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

			actualObjects, _ := storageClient.SpdxV1beta1().SBOMSyftFiltereds("").List(ctx, v1.ListOptions{})

			actualObjectNames := []string{}
			for _, obj := range actualObjects.Items {
				actualObjectNames = append(actualObjectNames, obj.ObjectMeta.Name)
			}

			// test slug to image ID map
			assert.Equal(t, len(tc.expectedSlugToImageIDMap), wh.SlugToImageID.Len(), "Slug to image ID map doesn’t match")
			for k, v := range tc.expectedSlugToImageIDMap {
				assert.Equal(t, v, wh.SlugToImageID.Get(k), "Slug to image ID map doesn’t match")
			}

			// test expectedWlidAndImageIDMap
			assert.Equal(t, len(tc.expectedWlidAndImageIDMap), wh.WlidAndImageID.Cardinality(), "Wlid and image ID map doesn’t match")
			for _, v := range tc.expectedWlidAndImageIDMap {
				assert.True(t, wh.WlidAndImageID.Contains(v), "Wlid and image ID map doesn’t match")
			}

			assert.Equal(t, tc.expectedObjectNames, actualObjectNames, "Objects in the storage don’t match")
			assert.Equal(t, tc.expectedErrors, actualErrors, "Errors don’t match")
			assert.Equal(t, tc.expectedCommands, actualCommands, "Commands don’t match")
		})

	}
}
func TestGetContainerDataFilteredSBOM(t *testing.T) {
	tests := []struct {
		obj     *spdxv1beta1.SBOMSyftFiltered
		want    *utils.ContainerData
		name    string
		wantErr bool
	}{
		{
			name: "valid SBOMSyftFiltered object",
			obj: &spdxv1beta1.SBOMSyftFiltered{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						helpersv1.InstanceIDMetadataKey:    "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d/containerName-nginx",
						helpersv1.WlidMetadataKey:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						helpersv1.ImageIDMetadataKey:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
						helpersv1.ImageTagMetadataKey:      "nginx:1.14.1",
						helpersv1.ContainerNameMetadataKey: "nginx",
					},
				},
			},
			want: &utils.ContainerData{
				Slug:          "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
				Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
				ContainerName: "nginx",
				ContainerType: "container",
				ImageID:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				ImageTag:      "nginx:1.14.1",
			},
			wantErr: false,
		},
		{
			name: "invalid SBOMSyftFiltered object - missing instanceID",
			obj: &spdxv1beta1.SBOMSyftFiltered{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						helpersv1.InstanceIDMetadataKey:    "",
						helpersv1.WlidMetadataKey:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						helpersv1.ImageIDMetadataKey:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
						helpersv1.ImageTagMetadataKey:      "nginx:1.14.1",
						helpersv1.ContainerNameMetadataKey: "nginx",
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid SBOMSyftFiltered object - missing other fields",
			obj: &spdxv1beta1.SBOMSyftFiltered{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						helpersv1.InstanceIDMetadataKey:    "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d/containerName-nginx",
						helpersv1.WlidMetadataKey:          "",
						helpersv1.ImageIDMetadataKey:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
						helpersv1.ImageTagMetadataKey:      "nginx:1.14.1",
						helpersv1.ContainerNameMetadataKey: "nginx",
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}

	wh := &WatchHandler{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := wh.getContainerDataFilteredSBOM(tt.obj)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}
func TestAnnotationsToContainerData(t *testing.T) {
	tests := []struct {
		annotations map[string]string
		wantData    *utils.ContainerData
		name        string
		wantErr     bool
	}{
		{
			name: "valid annotations",
			annotations: map[string]string{
				helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d/containerName-nginx",
				helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
				helpersv1.ImageIDMetadataKey:    "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				helpersv1.ImageTagMetadataKey:   "nginx:1.14.1",
			},
			wantData: &utils.ContainerData{
				Slug:          "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
				Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
				ContainerName: "nginx",
				ContainerType: "container",
				ImageID:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				ImageTag:      "nginx:1.14.1",
			},
			wantErr: false,
		},
		{
			name: "missing instance ID annotation",
			annotations: map[string]string{
				helpersv1.WlidMetadataKey:     "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
				helpersv1.ImageIDMetadataKey:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				helpersv1.ImageTagMetadataKey: "nginx:1.14.1",
			},
			wantData: &utils.ContainerData{},
			wantErr:  true,
		},
		{
			name: "invalid instance ID annotation",
			annotations: map[string]string{
				helpersv1.InstanceIDMetadataKey: "invalidInstanceID",
				helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
				helpersv1.ImageIDMetadataKey:    "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				helpersv1.ImageTagMetadataKey:   "nginx:1.14.1",
			},
			wantData: &utils.ContainerData{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, gotErr := annotationsToContainerData(tt.annotations)
			assert.Equal(t, tt.wantData, gotData)
			assert.Equal(t, tt.wantErr, gotErr != nil)
		})
	}
}
func TestSkipSBOM(t *testing.T) {
	tests := []struct {
		annotations map[string]string
		name        string
		wantSkip    bool
	}{
		{
			name: "status is empty",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: "",
			},
			wantSkip: false,
		},
		{
			name: "status is Ready",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: helpersv1.Ready,
			},
			wantSkip: false,
		},
		{
			name: "status is Completed",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: helpersv1.Completed,
			},
			wantSkip: false,
		},
		{
			name: "status is not recognized",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: "NotRecognized",
			},
			wantSkip: true,
		},
		{
			name:        "no status annotation",
			annotations: map[string]string{},
			wantSkip:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSkip := skipSBOM(tt.annotations)
			assert.Equal(t, tt.wantSkip, gotSkip)
		})
	}
}
func TestValidateContainerDataFilteredSBOM(t *testing.T) {
	tests := []struct {
		wantErr       error
		containerData *utils.ContainerData
		name          string
	}{
		{
			name: "missing ContainerName",
			containerData: &utils.ContainerData{
				ImageID:  "imageID",
				Slug:     "slug",
				Wlid:     "wlid",
				ImageTag: "imageTag",
			},
			wantErr: ErrMissingContainerName,
		},
		{
			name: "missing ImageID",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				Slug:          "slug",
				Wlid:          "wlid",
				ImageTag:      "imageTag",
			},
			wantErr: ErrMissingImageID,
		},
		{
			name: "missing Slug",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				ImageID:       "imageID",
				Wlid:          "wlid",
				ImageTag:      "imageTag",
			},
			wantErr: ErrMissingSlug,
		},
		{
			name: "missing WLID",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				ImageID:       "imageID",
				Slug:          "slug",
				ImageTag:      "imageTag",
			},
			wantErr: ErrMissingWLID,
		},
		{
			name: "missing ImageTag",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				ImageID:       "imageID",
				Slug:          "slug",
				Wlid:          "wlid",
			},
			wantErr: ErrMissingImageTag,
		},
		{
			name: "valid ContainerData",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				ImageID:       "imageID",
				Slug:          "slug",
				Wlid:          "wlid",
				ImageTag:      "imageTag",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContainerDataFilteredSBOM(tt.containerData)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}
