package watcher

import (
	"context"
	_ "embed"
	"errors"
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

func TestHandleApplicationProfileEvents(t *testing.T) {
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
			name: "Adding a new application profile should produce a matching scan command",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.ApplicationProfile{
						ObjectMeta: v1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d",
								helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
								helpersv1.CompletionMetadataKey: helpersv1.Complete,
								helpersv1.StatusMetadataKey:     helpersv1.Ready,
							},
						},
						Spec: spdxv1beta1.ApplicationProfileSpec{
							Containers: []spdxv1beta1.ApplicationProfileContainer{{
								Name:     "nginx",
								ImageID:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								ImageTag: "nginx:1.14.0",
							}},
						},
					},
				},
				{
					Type: watch.Modified,
					Object: &spdxv1beta1.ApplicationProfile{
						ObjectMeta: v1.ObjectMeta{
							Name: "replicaset-nginx-7584b6f84c",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-7584b6f84c",
								helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
								helpersv1.CompletionMetadataKey: helpersv1.Complete,
								helpersv1.StatusMetadataKey:     helpersv1.Ready,
							},
						},
						Spec: spdxv1beta1.ApplicationProfileSpec{
							InitContainers: []spdxv1beta1.ApplicationProfileContainer{{
								Name:     "nginx",
								ImageID:  "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
								ImageTag: "nginx:latest",
							}},
						},
					},
				},
			},
			expectedCommands: []*apis.Command{
				{
					CommandName: utils.CommandScanApplicationProfile,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-nginx-6ccd565b7d-nginx-49d3-1861",
							ImageID:       "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
							ImageTag:      "nginx:1.14.0",
							InstanceID:    "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d/containerName-nginx",
							ContainerName: "nginx",
							ContainerType: "container",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						},
					},
				},
				{
					CommandName: utils.CommandScanApplicationProfile,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-nginx-7584b6f84c-nginx-d01e-79cc",
							ImageID:       "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
							ImageTag:      "nginx:latest",
							InstanceID:    "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-7584b6f84c/initContainerName-nginx",
							ContainerName: "nginx",
							ContainerType: "initContainer",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						},
					},
				},
			},
			expectedObjectNames: []string{
				"replicaset-nginx-6ccd565b7d",
				"replicaset-nginx-7584b6f84c",
			},
			expectedSlugToImageIDMap: map[string]string{
				"replicaset-nginx-6ccd565b7d-nginx-49d3-1861": "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				"replicaset-nginx-7584b6f84c-nginx-d01e-79cc": "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
			},
			expectedWlidAndImageIDMap: []string{
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginxnginxdocker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginxnginxdocker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
			},
			expectedErrors: []error{},
		},
		{
			name: "Missing image tag",
			inputEvents: []watch.Event{
				{
					Type: watch.Added,
					Object: &spdxv1beta1.ApplicationProfile{
						ObjectMeta: v1.ObjectMeta{
							Name: "replicaset-nginx-6ccd565b7d",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d",
								helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
								helpersv1.CompletionMetadataKey: helpersv1.Complete,
								helpersv1.StatusMetadataKey:     helpersv1.Ready,
							},
						},
						Spec: spdxv1beta1.ApplicationProfileSpec{
							Containers: []spdxv1beta1.ApplicationProfileContainer{{
								Name:     "nginx",
								ImageID:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
								ImageTag: "", // missing image tag
							}},
						},
					},
				},
			},
			expectedCommands:          []*apis.Command{},
			expectedObjectNames:       []string{"replicaset-nginx-6ccd565b7d"},
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
					Object: &spdxv1beta1.ApplicationProfile{},
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

			k8sClient := k8sfake.NewClientset()
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset(startingObjects...)

			inputEvents := make(chan watch.Event)
			cmdCh := make(chan *apis.Command)
			errorCh := make(chan error)

			wh := NewWatchHandler(ctx, operatorConfig, k8sAPI, storageClient, nil)

			go wh.HandleApplicationProfileEvents(inputEvents, cmdCh, errorCh)

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

			actualObjects, _ := storageClient.SpdxV1beta1().ApplicationProfiles("").List(ctx, v1.ListOptions{})

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
			assert.Equal(t, len(tc.expectedErrors), len(actualErrors), "Errors don’t match")
			for i := range actualErrors {
				assert.True(t, errors.Is(actualErrors[i], tc.expectedErrors[i]), "Errors don’t match")
			}
			assert.Equal(t, tc.expectedCommands, actualCommands, "Commands don’t match")
		})

	}
}

func TestSkipAP(t *testing.T) {
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
			gotSkip := skipAP(tt.annotations)
			assert.Equal(t, tt.wantSkip, gotSkip)
		})
	}
}

func TestValidateContainerDataApplicationProfile(t *testing.T) {
	tests := []struct {
		wantErr       error
		containerData *utils.ContainerData
		name          string
	}{
		{
			name: "missing ContainerName",
			containerData: &utils.ContainerData{
				ImageID:    "imageID",
				Slug:       "slug",
				InstanceID: "TODO",
				Wlid:       "wlid",
				ImageTag:   "imageTag",
			},
			wantErr: ErrMissingContainerName,
		},
		{
			name: "missing ImageID",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				Slug:          "slug",
				InstanceID:    "TODO",
				Wlid:          "wlid",
				ImageTag:      "imageTag",
			},
			wantErr: ErrMissingImageID,
		},
		{
			name: "missing Slug",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				InstanceID:    "TODO",
				ImageID:       "imageID",
				Wlid:          "wlid",
				ImageTag:      "imageTag",
			},
			wantErr: ErrMissingSlug,
		},
		{
			name: "missing InstanceID",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				Slug:          "slug",
				ImageID:       "imageID",
				Wlid:          "wlid",
				ImageTag:      "imageTag",
			},
			wantErr: ErrMissingInstanceID,
		},
		{
			name: "missing WLID",
			containerData: &utils.ContainerData{
				ContainerName: "containerName",
				ImageID:       "imageID",
				Slug:          "slug",
				InstanceID:    "TODO",
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
				InstanceID:    "TODO",
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
				InstanceID:    "TODO",
				Wlid:          "wlid",
				ImageTag:      "imageTag",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContainerDataApplicationProfiles(tt.containerData)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}
