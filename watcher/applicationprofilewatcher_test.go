package watcher

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestHandleApplicationProfileEvents(t *testing.T) {
	tt := []struct {
		name                      string
		inputEvents               []watch.Event
		objects                   []runtime.Object
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
						ObjectMeta: metav1.ObjectMeta{
							Name:      "replicaset-nginx-6ccd565b7d",
							Namespace: "systest-ns-rarz",
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
						ObjectMeta: metav1.ObjectMeta{
							Name:      "replicaset-nginx-7584b6f84c",
							Namespace: "systest-ns-rarz",
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
				{
					Type: watch.Added,
					Object: &spdxv1beta1.ApplicationProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "workflow-foo-1747274700",
							Namespace: "systest-ns-rarz",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey: "apiVersion-aroproj.io/v1alpha/namespace-systest-ns-rarz/kind-Workflow/name-foo-1747274700",
								helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/pod-foo-1747274700",
								helpersv1.CompletionMetadataKey: helpersv1.Complete,
								helpersv1.StatusMetadataKey:     helpersv1.Ready,
							},
							Labels: map[string]string{
								helpersv1.KindMetadataKey: "Pod",
								helpersv1.NameMetadataKey: "foo-1747274700",
							},
						},
						Spec: spdxv1beta1.ApplicationProfileSpec{
							Containers: []spdxv1beta1.ApplicationProfileContainer{{
								Name:     "nginx",
								ImageID:  "docker.io/library/nginx@sha256:91ec405acd96b4645695911d675f71897c6f57531265c7302c7e16088b9f37ab",
								ImageTag: "nginx:1.28-otel",
							}},
						},
					},
				},
				{
					Type: watch.Added,
					Object: &spdxv1beta1.ApplicationProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "workflow-foo2-2747274700",
							Namespace: "systest-ns-rarz",
							Annotations: map[string]string{
								helpersv1.InstanceIDMetadataKey: "apiVersion-aroproj.io/v1alpha/namespace-systest-ns-rarz/kind-Workflow/name-foo2-2747274700",
								helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/pod-foo2-2747274700",
								helpersv1.CompletionMetadataKey: helpersv1.Complete,
								helpersv1.StatusMetadataKey:     helpersv1.Ready,
							},
							Labels: map[string]string{
								helpersv1.KindMetadataKey: "Pod",
								helpersv1.NameMetadataKey: "foo2-2747274700",
							},
						},
						Spec: spdxv1beta1.ApplicationProfileSpec{
							Containers: []spdxv1beta1.ApplicationProfileContainer{{
								Name:     "nginx",
								ImageID:  "docker.io/library/nginx@sha256:391f518c1133681a00217e77976665c056bcdbe185a22efbcd6e4ae67c450d1a",
								ImageTag: "nginx:1.28-perl",
							}},
						},
					},
				},
			},
			objects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo2-2747274700",
						Namespace: "systest-ns-rarz",
					},
				},
			},
			expectedCommands: []*apis.Command{
				{
					CommandName: utils.CommandScanApplicationProfile,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
					Args: map[string]interface{}{
						utils.ArgsName:      "replicaset-nginx-6ccd565b7d",
						utils.ArgsNamespace: "systest-ns-rarz",
					},
				},
				{
					CommandName: utils.CommandScanApplicationProfile,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
					Args: map[string]interface{}{
						utils.ArgsName:      "replicaset-nginx-7584b6f84c",
						utils.ArgsNamespace: "systest-ns-rarz",
					},
				},
				{
					CommandName: utils.CommandScanApplicationProfile,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/pod-foo-1747274700",
					Args: map[string]interface{}{
						utils.ArgsName:      "workflow-foo-1747274700",
						utils.ArgsNamespace: "systest-ns-rarz",
					},
				},
				{
					CommandName: utils.CommandScanApplicationProfile,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/pod-foo2-2747274700",
					Args: map[string]interface{}{
						utils.ArgsName:      "workflow-foo2-2747274700",
						utils.ArgsNamespace: "systest-ns-rarz",
						utils.ArgsPod: &corev1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "foo2-2747274700",
								Namespace: "systest-ns-rarz",
							},
						},
					},
				},
			},
			expectedObjectNames: []string{
				"replicaset-nginx-6ccd565b7d",
				"replicaset-nginx-7584b6f84c",
				"workflow-foo-1747274700",
				"workflow-foo2-2747274700",
			},
			expectedSlugToImageIDMap: map[string]string{
				"replicaset-nginx-6ccd565b7d-nginx-49d3-1861": "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				"replicaset-nginx-7584b6f84c-nginx-d01e-79cc": "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
			},
			expectedWlidAndImageIDMap: []string{
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginxnginxdocker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginxnginxdocker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
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
			operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, cfg)

			k8sClient := k8sfake.NewClientset(tc.objects...)
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset(startingObjects...)

			eventQueue := NewCooldownQueueWithParams(1*time.Second, 1*time.Second)
			cmdCh := make(chan *apis.Command)
			errorCh := make(chan error)

			wh := NewWatchHandler(operatorConfig, k8sAPI, storageClient, nil)

			go wh.HandleApplicationProfileEvents(eventQueue, cmdCh, errorCh)

			go func() {
				for _, e := range tc.inputEvents {
					eventQueue.Enqueue(e)
				}
				time.Sleep(5 * time.Second)
				eventQueue.Stop()
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

			actualObjects, _ := storageClient.SpdxV1beta1().ApplicationProfiles("").List(ctx, metav1.ListOptions{})

			var actualObjectNames []string
			for _, obj := range actualObjects.Items {
				actualObjectNames = append(actualObjectNames, obj.ObjectMeta.Name)
			}

			assert.Equal(t, tc.expectedObjectNames, actualObjectNames, "Objects in the storage don’t match")
			assert.Equal(t, tc.expectedErrors, actualErrors, "Errors don’t match")
			assert.ElementsMatch(t, tc.expectedCommands, actualCommands, "Commands don’t match")
		})

	}
}
