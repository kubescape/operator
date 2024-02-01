package watcher

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"sync"
	"testing"

	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/initcontainerinstance"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var (
	podCollection               = "testdata/pod-collection.json"
	podCollectionDifferentImage = "testdata/pod-collection-different-image.json"
	replicaSetCollection        = "testdata/replicaset-collection.json"
	deploymentCollection        = "testdata/deployment-collection.json"
	podPartialStatus            = "testdata/pod-with-some-empty-status.json"
	podRedis                    = "testdata/pod-redis.json"
	replicaSetRedis             = "testdata/rs-redis.json"
	podRedis2                   = "testdata/pod-redis-2.json"
	replicaSetRedis2            = "testdata/rs-redis-2.json"
	deploymentRedis             = "testdata/deployment-redis.json"
)

func readFileToBytes(filePath string) []byte {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	return content
}
func bytesToPod(b []byte) *core1.Pod {
	var pod *core1.Pod
	json.Unmarshal(b, &pod)
	return pod
}

func bytesToRuntimeObj(b []byte) runtime.Object {
	var obj *unstructured.Unstructured
	json.Unmarshal(b, &obj)
	runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &obj)
	return obj
}

func podToInstanceIDs(p *core1.Pod) []instanceidhandler.IInstanceID {
	instanceIDs, _ := instanceidhandlerv1.GenerateInstanceIDFromPod(p)
	return instanceIDs
}

func TestPodWatch(t *testing.T) {
	tt := []struct {
		name                     string
		pods                     []*core1.Pod
		parentObjects            []runtime.Object
		expectedObjectNames      []string
		expectedErrors           []error
		numberOfExpectedCommands int
	}{
		{
			name: "Adding pods",
			pods: []*core1.Pod{
				bytesToPod(readFileToBytes(podCollection)),
			},
			parentObjects: []runtime.Object{
				bytesToRuntimeObj(readFileToBytes(deploymentCollection)),
				bytesToRuntimeObj(readFileToBytes(replicaSetCollection)),
			},
			numberOfExpectedCommands: 5,
			expectedObjectNames: []string{
				bytesToPod(readFileToBytes(podCollection)).Name,
			},
			expectedErrors: []error{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			ctx := context.Background()
			clusterConfig := utilsmetadata.ClusterConfig{
				ClusterName: "gke_armo-test-clusters_us-central1-c_dwertent-syft",
			}
			cfg, err := config.LoadConfig("../configuration")
			assert.NoError(t, err)

			operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, "", cfg)

			k8sClient := k8sfake.NewSimpleClientset(tc.parentObjects...)
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), tc.parentObjects...)
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset()
			k8sAPI.DynamicClient = dynClient

			eventQueue := NewCooldownQueue(DefaultQueueSize, DefaultTTL)
			wh := NewWatchHandler(ctx, operatorConfig, k8sAPI, storageClient, eventQueue)

			resourcesCreatedWg := &sync.WaitGroup{}
			resourcesCreatedWg.Add(tc.numberOfExpectedCommands)

			actualCommands := []apis.Command{}
			pool, _ := ants.NewPoolWithFunc(1, func(i interface{}) {
				j := i.(utils.Job)
				command := j.Obj().Command
				actualCommands = append(actualCommands, command)
				resourcesCreatedWg.Done()
			})

			go wh.PodWatch(ctx, pool)

			go func() {
				for i := range tc.pods {
					tc.pods[i].Namespace = ""
					wh.k8sAPI.KubernetesClient.CoreV1().Pods("default").Create(ctx, tc.pods[i], v1.CreateOptions{})
				}
			}()

			resourcesCreatedWg.Wait()
			actualObjects, _ := k8sAPI.KubernetesClient.CoreV1().Pods("").List(ctx, v1.ListOptions{})

			actualObjectNames := []string{}
			for _, obj := range actualObjects.Items {
				actualObjectNames = append(actualObjectNames, obj.ObjectMeta.Name)
			}
			assert.Equal(t, tc.expectedObjectNames, actualObjectNames, "Objects in the storage don’t match")
			assert.Equal(t, tc.numberOfExpectedCommands, len(actualCommands), "expected commands length don’t match")

		})
	}
}

func Test_handlePodWatcher(t *testing.T) {
	tt := []struct {
		name                      string
		pods                      []*core1.Pod
		parentObjects             []runtime.Object
		expectedObjectNames       []string
		expectedCommands          []apis.Command
		expectedErrors            []error
		expectedSlugToImageIDMap  map[string]string
		expectedWlidAndImageIDMap []string
	}{
		{
			name: "Testing pod with many containers",
			pods: []*core1.Pod{
				// pod with 5 containers, this will test:
				// (1) new workload, new image - new wlid, new slug, new image // scan
				// (3) existing workload, new image - existing wlid, new slug, new image // scan
				bytesToPod(readFileToBytes(podCollection)),
				// same pod as above, this will test:
				// (6) existing workload, existing image - existing wlid, existing slug, existing image. This is an ordinary watch event that nothing changed // ignore
				bytesToPod(readFileToBytes(podCollection)),
				// same pod as above, different image ID. this will test:
				// (4) existing workload, existing slug, new image hash - existing wlid, existing slug, new image. This can happen when restarting a workload that has same imageTag but the image hash changed // scan
				bytesToPod(readFileToBytes(podCollectionDifferentImage)),
				// new pod, with existing image. this will test:
				// (2) new workload, existing image - new wlid, new slug, existing image // scan
				bytesToPod(readFileToBytes(podRedis)),
				// same pod as above, different replicaSet parent. this will test:
				// (5) existing workload, existing image - existing wlid, new slug, existing image. This can happen when restarting a workload // ignore
				bytesToPod(readFileToBytes(podRedis2)),
			},
			parentObjects: []runtime.Object{
				bytesToRuntimeObj(readFileToBytes(deploymentCollection)),
				bytesToRuntimeObj(readFileToBytes(replicaSetCollection)),
				bytesToRuntimeObj(readFileToBytes(deploymentRedis)),
				bytesToRuntimeObj(readFileToBytes(replicaSetRedis)),
				bytesToRuntimeObj(readFileToBytes(replicaSetRedis2)),
			},
			expectedCommands: []apis.Command{
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-collection-69c659f8cb-alpine-container-9858-6638",
							ImageID:       "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
							ImageTag:      "alpine:3.18.2",
							ContainerName: "alpine-container",
							ContainerType: "container",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
						},
						utils.ArgsPod: bytesToPod(readFileToBytes(podCollection)),
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-collection-69c659f8cb-redis-beb0-de8a",
							ImageID:       "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
							ImageTag:      "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
							ContainerName: "redis",
							ContainerType: "container",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
						},
						utils.ArgsPod: bytesToPod(readFileToBytes(podCollection)),
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-collection-69c659f8cb-wordpress-05df-a39f",
							ImageID:       "docker.io/library/wordpress@sha256:5f1873a461105cb1dc1a75731671125f1fb406b18e3fcf63210e8f7f84ce560b",
							ImageTag:      "wordpress:6.0.1-php7.4",
							ContainerName: "wordpress",
							ContainerType: "container",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
						},
						utils.ArgsPod: bytesToPod(readFileToBytes(podCollection)),
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-collection-69c659f8cb-busybox-b1d9-e8c6",
							ImageID:       "docker.io/library/busybox@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231",
							ImageTag:      "busybox:1.34.0",
							ContainerName: "busybox",
							ContainerType: "initContainer",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
						},
						utils.ArgsPod: bytesToPod(readFileToBytes(podCollection)),
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-collection-69c659f8cb-alpine-3ac2-aecc",
							ImageID:       "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
							ImageTag:      "alpine:3.14.2",
							ContainerName: "alpine",
							ContainerType: "initContainer",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
						},
						utils.ArgsPod: bytesToPod(readFileToBytes(podCollection)),
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-collection-69c659f8cb-alpine-container-9858-6638",
							ImageID:       "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
							ImageTag:      "alpine:3.14.2",
							ContainerName: "alpine-container",
							ContainerType: "container",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection",
						},
						utils.ArgsPod: bytesToPod(readFileToBytes(podCollectionDifferentImage)),
					},
				},
				{
					CommandName: apis.TypeScanImages,
					Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-redis",
					Args: map[string]interface{}{
						utils.ArgsContainerData: &utils.ContainerData{
							Slug:          "replicaset-redis-77b4fdf86c-redis-ef54-393f",
							ImageID:       "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
							ImageTag:      "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
							ContainerName: "redis",
							ContainerType: "container",
							Wlid:          "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-redis",
						},
						utils.ArgsPod: bytesToPod(readFileToBytes(podRedis)),
					},
				},
			},
			expectedObjectNames: []string{
				bytesToPod(readFileToBytes(podCollection)).Name,
				bytesToPod(readFileToBytes(podCollectionDifferentImage)).Name,
			},
			expectedSlugToImageIDMap: map[string]string{
				"replicaset-collection-69c659f8cb-busybox-b1d9-e8c6":          "docker.io/library/busybox@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231",
				"replicaset-collection-69c659f8cb-alpine-3ac2-aecc":           "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
				"replicaset-collection-69c659f8cb-alpine-container-9858-6638": "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
				"replicaset-collection-69c659f8cb-redis-beb0-de8a":            "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
				"replicaset-collection-69c659f8cb-wordpress-05df-a39f":        "docker.io/library/wordpress@sha256:5f1873a461105cb1dc1a75731671125f1fb406b18e3fcf63210e8f7f84ce560b",
				"replicaset-redis-77b4fdf86c-redis-ef54-393f":                 "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
				"replicaset-redis-7bfdd886d9-redis-8235-d67e":                 "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
			},
			expectedWlidAndImageIDMap: []string{
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection" + "alpine-container" + "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection" + "redis" + "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection" + "wordpress" + "docker.io/library/wordpress@sha256:5f1873a461105cb1dc1a75731671125f1fb406b18e3fcf63210e8f7f84ce560b",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection" + "busybox" + "docker.io/library/busybox@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection" + "alpine" + "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-collection" + "alpine-container" + "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
				"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-default/deployment-redis" + "redis" + "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
			},
			expectedErrors: []error{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			ctx := context.Background()
			clusterConfig := utilsmetadata.ClusterConfig{
				ClusterName: "gke_armo-test-clusters_us-central1-c_dwertent-syft",
			}
			cfg, err := config.LoadConfig("../configuration")
			assert.NoError(t, err)

			operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, "", cfg)

			k8sClient := k8sfake.NewSimpleClientset(tc.parentObjects...)
			dynClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), tc.parentObjects...)
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset()
			k8sAPI.DynamicClient = dynClient

			eventQueue := NewCooldownQueue(DefaultQueueSize, DefaultTTL)
			wh := NewWatchHandler(ctx, operatorConfig, k8sAPI, storageClient, eventQueue)

			resourcesCreatedWg := &sync.WaitGroup{}
			resourcesCreatedWg.Add(len(tc.expectedCommands))

			actualCommands := []apis.Command{}
			pool, _ := ants.NewPoolWithFunc(1, func(i interface{}) {
				j := i.(utils.Job)
				command := j.Obj().Command
				actualCommands = append(actualCommands, command)
				resourcesCreatedWg.Done()
			})

			for i := range tc.pods {
				wh.handlePodWatcher(ctx, tc.pods[i], pool)
			}

			resourcesCreatedWg.Wait()

			// test slug to image ID map
			assert.Equal(t, len(tc.expectedSlugToImageIDMap), wh.SlugToImageID.Len(), "Slug to image ID map doesn’t match")
			for k, v := range tc.expectedSlugToImageIDMap {
				assert.Equal(t, v, wh.SlugToImageID.Get(k), "Slug '%s' to image ID map doesn’t match", k)
			}

			// test expectedWlidAndImageIDMap
			assert.Equal(t, len(tc.expectedWlidAndImageIDMap), wh.WlidAndImageID.Cardinality(), "Wlid and image ID map doesn’t match")
			for _, v := range tc.expectedWlidAndImageIDMap {
				assert.True(t, wh.WlidAndImageID.Contains(v), "Wlid and image ID map doesn’t match")
			}

			assert.Equal(t, len(tc.expectedCommands), len(actualCommands), "expected commands length don’t match")
			found := 0
			for i := 0; i < len(tc.expectedCommands); i++ {
				expected := tc.expectedCommands[i].Args[utils.ArgsContainerData].(*utils.ContainerData)
				for j := 0; j < len(actualCommands); j++ {
					actual := actualCommands[j].Args[utils.ArgsContainerData].(*utils.ContainerData)
					if actual.Slug != expected.Slug || actual.ImageID != expected.ImageID {
						continue
					}
					assert.Equal(t, tc.expectedCommands[i].CommandName, actualCommands[j].CommandName, "Command names don’t match")
					assert.Equal(t, tc.expectedCommands[i].Wlid, actualCommands[j].Wlid, "Wlid don’t match")
					assert.Equal(t, tc.expectedCommands[i].Args[utils.ArgsPod], actualCommands[j].Args[utils.ArgsPod], "pods don’t match")
					found++
				}
			}
			assert.Equal(t, len(actualCommands), found, "expected commands length don’t match")
		})
	}
}

func Test_listPods(t *testing.T) {
	tt := []struct {
		name                string
		pods                []*core1.Pod
		expectedObjectNames []string
	}{
		{
			name: "list pods",
			pods: []*core1.Pod{
				bytesToPod(readFileToBytes(podCollection)),
				bytesToPod(readFileToBytes(podRedis)),
			},
			expectedObjectNames: []string{
				bytesToPod(readFileToBytes(podCollection)).Name,
				bytesToPod(readFileToBytes(podRedis)).Name,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare starting startingObjects for storage
			operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, "", config.Config{})
			ctx := context.Background()
			k8sClient := k8sfake.NewSimpleClientset()
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset()
			eventQueue := NewCooldownQueue(DefaultQueueSize, DefaultTTL)

			wh := NewWatchHandler(ctx, operatorConfig, k8sAPI, storageClient, eventQueue)
			resourcesCreatedWg := &sync.WaitGroup{}

			for i := range tc.pods {
				resourcesCreatedWg.Add(1)
				tc.pods[i].Namespace = ""
				_, err := k8sAPI.KubernetesClient.CoreV1().Pods("").Create(ctx, tc.pods[i], v1.CreateOptions{})
				assert.NoError(t, err)
			}

			go func() {
				for e := range eventQueue.ResultChan {
					assert.Equal(t, watch.Added, e.Type)
					assert.Contains(t, tc.expectedObjectNames, e.Object.(*core1.Pod).Name)
					resourcesCreatedWg.Done()
				}
			}()
			wh.listPods(ctx)
			resourcesCreatedWg.Wait()
			eventQueue.Stop()
		})
	}
}
func Test_mapSlugToInstanceID(t *testing.T) {
	instanceIDs := podToInstanceIDs(bytesToPod(readFileToBytes(podCollection)))
	expected := map[string]instanceidhandler.IInstanceID{
		"replicaset-collection-69c659f8cb-alpine-container-9858-6638": instanceIDs[0],
		"replicaset-collection-69c659f8cb-redis-beb0-de8a":            instanceIDs[1],
		"replicaset-collection-69c659f8cb-wordpress-05df-a39f":        instanceIDs[2],
		"replicaset-collection-69c659f8cb-busybox-b1d9-e8c6":          instanceIDs[3],
		"replicaset-collection-69c659f8cb-alpine-3ac2-aecc":           instanceIDs[4],
	}

	result := mapSlugToInstanceID(instanceIDs)

	if len(result) != len(expected) {
		t.Errorf("Unexpected result length. Expected: %d, Got: %d", len(expected), len(result))
	}

	for slug, expectedInstanceID := range expected {
		resultInstanceID, ok := result[slug]
		if !ok {
			t.Errorf("Missing instance ID for slug: %s", slug)
			continue
		}

		if resultInstanceID != expectedInstanceID {
			t.Errorf("Unexpected instance ID for slug: %s. Expected: %v, Got: %v", slug, expectedInstanceID, resultInstanceID)
		}
	}
}
func Test_slugToImage(t *testing.T) {
	type args struct {
		slugToImageID   map[string]string
		instanceType    helpers.InstanceType
		instanceIDs     []instanceidhandler.IInstanceID
		containerStatus []core1.ContainerStatus
	}
	tests := []struct {
		expected map[string]string
		name     string
		args     args
	}{
		{
			name: "regular container",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(readFileToBytes(podCollection))),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(readFileToBytes(podCollection)).Status.ContainerStatuses,
				instanceType:    containerinstance.InstanceType,
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-alpine-container-9858-6638": "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
				"replicaset-collection-69c659f8cb-redis-beb0-de8a":            "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
				"replicaset-collection-69c659f8cb-wordpress-05df-a39f":        "docker.io/library/wordpress@sha256:5f1873a461105cb1dc1a75731671125f1fb406b18e3fcf63210e8f7f84ce560b",
			},
		},
		{
			name: "init container",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(readFileToBytes(podCollection))),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(readFileToBytes(podCollection)).Status.InitContainerStatuses,
				instanceType:    initcontainerinstance.InstanceType,
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-busybox-b1d9-e8c6": "docker.io/library/busybox@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231",
				"replicaset-collection-69c659f8cb-alpine-3ac2-aecc":  "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
			},
		},
		{
			name: "missing container status",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(readFileToBytes(podPartialStatus))),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(readFileToBytes(podPartialStatus)).Status.ContainerStatuses,
				instanceType:    containerinstance.InstanceType,
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-alpine-container-9858-6638": "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
				"replicaset-collection-69c659f8cb-redis-beb0-de8a":            "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
			},
		},
		{
			name: "wrong container type",
			args: args{
				instanceIDs:     podToInstanceIDs(bytesToPod(readFileToBytes(podPartialStatus))),
				slugToImageID:   map[string]string{},
				containerStatus: bytesToPod(readFileToBytes(podCollection)).Status.ContainerStatuses,
				instanceType:    "",
			},
			expected: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slugToImage(tt.args.instanceIDs, tt.args.slugToImageID, tt.args.containerStatus, tt.args.instanceType)

			if len(tt.args.slugToImageID) != len(tt.expected) {
				t.Errorf("Unexpected result length. Expected: %d, Got: %d", len(tt.expected), len(tt.args.slugToImageID))
			}

			for slug, expectedImageID := range tt.expected {
				resultImageID, ok := tt.args.slugToImageID[slug]
				if !ok {
					t.Errorf("Missing image ID for slug: %s", slug)
					continue
				}

				if resultImageID != expectedImageID {
					t.Errorf("Unexpected image ID for slug: %s. Expected: %v, Got: %v", slug, expectedImageID, resultImageID)
				}
			}
		})
	}
}

func Test_mapSlugsToImageIDs(t *testing.T) {
	type args struct {
		pod         *core1.Pod
		instanceIDs []instanceidhandler.IInstanceID
	}
	tests := []struct {
		expected map[string]string
		name     string
		args     args
	}{
		{
			name: "regular pod",
			args: args{
				instanceIDs: podToInstanceIDs(bytesToPod(readFileToBytes(podCollection))),
				pod:         bytesToPod(readFileToBytes(podCollection)),
			},
			expected: map[string]string{
				"replicaset-collection-69c659f8cb-alpine-container-9858-6638": "docker.io/library/alpine@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1",
				"replicaset-collection-69c659f8cb-redis-beb0-de8a":            "docker.io/library/redis@sha256:92f3e116c1e719acf78004dd62992c3ad56f68f810c93a8db3fe2351bb9722c2",
				"replicaset-collection-69c659f8cb-wordpress-05df-a39f":        "docker.io/library/wordpress@sha256:5f1873a461105cb1dc1a75731671125f1fb406b18e3fcf63210e8f7f84ce560b",
				"replicaset-collection-69c659f8cb-busybox-b1d9-e8c6":          "docker.io/library/busybox@sha256:e8e5cca392e3cf056fcdb3093e7ac2bf83fcf28b3bcf5818fe8ae71cf360c231",
				"replicaset-collection-69c659f8cb-alpine-3ac2-aecc":           "docker.io/library/alpine@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := mapSlugsToImageIDs(tt.args.pod, tt.args.instanceIDs)

			if len(l) != len(tt.expected) {
				t.Errorf("Unexpected result length. Expected: %d, Got: %d", len(tt.expected), len(l))
			}

			for slug, expectedImageID := range tt.expected {
				resultImageID, ok := l[slug]
				if !ok {
					t.Errorf("Missing image ID for slug: %s", slug)
					continue
				}

				if resultImageID != expectedImageID {
					t.Errorf("Unexpected image ID for slug: %s. Expected: %v, Got: %v", slug, expectedImageID, resultImageID)
				}
			}
		})
	}
}
