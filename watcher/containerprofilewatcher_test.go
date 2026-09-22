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
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestHandleContainerProfileEvents(t *testing.T) {
	sampleEvents := []watch.Event{
		{
			Type: watch.Added,
			Object: &spdxv1beta1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "replicaset-nginx-6ccd565b7d",
					Namespace: "systest-ns-rarz",
					Annotations: map[string]string{
						helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-6ccd565b7d",
						helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						helpersv1.CompletionMetadataKey: helpersv1.Full,
						helpersv1.StatusMetadataKey:     helpersv1.Learning,
					},
				},
				Spec: spdxv1beta1.ContainerProfileSpec{
					ImageID:  "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
					ImageTag: "nginx:1.14.0",
				},
			},
		},
		{
			Type: watch.Modified,
			Object: &spdxv1beta1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "replicaset-nginx-7584b6f84c",
					Namespace: "systest-ns-rarz",
					Annotations: map[string]string{
						helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-systest-ns-rarz/kind-ReplicaSet/name-nginx-7584b6f84c",
						helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
						helpersv1.CompletionMetadataKey: helpersv1.Full,
						helpersv1.StatusMetadataKey:     helpersv1.Learning,
					},
				},
				Spec: spdxv1beta1.ContainerProfileSpec{
					ImageID:  "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
					ImageTag: "nginx:latest",
				},
			},
		},
		{
			Type: watch.Added,
			Object: &spdxv1beta1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "workflow-foo-1747274700",
					Namespace: "systest-ns-rarz",
					Annotations: map[string]string{
						helpersv1.InstanceIDMetadataKey: "apiVersion-aroproj.io/v1alpha/namespace-systest-ns-rarz/kind-Workflow/name-foo-1747274700",
						helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/pod-foo-1747274700",
						helpersv1.CompletionMetadataKey: helpersv1.Full,
						helpersv1.StatusMetadataKey:     helpersv1.Learning,
					},
					Labels: map[string]string{
						helpersv1.RelatedKindMetadataKey: "Pod",
						helpersv1.RelatedNameMetadataKey: "foo-1747274700",
					},
				},
				Spec: spdxv1beta1.ContainerProfileSpec{
					ImageID:  "docker.io/library/nginx@sha256:91ec405acd96b4645695911d675f71897c6f57531265c7302c7e16088b9f37ab",
					ImageTag: "nginx:1.28-otel",
				},
			},
		},
		{
			Type: watch.Added,
			Object: &spdxv1beta1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "workflow-foo2-2747274700",
					Namespace: "systest-ns-rarz",
					Annotations: map[string]string{
						helpersv1.InstanceIDMetadataKey: "apiVersion-aroproj.io/v1alpha/namespace-systest-ns-rarz/kind-Workflow/name-foo2-2747274700",
						helpersv1.WlidMetadataKey:       "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/pod-foo2-2747274700",
						helpersv1.CompletionMetadataKey: helpersv1.Full,
						helpersv1.StatusMetadataKey:     helpersv1.Learning,
					},
					Labels: map[string]string{
						helpersv1.RelatedKindMetadataKey: "Pod",
						helpersv1.RelatedNameMetadataKey: "foo2-2747274700",
					},
				},
				Spec: spdxv1beta1.ContainerProfileSpec{
					ImageID:  "docker.io/library/nginx@sha256:391f518c1133681a00217e77976665c056bcdbe185a22efbcd6e4ae67c450d1a",
					ImageTag: "nginx:1.28-perl",
				},
			},
		},
	}
	sampleObjects := []runtime.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo2-2747274700",
				Namespace: "systest-ns-rarz",
			},
		},
	}
	sampleCommands := []*apis.Command{
		{
			CommandName: utils.CommandScanContainerProfile,
			Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
			Args: map[string]interface{}{
				utils.ArgsName:      "replicaset-nginx-6ccd565b7d",
				utils.ArgsNamespace: "systest-ns-rarz",
			},
		},
		{
			CommandName: utils.CommandScanContainerProfile,
			Wlid:        "wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginx",
			Args: map[string]interface{}{
				utils.ArgsName:      "replicaset-nginx-7584b6f84c",
				utils.ArgsNamespace: "systest-ns-rarz",
			},
		},
		{
			CommandName: utils.CommandScanContainerProfile,
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
	}
	sampleObjectNames := []string{
		"replicaset-nginx-6ccd565b7d",
		"replicaset-nginx-7584b6f84c",
		"workflow-foo-1747274700",
		"workflow-foo2-2747274700",
	}
	sampleSlugToImageIDMap := map[string]string{
		"replicaset-nginx-6ccd565b7d-nginx-49d3-1861": "docker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
		"replicaset-nginx-7584b6f84c-nginx-d01e-79cc": "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
	}
	sampleWlidAndImageIDMap := []string{
		"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginxnginxdocker.io/library/nginx@sha256:aa0afebbb3cfa473099a62c4b32e9b3fb73ed23f2a75a65ce1d4b4f55a5c2ef2",
		"wlid://cluster-gke_armo-test-clusters_us-central1-c_dwertent-syft/namespace-systest-ns-rarz/deployment-nginxnginxdocker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
	}

	tt := []struct {
		name                      string
		inputEvents               []watch.Event
		objects                   []runtime.Object
		expectedObjectNames       []string
		expectedCommands          []*apis.Command
		expectedErrors            []error
		expectedSlugToImageIDMap  map[string]string
		expectedWlidAndImageIDMap []string
		cfgModifier               func(*config.Config)
	}{
		{
			name:                      "Adding a new container profile should produce a matching scan command",
			inputEvents:               sampleEvents,
			objects:                   sampleObjects,
			expectedCommands:          sampleCommands,
			expectedObjectNames:       sampleObjectNames,
			expectedSlugToImageIDMap:  sampleSlugToImageIDMap,
			expectedWlidAndImageIDMap: sampleWlidAndImageIDMap,
		},
		{
			name: "Delete event",
			inputEvents: []watch.Event{
				{
					Type:   watch.Deleted,
					Object: &spdxv1beta1.ContainerProfile{},
				},
			},
			expectedCommands:          []*apis.Command{},
			expectedObjectNames:       []string{""},
			expectedSlugToImageIDMap:  map[string]string{},
			expectedWlidAndImageIDMap: []string{},
		},
		{
			name:                      "ContainerProfile in namespace matching excludeNamespacesRegex is skipped",
			inputEvents:               sampleEvents,
			objects:                   sampleObjects,
			expectedCommands:          []*apis.Command{},
			expectedObjectNames:       sampleObjectNames,
			expectedSlugToImageIDMap:  sampleSlugToImageIDMap,
			expectedWlidAndImageIDMap: sampleWlidAndImageIDMap,
			cfgModifier: func(cfg *config.Config) {
				cfg.ExcludeNamespacesRegex = []string{"^systest-ns-rarz$"}
			},
		},
		{
			name:                      "ContainerProfile in namespace not matching includeNamespacesRegex is skipped",
			inputEvents:               sampleEvents,
			objects:                   sampleObjects,
			expectedCommands:          []*apis.Command{},
			expectedObjectNames:       sampleObjectNames,
			expectedSlugToImageIDMap:  sampleSlugToImageIDMap,
			expectedWlidAndImageIDMap: sampleWlidAndImageIDMap,
			cfgModifier: func(cfg *config.Config) {
				cfg.IncludeNamespacesRegex = []string{"^prod-.*$"}
			},
		},
		{
			name:                      "Allowed control case - ContainerProfile in namespace matching includeNamespacesRegex is scanned",
			inputEvents:               sampleEvents,
			objects:                   sampleObjects,
			expectedCommands:          sampleCommands,
			expectedObjectNames:       sampleObjectNames,
			expectedSlugToImageIDMap:  sampleSlugToImageIDMap,
			expectedWlidAndImageIDMap: sampleWlidAndImageIDMap,
			cfgModifier: func(cfg *config.Config) {
				cfg.IncludeNamespacesRegex = []string{"^systest-.*$"}
			},
		},
		{
			name:                      "Allowed control case - ContainerProfile in namespace not matching excludeNamespacesRegex is scanned",
			inputEvents:               sampleEvents,
			objects:                   sampleObjects,
			expectedCommands:          sampleCommands,
			expectedObjectNames:       sampleObjectNames,
			expectedSlugToImageIDMap:  sampleSlugToImageIDMap,
			expectedWlidAndImageIDMap: sampleWlidAndImageIDMap,
			cfgModifier: func(cfg *config.Config) {
				cfg.ExcludeNamespacesRegex = []string{"^dev-.*$", "^temp-.*$"}
			},
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
			// This fixture exercises the legacy opt-out behavior.
			cfg.SkipProfilesWithoutInstances = false
			if tc.cfgModifier != nil {
				tc.cfgModifier(&cfg)
			}
			operatorConfig, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterConfig, &beUtils.Credentials{}, cfg)
			assert.NoError(t, err)

			k8sClient := k8sfake.NewClientset(tc.objects...)
			k8sAPI := utils.NewK8sInterfaceFake(k8sClient)
			storageClient := kssfake.NewSimpleClientset(startingObjects...)

			eventQueue := NewCooldownQueueWithParams(500*time.Millisecond, 100*time.Millisecond)
			cmdCh := make(chan *apis.Command)
			errorCh := make(chan error)

			wh := NewWatchHandler(operatorConfig, k8sAPI, storageClient, nil)

			go wh.HandleContainerProfileEvents(eventQueue, cmdCh, errorCh)

			go func() {
				for _, e := range tc.inputEvents {
					eventQueue.Enqueue(e)
				}
				time.Sleep(2 * time.Second)
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

			actualObjects, _ := storageClient.SpdxV1beta1().ContainerProfiles("").List(ctx, metav1.ListOptions{})

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

func TestWatchHandler_hasMatchingPod(t *testing.T) {
	objects := []runtime.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-pod-1",
				Namespace: "web",
				Labels: map[string]string{
					"app": "nginx",
				},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-deployment",
				Namespace: "web",
				Labels: map[string]string{
					"app": "nginx",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "nginx",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app": "nginx",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "nginx",
								Image: "nginx:1.14.0",
							},
						},
					},
				},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "empty-deployment",
				Namespace: "web",
				Labels: map[string]string{
					"app": "empty",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "empty",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app": "empty",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{},
					},
				},
			},
		},
	}
	sch := runtime.NewScheme()
	err := scheme.AddToScheme(sch) // Registers core types like v1.Pod
	require.NoError(t, err)
	wh := &WatchHandler{
		k8sAPI: &k8sinterface.KubernetesApi{
			KubernetesClient: k8sfake.NewClientset(objects...),
			DynamicClient:    dynamicfake.NewSimpleDynamicClient(sch, objects...),
		},
	}
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{
			name:   "No labels",
			labels: map[string]string{},
			want:   false,
		},
		{
			name: "Matching labels",
			labels: map[string]string{
				helpersv1.ApiGroupMetadataKey:         "apps",
				helpersv1.ApiVersionMetadataKey:       "v1",
				helpersv1.RelatedKindMetadataKey:      "Deployment",
				helpersv1.RelatedNameMetadataKey:      "nginx-deployment",
				helpersv1.RelatedNamespaceMetadataKey: "web",
			},
			want: true,
		},
		{
			name: "Non-matching labels",
			labels: map[string]string{
				helpersv1.ApiGroupMetadataKey:         "apps",
				helpersv1.ApiVersionMetadataKey:       "v1",
				helpersv1.RelatedKindMetadataKey:      "Deployment",
				helpersv1.RelatedNameMetadataKey:      "nginx-deployment",
				helpersv1.RelatedNamespaceMetadataKey: "other",
			},
			want: false,
		},
		{
			name: "No pods",
			labels: map[string]string{
				helpersv1.ApiGroupMetadataKey:         "apps",
				helpersv1.ApiVersionMetadataKey:       "v1",
				helpersv1.RelatedKindMetadataKey:      "Deployment",
				helpersv1.RelatedNameMetadataKey:      "empty-deployment",
				helpersv1.RelatedNamespaceMetadataKey: "web",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &spdxv1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Namespace: tt.labels[helpersv1.RelatedNamespaceMetadataKey], Labels: tt.labels}}
			assert.Equalf(t, tt.want, wh.hasMatchingPod(profile), "hasMatchingPod(%v)", tt.labels)
		})
	}
}

func TestContainerProfileRelistSkipsOrphanedInstances(t *testing.T) {
	const namespace = "web"
	current := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "app-new", Namespace: namespace, UID: "new-uid"}, Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	wrongOwner := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "app-old", Namespace: namespace, UID: "old-uid"}, Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: namespace, UID: "stateful-uid"}, Spec: appsv1.StatefulSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "database"}}}}
	daemonSet := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "node-agent", Namespace: namespace, UID: "daemon-uid"}, Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "node-agent"}}}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "batch-job", Namespace: namespace, UID: "job-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "scheduled-job", UID: "cron-uid"}}}, Spec: batchv1.JobSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"job-name": "batch-job"}}}}
	failedJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "failed-job", Namespace: namespace, UID: "failed-job-uid"}, Spec: batchv1.JobSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"job-name": "failed-job"}}}}
	expressionWorkload := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "expression-workload", Namespace: namespace}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"backend"}}}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app-new-pod", Namespace: namespace, Labels: map[string]string{"app": "web"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: current.Name, UID: current.UID}}}}
	statefulPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "database-0", Namespace: namespace, Labels: map[string]string{"app": "database", appsv1.StatefulSetRevisionLabel: "database-new"}, OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: statefulSet.Name, UID: statefulSet.UID}}}}
	daemonPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "node-agent-xyz", Namespace: namespace, Labels: map[string]string{"app": "node-agent", appsv1.StatefulSetRevisionLabel: "f9dd7596f"}, OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: daemonSet.Name, UID: daemonSet.UID}}}}
	jobPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "batch-job-pod", Namespace: namespace, Labels: map[string]string{"job-name": "batch-job"}, OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: job.Name, UID: job.UID}}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
	failedJobPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "failed-job-pod", Namespace: namespace, Labels: map[string]string{"job-name": "failed-job"}, OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: failedJob.Name, UID: failedJob.UID}}}, Status: corev1.PodStatus{Phase: corev1.PodFailed}}
	expressionPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "expression-pod", Namespace: namespace, Labels: map[string]string{"tier": "backend"}}}
	directPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "direct-pod", Namespace: namespace}}
	completedPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "completed-pod", Namespace: namespace}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
	failedPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "failed-pod", Namespace: namespace}, Status: corev1.PodStatus{Phase: corev1.PodFailed}}

	sch := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(sch))
	k8sClient := k8sfake.NewClientset(pod, statefulPod, daemonPod, jobPod, failedJobPod, expressionPod, directPod, completedPod, failedPod)
	k8sAPI := &k8sinterface.KubernetesApi{KubernetesClient: k8sClient, DynamicClient: dynamicfake.NewSimpleDynamicClient(sch, current, wrongOwner, statefulSet, daemonSet, job, failedJob, expressionWorkload)}
	cfg, err := config.LoadConfig("../configuration")
	require.NoError(t, err)
	require.True(t, cfg.SkipProfilesWithoutInstances)
	operatorConfig, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, cfg)
	require.NoError(t, err)
	wh := NewWatchHandler(operatorConfig, k8sAPI, nil, nil)

	replicaSetProfile := func(name, workload string) *spdxv1beta1.ContainerProfile {
		return &spdxv1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: "instance", helpersv1.WlidMetadataKey: "wlid"}, Labels: map[string]string{
			helpersv1.ApiGroupMetadataKey: "apps", helpersv1.ApiVersionMetadataKey: "v1", helpersv1.RelatedKindMetadataKey: "ReplicaSet", helpersv1.RelatedNameMetadataKey: workload, helpersv1.RelatedNamespaceMetadataKey: namespace,
		}}}
	}
	statefulSetProfile := func(name, revision string) *spdxv1beta1.ContainerProfile {
		return &spdxv1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-" + namespace + "/kind-StatefulSet/name-" + revision, helpersv1.WlidMetadataKey: "wlid"}, Labels: map[string]string{
			helpersv1.ApiGroupMetadataKey: "apps", helpersv1.ApiVersionMetadataKey: "v1", helpersv1.RelatedKindMetadataKey: "StatefulSet", helpersv1.RelatedNameMetadataKey: statefulSet.Name, helpersv1.RelatedNamespaceMetadataKey: namespace,
		}}}
	}
	// DaemonSet AlternateName is <daemonset-name>-<controller-revision-hash>
	daemonSetProfile := func(name, revisionHash string) *spdxv1beta1.ContainerProfile {
		return &spdxv1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-" + namespace + "/kind-DaemonSet/name-" + daemonSet.Name + "-" + revisionHash, helpersv1.WlidMetadataKey: "wlid"}, Labels: map[string]string{
			helpersv1.ApiGroupMetadataKey: "apps", helpersv1.ApiVersionMetadataKey: "v1", helpersv1.RelatedKindMetadataKey: "DaemonSet", helpersv1.RelatedNameMetadataKey: daemonSet.Name, helpersv1.RelatedNamespaceMetadataKey: namespace,
		}}}
	}
	jobProfile := &spdxv1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "completed-cronjob-run", Namespace: namespace, Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: "instance", helpersv1.WlidMetadataKey: "wlid"}, Labels: map[string]string{
		helpersv1.ApiGroupMetadataKey: "batch", helpersv1.ApiVersionMetadataKey: "v1", helpersv1.RelatedKindMetadataKey: "Job", helpersv1.RelatedNameMetadataKey: job.Name, helpersv1.RelatedNamespaceMetadataKey: namespace,
	}}}
	podProfile := func(name, podName string) *spdxv1beta1.ContainerProfile {
		return &spdxv1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: "instance", helpersv1.WlidMetadataKey: "wlid"}, Labels: map[string]string{
			helpersv1.RelatedKindMetadataKey: "Pod", helpersv1.RelatedNameMetadataKey: podName,
		}}}
	}
	profiles := []*spdxv1beta1.ContainerProfile{
		replicaSetProfile("deleted-generation", "app-deleted"),
		replicaSetProfile("wrong-generation", wrongOwner.Name),
		replicaSetProfile("current-generation", current.Name),
		statefulSetProfile("old-stateful-generation", "database-old"),
		statefulSetProfile("current-stateful-generation", "database-new"),
		jobProfile,
		{ObjectMeta: metav1.ObjectMeta{Name: "expression-generation", Namespace: namespace, Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: "instance", helpersv1.WlidMetadataKey: "wlid"}, Labels: map[string]string{
			helpersv1.ApiGroupMetadataKey: "apps", helpersv1.ApiVersionMetadataKey: "v1", helpersv1.RelatedKindMetadataKey: "Deployment", helpersv1.RelatedNameMetadataKey: expressionWorkload.Name, helpersv1.RelatedNamespaceMetadataKey: namespace,
		}}},
		podProfile("deleted-pod", "gone"),
		podProfile("completed-pod", completedPod.Name),
		podProfile("current-pod", directPod.Name),
		podProfile("failed-pod", failedPod.Name),
		statefulSetProfile("missing-stateful-revision", ""),
		{ObjectMeta: metav1.ObjectMeta{Name: "failed-job-run", Namespace: namespace, Annotations: map[string]string{helpersv1.InstanceIDMetadataKey: "instance", helpersv1.WlidMetadataKey: "wlid"}, Labels: map[string]string{
			helpersv1.ApiGroupMetadataKey: "batch", helpersv1.ApiVersionMetadataKey: "v1", helpersv1.RelatedKindMetadataKey: "Job", helpersv1.RelatedNameMetadataKey: failedJob.Name, helpersv1.RelatedNamespaceMetadataKey: namespace,
		}}},
		daemonSetProfile("old-daemon-generation", "abc123old"),
		daemonSetProfile("current-daemon-generation", "f9dd7596f"),
	}
	require.True(t, wh.hasMatchingPod(profiles[2]), "current ReplicaSet must have a matching Pod")
	require.False(t, wh.hasMatchingPod(profiles[3]), "old StatefulSet revision must not match the current Pod")
	require.True(t, wh.hasMatchingPod(profiles[4]), "current StatefulSet revision must match")
	require.True(t, wh.hasMatchingPod(profiles[5]), "completed CronJob Pod must still match its Job")
	require.True(t, wh.hasMatchingPod(profiles[6]), "matchExpressions-only workload must have a matching Pod")
	require.True(t, wh.hasMatchingPod(profiles[9]), "current Pod must exist")
	require.False(t, wh.hasMatchingPod(profiles[11]), "StatefulSet profile without a revision must not match")
	require.True(t, wh.hasMatchingPod(profiles[12]), "failed Job Pod must still match its Job")
	require.False(t, wh.hasMatchingPod(profiles[13]), "old DaemonSet revision must not match the current Pod")
	require.True(t, wh.hasMatchingPod(profiles[14]), "current DaemonSet revision must match")
	events := make(chan watch.Event, len(profiles))
	queue := &CooldownQueue{ResultChan: events}
	commands := make(chan *apis.Command)
	errors := make(chan error)
	go wh.HandleContainerProfileEvents(queue, commands, errors)
	for _, profile := range profiles {
		events <- watch.Event{Type: watch.Added, Object: profile}
	}
	close(events)
	var names []string
	for {
		select {
		case cmd := <-commands:
			names = append(names, cmd.Args[utils.ArgsName].(string))
		case err, ok := <-errors:
			if !ok {
				assert.ElementsMatch(t, []string{"current-generation", "current-stateful-generation", "current-daemon-generation", "completed-cronjob-run", "failed-job-run", "expression-generation", "completed-pod", "current-pod", "failed-pod"}, names)
				return
			}
			t.Errorf("unexpected event error: %v", err)
		case <-time.After(8 * time.Second):
			t.Fatal("timed out waiting for profile events")
		}
	}
}
