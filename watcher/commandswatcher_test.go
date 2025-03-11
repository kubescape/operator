package watcher

import (
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/command"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

//go:embed testdata/create-registry-command.json
var createRegistryCommand []byte

//go:embed testdata/registry-template-configmap.yaml
var registryTemplateConfiMap []byte

func TestRegistryCommandWatch(t *testing.T) {
	ctx := context.Background()
	logger.InitDefaultLogger()
	terminateFunc, k8sAPI := initK8sClient(t, ctx)
	defer terminateFunc()
	setupEnvAndWatchers(t, ctx, k8sAPI)

	// send create registry operator command
	var cmd unstructured.Unstructured
	err := json.Unmarshal(createRegistryCommand, &cmd)
	require.NoError(t, err)
	_, err = k8sAPI.DynamicClient.Resource(v1alpha1.SchemaGroupVersionResource).Namespace("kubescape").Create(ctx, &cmd, metav1.CreateOptions{})
	require.NoError(t, err)

	// let registry command handler consume the create command
	time.Sleep(time.Second * 10)

	// verify resources are created
	resourceName := "kubescape-registry-scan-2122797310"
	configMap, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps("kubescape").Get(ctx, resourceName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, configMap)
	secret, err := k8sAPI.KubernetesClient.CoreV1().Secrets("kubescape").Get(ctx, resourceName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, secret)
	cronjob, err := k8sAPI.KubernetesClient.BatchV1().CronJobs("kubescape").Get(ctx, resourceName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, cronjob)

	// delete existing command - usually done by the BE
	err = k8sAPI.DynamicClient.Resource(v1alpha1.SchemaGroupVersionResource).Namespace("kubescape").Delete(ctx, "52601522-359f-4417-a140-cf60e57302f6", metav1.DeleteOptions{})
	require.NoError(t, err)

	// send delete command
	deleteCommandStr := strings.ReplaceAll(string(createRegistryCommand), string(command.OperatorCommandTypeCreateRegistry), string(command.OperatorCommandTypeDeleteRegistry))
	err = json.Unmarshal([]byte(deleteCommandStr), &cmd)
	require.NoError(t, err)
	_, err = k8sAPI.DynamicClient.Resource(v1alpha1.SchemaGroupVersionResource).Namespace("kubescape").Create(ctx, &cmd, metav1.CreateOptions{})
	require.NoError(t, err)

	// let registry command handler consume the command
	time.Sleep(time.Second * 10)

	// verify resources are deleted
	_, err = k8sAPI.KubernetesClient.CoreV1().ConfigMaps("kubescape").Get(ctx, resourceName, metav1.GetOptions{})
	require.ErrorContains(t, err, "not found")
	_, err = k8sAPI.KubernetesClient.CoreV1().Secrets("kubescape").Get(ctx, resourceName, metav1.GetOptions{})
	require.ErrorContains(t, err, "not found")
	_, err = k8sAPI.KubernetesClient.BatchV1().CronJobs("kubescape").Get(ctx, resourceName, metav1.GetOptions{})
	require.ErrorContains(t, err, "not found")

}

func setupEnvAndWatchers(t *testing.T, ctx context.Context, k8sAPI *k8sinterface.KubernetesApi) {
	// install operator command crd
	url := "https://raw.githubusercontent.com/kubescape/helm-charts/main/charts/dependency_chart/operatorcommand-crds/crds/operator-command.crd.yaml"
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var crd unstructured.Unstructured
	require.NoError(t, yaml.Unmarshal(content, &crd))
	_, err = k8sAPI.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}).Create(ctx, &crd, metav1.CreateOptions{})
	require.NoError(t, err)

	// add kubescape namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubescape",
		},
	}
	_, err = k8sAPI.KubernetesClient.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	require.NoError(t, err)

	// add registry cronjob template
	var cjTemplate corev1.ConfigMap
	require.NoError(t, yaml.Unmarshal(registryTemplateConfiMap, &cjTemplate))
	_, err = k8sAPI.KubernetesClient.CoreV1().ConfigMaps("kubescape").Create(ctx, &cjTemplate, metav1.CreateOptions{})
	require.NoError(t, err)

	// start watcher
	operatorConfig := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, "", config.Config{Namespace: "kubescape"})
	commandWatchHandler := NewCommandWatchHandler(k8sAPI, operatorConfig)
	registryCommandsHandler := NewRegistryCommandsHandler(ctx, k8sAPI, commandWatchHandler, operatorConfig)
	go registryCommandsHandler.Start()
	go commandWatchHandler.CommandWatch(ctx)
}

func initK8sClient(t *testing.T, ctx context.Context) (func(), *k8sinterface.KubernetesApi) {
	k3sC, err := k3s.Run(ctx, "docker.io/rancher/k3s:v1.27.9-k3s1")
	require.NoError(t, err)
	kubeConfigYaml, err := k3sC.GetKubeConfig(ctx)
	require.NoError(t, err)
	clusterConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigYaml)
	require.NoError(t, err)
	dynamicClient := dynamic.NewForConfigOrDie(clusterConfig)
	k8sClient := kubernetes.NewForConfigOrDie(clusterConfig)
	k8sAPI := &k8sinterface.KubernetesApi{
		KubernetesClient: k8sClient,
		DynamicClient:    dynamicClient,
		Context:          context.Background(),
	}
	return func() {
		_ = k3sC.Terminate(ctx)
	}, k8sAPI
}
