package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/command"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func deleteRegistryCommand(t *testing.T, name string) v1alpha1.OperatorCommand {
	t.Helper()
	registry := armotypes.HarborImageRegistry{InstanceURL: "https://harbor.example", Username: "scanner", Password: "secret"}
	registry.Provider = armotypes.Harbor
	registry.ResourceName = name
	body, err := json.Marshal(registry)
	require.NoError(t, err)
	return v1alpha1.OperatorCommand{Spec: v1alpha1.OperatorCommandSpec{CommandType: string(command.OperatorCommandTypeDeleteRegistry), Body: body}}
}

// registryObjects is what upsertRegistry creates for a registry: the secret, the request
// ConfigMap, the job of the immediate scan and, when the registry has a scan frequency,
// the CronJob.
func registryObjects(name string, withSchedule bool) []runtime.Object {
	meta := metav1.ObjectMeta{Namespace: "kubescape", Name: name}
	objects := []runtime.Object{&corev1.Secret{ObjectMeta: meta}, &corev1.ConfigMap{ObjectMeta: meta}, &batchv1.Job{ObjectMeta: meta}}
	if withSchedule {
		objects = append(objects, &batchv1.CronJob{ObjectMeta: meta})
	}
	return objects
}

func newRegistryHandler(t *testing.T, objects ...runtime.Object) (*RegistryCommandsHandler, *fake.Clientset) {
	t.Helper()
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	client := fake.NewSimpleClientset(objects...)
	return &RegistryCommandsHandler{ctx: context.Background(), k8sAPI: &k8sinterface.KubernetesApi{KubernetesClient: client}, config: cfg}, client
}

// remaining reports which of a registry's objects still exist.
func remaining(t *testing.T, client *fake.Clientset, name string) map[string]bool {
	t.Helper()
	ctx := context.Background()
	exists := func(err error) bool {
		if err == nil {
			return true
		}
		require.True(t, apierrors.IsNotFound(err), err)
		return false
	}
	_, secretErr := client.CoreV1().Secrets("kubescape").Get(ctx, name, metav1.GetOptions{})
	_, configMapErr := client.CoreV1().ConfigMaps("kubescape").Get(ctx, name, metav1.GetOptions{})
	_, jobErr := client.BatchV1().Jobs("kubescape").Get(ctx, name, metav1.GetOptions{})
	_, cronJobErr := client.BatchV1().CronJobs("kubescape").Get(ctx, name, metav1.GetOptions{})
	return map[string]bool{"secret": exists(secretErr), "configmap": exists(configMapErr), "job": exists(jobErr), "cronjob": exists(cronJobErr)}
}

func TestDeleteRegistryRemovesEverythingTheRegistryHad(t *testing.T) {
	for _, withSchedule := range []bool{true, false} {
		name := "without a schedule"
		if withSchedule {
			name = "with a schedule"
		}
		t.Run(name, func(t *testing.T) {
			objects := append(registryObjects("registry-a", withSchedule), registryObjects("registry-b", true)...)
			h, client := newRegistryHandler(t, objects...)

			require.NoError(t, h.deleteRegistry(deleteRegistryCommand(t, "registry-a")))

			assert.Equal(t, map[string]bool{"secret": false, "configmap": false, "job": false, "cronjob": false}, remaining(t, client, "registry-a"))
			assert.Equal(t, map[string]bool{"secret": true, "configmap": true, "job": true, "cronjob": true}, remaining(t, client, "registry-b"), "another registry's objects stay")
		})
	}
}

func TestDeleteRegistryDeletesJobsWithTheirPods(t *testing.T) {
	h, client := newRegistryHandler(t, registryObjects("registry-a", true)...)

	require.NoError(t, h.deleteRegistry(deleteRegistryCommand(t, "registry-a")))

	policies := map[string]*metav1.DeletionPropagation{}
	for _, action := range client.Actions() {
		if del, ok := action.(k8stesting.DeleteActionImpl); ok {
			policies[del.GetResource().Resource] = del.DeleteOptions.PropagationPolicy
		}
	}
	for _, resource := range []string{"jobs", "cronjobs"} {
		require.NotNil(t, policies[resource], resource)
		assert.Equal(t, metav1.DeletePropagationBackground, *policies[resource], resource)
	}
}

func TestDeleteRegistryReportsTheFirstFailureAfterTryingEverything(t *testing.T) {
	h, client := newRegistryHandler(t, registryObjects("registry-a", true)...)
	boom := errors.New("secrets is forbidden")
	client.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, boom
	})

	err := h.deleteRegistry(deleteRegistryCommand(t, "registry-a"))

	require.ErrorIs(t, err, boom)
	assert.Equal(t, map[string]bool{"secret": true, "configmap": false, "job": false, "cronjob": false}, remaining(t, client, "registry-a"), "the rest is still removed")
}
