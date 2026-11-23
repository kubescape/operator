package mainhandler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const vulnScanTestNamespace = "kubescape"

func vulnScanCronJobTemplate(t *testing.T) *corev1.ConfigMap {
	t.Helper()
	template := &batchv1.CronJob{}
	template.Spec.JobTemplate.Spec.Template.Spec.Volumes = []corev1.Volume{{
		Name:         requestVolumeName,
		VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}},
	}}
	templateJSON, err := json.Marshal(template)
	require.NoError(t, err)
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: VulnScanCronjobTemplateName, Namespace: vulnScanTestNamespace},
		Data:       map[string]string{cronjobTemplateName: string(templateJSON)},
	}
}

func vulnScanCronJobHandler(t *testing.T, client *fake.Clientset, args map[string]interface{}) *ActionHandler {
	t.Helper()
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{Components: config.Components{KubevulnScheduler: config.Component{Enabled: true}}},
		utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, config.Config{Namespace: vulnScanTestNamespace},
	)
	require.NoError(t, err)
	return &ActionHandler{
		config:     cfg,
		k8sAPI:     &k8sinterface.KubernetesApi{KubernetesClient: client},
		sessionObj: &utils.SessionObj{Command: &apis.Command{CommandName: apis.TypeSetVulnScanCronJob, Args: args}},
	}
}

// A command that is rejected must not leave its request ConfigMap behind: the
// name is random and no CronJob refers to it, so nothing would ever delete it.
func TestSetVulnScanCronJob_RejectedCommandLeavesNoConfigMap(t *testing.T) {
	tests := []struct {
		name    string
		objects []*corev1.ConfigMap
		args    map[string]interface{}
	}{
		{
			name:    "no schedule",
			objects: []*corev1.ConfigMap{vulnScanCronJobTemplate(t)},
			args:    map[string]interface{}{},
		},
		{
			name: "no cronjob template",
			args: map[string]interface{}{"jobParams": apis.CronJobParams{CronTabSchedule: "0 3 * * *"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			for _, object := range tt.objects {
				_, err := client.CoreV1().ConfigMaps(vulnScanTestNamespace).Create(context.Background(), object, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			require.Error(t, vulnScanCronJobHandler(t, client, tt.args).setVulnScanCronJob(context.Background()))

			cronJobs, err := client.BatchV1().CronJobs(vulnScanTestNamespace).List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			assert.Empty(t, cronJobs.Items)

			configMaps, err := client.CoreV1().ConfigMaps(vulnScanTestNamespace).List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			for _, configMap := range configMaps.Items {
				assert.Equal(t, VulnScanCronjobTemplateName, configMap.Name, "request ConfigMap left behind")
			}
		})
	}
}

// The accepted path still creates the CronJob together with the request
// ConfigMap it mounts.
func TestSetVulnScanCronJob_CreatesCronJobAndRequestConfigMap(t *testing.T) {
	client := fake.NewSimpleClientset(vulnScanCronJobTemplate(t))
	args := map[string]interface{}{"jobParams": apis.CronJobParams{CronTabSchedule: "0 3 * * *"}}

	require.NoError(t, vulnScanCronJobHandler(t, client, args).setVulnScanCronJob(context.Background()))

	cronJobs, err := client.BatchV1().CronJobs(vulnScanTestNamespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, cronJobs.Items, 1)
	assert.Equal(t, "0 3 * * *", cronJobs.Items[0].Spec.Schedule)

	_, err = client.CoreV1().ConfigMaps(vulnScanTestNamespace).Get(context.Background(), cronJobs.Items[0].Name, metav1.GetOptions{})
	assert.NoError(t, err)
}

// If the API server rejects the CronJob, its request ConfigMap is removed
// again: without the CronJob nothing refers to it. When the outcome is unknown
// (timeout, transport error, AlreadyExists) the CronJob may be stored now or
// later and mount the ConfigMap, so the ConfigMap is kept.
func TestSetVulnScanCronJob_FailedCronJobCreate(t *testing.T) {
	cronJobs := schema.GroupResource{Group: "batch", Resource: "cronjobs"}
	lostResponse := errors.New("http2: client connection lost")
	tests := []struct {
		name          string
		createErr     error
		stored        bool // the CronJob is stored although Create returns an error
		keepConfigMap bool
	}{
		{
			name:      "quota rejects the CronJob",
			createErr: apierrors.NewForbidden(cronJobs, "kubevuln-schedule", errors.New("exceeded quota")),
		},
		{
			name:      "admission webhook denies the CronJob",
			createErr: apierrors.NewBadRequest("admission webhook denied the request"),
		},
		{
			name:          "server timeout after the CronJob was stored",
			createErr:     apierrors.NewTimeoutError("request did not complete", 0),
			stored:        true,
			keepConfigMap: true,
		},
		{
			name:          "server timeout before the CronJob was stored",
			createErr:     apierrors.NewTimeoutError("request did not complete", 0),
			keepConfigMap: true,
		},
		{
			name:          "lost response after the CronJob was stored",
			createErr:     lostResponse,
			stored:        true,
			keepConfigMap: true,
		},
		{
			name:          "transport error before the CronJob was stored",
			createErr:     lostResponse,
			keepConfigMap: true,
		},
		{
			name:          "CronJob already exists",
			createErr:     apierrors.NewAlreadyExists(cronJobs, "kubevuln-schedule"),
			stored:        true,
			keepConfigMap: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(vulnScanCronJobTemplate(t))
			client.PrependReactor("create", "cronjobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if tt.stored {
					create := action.(k8stesting.CreateAction)
					require.NoError(t, client.Tracker().Create(create.GetResource(), create.GetObject(), create.GetNamespace()))
				}
				return true, nil, tt.createErr
			})
			args := map[string]interface{}{"jobParams": apis.CronJobParams{CronTabSchedule: "0 3 * * *"}}

			err := vulnScanCronJobHandler(t, client, args).setVulnScanCronJob(context.Background())
			require.ErrorIs(t, err, tt.createErr)

			configMaps, err := client.CoreV1().ConfigMaps(vulnScanTestNamespace).List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			var requestConfigMaps []string
			for _, configMap := range configMaps.Items {
				if configMap.Name != VulnScanCronjobTemplateName {
					requestConfigMaps = append(requestConfigMaps, configMap.Name)
				}
			}
			if tt.keepConfigMap {
				assert.Len(t, requestConfigMaps, 1, "request ConfigMap deleted although the CronJob may exist")
			} else {
				assert.Empty(t, requestConfigMaps, "request ConfigMap left behind")
			}
		})
	}
}
