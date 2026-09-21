package mainhandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/k8s-interface/k8sinterface"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAgentRuntimeFrameworkRequestSurvivesScheduledTrigger(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "configured default"
		if explicit {
			name = "explicit framework"
		}
		t.Run(name, func(t *testing.T) {
			payload := map[string]interface{}{
				"includeNamespaces":  []string{"agents"},
				"excludedNamespaces": []string{"kube-system"},
				"hostScanner":        false,
				"keepLocal":          true,
				"useCachedArtifacts": true,
				"exceptions":         []interface{}{map[string]interface{}{"name": "agent-runtime-exception"}},
			}
			defaults := []string{"AgentRuntimeHardening"}
			if explicit {
				payload["targetType"] = utilsapisv1.KindFramework
				payload["targetNames"] = []string{"AgentRuntimeHardening"}
				defaults = []string{"nsa"}
			}
			args := map[string]interface{}{utils.KubescapeScanV1: payload}
			requested, err := getKubescapeV1ScanRequest(args, defaults)
			require.NoError(t, err)
			scheduled, err := getKubescapeRequest(args, defaults)
			require.NoError(t, err)
			require.Equal(t, requested, scheduled)
			assert.Equal(t, []string{"AgentRuntimeHardening"}, scheduled.TargetNames)
			assert.Equal(t, utilsapisv1.KindFramework, scheduled.TargetType)
			assert.Equal(t, []string{"agents"}, scheduled.IncludeNamespaces)
			assert.Equal(t, []string{"kube-system"}, scheduled.ExcludedNamespaces)
			require.NotNil(t, scheduled.HostScanner)
			assert.False(t, *scheduled.HostScanner)
			require.NotNil(t, scheduled.KeepLocal)
			assert.True(t, *scheduled.KeepLocal)
			require.NotNil(t, scheduled.UseCachedArtifacts)
			assert.True(t, *scheduled.UseCachedArtifacts)
			require.Len(t, scheduled.Exceptions, 1)
			assert.Equal(t, "agent-runtime-exception", scheduled.Exceptions[0].Name)

			template := &batchv1.CronJob{}
			template.Spec.JobTemplate.Spec.Template.Spec.Volumes = []corev1.Volume{{
				Name:         requestVolumeName,
				VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}},
			}}
			templateJSON, err := json.Marshal(template)
			require.NoError(t, err)
			client := fake.NewSimpleClientset(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: KubescapeCronJobTemplateName, Namespace: "kubescape"},
				Data:       map[string]string{cronjobTemplateName: string(templateJSON)},
			})
			api := &k8sinterface.KubernetesApi{KubernetesClient: client}
			received := make(chan utilsmetav1.PostScanRequest, 1)
			scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/v1/scan", r.URL.Path)
				var request utilsmetav1.PostScanRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode scanner request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				received <- request
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"agent-runtime-scan","type":"success"}`))
			}))
			defer scanner.Close()
			previousClient := KubescapeHttpClient
			KubescapeHttpClient = scanner.Client()
			t.Cleanup(func() { KubescapeHttpClient = previousClient })
			cfg, err := config.NewOperatorConfig(
				config.CapabilitiesConfig{Components: config.Components{Kubescape: config.Component{Enabled: true}, KubescapeScheduler: config.Component{Enabled: true}}},
				utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://"), InstallationData: armotypes.InstallationData{DefaultFrameworks: defaults}},
				&beUtils.Credentials{}, config.Config{Namespace: "kubescape"},
			)
			require.NoError(t, err)
			args["jobParams"] = apis.CronJobParams{CronTabSchedule: "0 3 * * *"}
			handler := &ActionHandler{config: cfg, k8sAPI: api, sessionObj: &utils.SessionObj{Command: &apis.Command{Args: args}}}
			require.NoError(t, handler.kubescapeScan(context.Background()))
			select {
			case forwarded := <-received:
				assert.Equal(t, requested, &forwarded)
			default:
				t.Fatal("scanner did not receive the requested scan")
			}
			require.NoError(t, handler.setKubescapeCronJob(context.Background()))
			jobs, err := client.BatchV1().CronJobs("kubescape").List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			require.Len(t, jobs.Items, 1)
			job := jobs.Items[0]
			require.Len(t, job.Spec.JobTemplate.Spec.Template.Spec.Volumes, 1)
			jobName := job.Name
			assert.Equal(t, jobName, job.Spec.JobTemplate.Spec.Template.Spec.Volumes[0].ConfigMap.Name)
			configMap, err := client.CoreV1().ConfigMaps("kubescape").Get(context.Background(), jobName, metav1.GetOptions{})
			require.NoError(t, err)
			var commands apis.Commands
			require.NoError(t, json.Unmarshal([]byte(configMap.Data["request-body.json"]), &commands))
			require.Len(t, commands.Commands, 1)
			assert.Equal(t, apis.TypeRunKubescape, commands.Commands[0].CommandName)
			replayed, err := getKubescapeV1ScanRequest(commands.Commands[0].Args, []string{"mitre"})
			require.NoError(t, err)
			assert.Equal(t, scheduled, replayed, "the stored trigger must preserve the complete supported request")

			assert.Equal(t, "0 3 * * *", job.Spec.Schedule)
			assert.Equal(t, "AgentRuntimeHardening", job.Spec.JobTemplate.Spec.Template.Annotations["armo.framework"])
		})
	}
}
