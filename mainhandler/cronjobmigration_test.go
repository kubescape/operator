package mainhandler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

// httpTemplate is a schedule template from before helm-charts#964: the pod posts the
// request body to the operator's trigger endpoint.
const httpTemplate = `apiVersion: batch/v1
kind: CronJob
metadata:
  name: %[1]s
  namespace: kubescape
  labels:
    app: %[1]s
    armo.tier: "%[2]s"
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            armo.tier: "%[2]s"
            kubescape.io/tier: "core"
        spec:
          containers:
          - name: %[1]s
            image: "quay.io/kubescape/http-request:v0.2.9"
            args:
              - -method=post
              - -scheme=http
              - -host=operator:4002
              - -path=v1/triggerAction
              - -headers=Content-Type:application/json
              - -path-body=/home/ks/request-body.json
            volumeMounts:
              - name: request-body-volume
                mountPath: /home/ks/request-body.json
                subPath: request-body.json
                readOnly: true
          restartPolicy: Never
          serviceAccountName: kubevuln
          automountServiceAccountToken: false
          volumes:
            - name: request-body-volume
              configMap:
                name: %[1]s
`

// commandTemplate is the template as of helm-charts#964: the pod creates an OperatorCommand
// from the request body.
const commandTemplate = `apiVersion: batch/v1
kind: CronJob
metadata:
  name: %[1]s
  namespace: kubescape
  labels:
    app: %[1]s
    armo.tier: "%[2]s"
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            armo.tier: "%[2]s"
            kubescape.io/tier: "core"
        spec:
          containers:
          - name: %[1]s
            image: "quay.io/kubescape/kubectl:v1.31.0"
            command: ["/scripts/create-operator-command.sh"]
            args:
              - --namespace
              - kubescape
              - --request-body
              - /home/ks/request-body.json
              - --generate-name
              - %[1]s-
            volumeMounts:
              - name: request-body-volume
                mountPath: /home/ks/request-body.json
                subPath: request-body.json
                readOnly: true
              - name: command-scripts
                mountPath: /scripts
                readOnly: true
              - name: tmp-dir
                mountPath: /tmp
          restartPolicy: Never
          serviceAccountName: kubevuln
          automountServiceAccountToken: true
          volumes:
            - name: request-body-volume
              configMap:
                name: %[1]s
            - name: command-scripts
              configMap:
                name: kubescape-command-scripts
                defaultMode: 0755
            - name: tmp-dir
              emptyDir: {}
`

var schedulerNames = map[string]string{"vuln-scan": "kubevuln-scheduler", "kubescape-scan": "kubescape-scheduler", "registry-scan": "registry-scheduler"}

func parseTemplate(t *testing.T, template, tier string) *batchv1.CronJob {
	t.Helper()
	cronJob := &batchv1.CronJob{}
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf(template, schedulerNames[tier], tier)), cronJob))
	return cronJob
}

// templateConfigMap is the chart's template ConfigMap for a tier.
func templateConfigMap(t *testing.T, template, tier string) *corev1.ConfigMap {
	t.Helper()
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: scheduleTemplates[tier], Namespace: "kubescape"},
		Data:       map[string]string{cronjobTemplateName: fmt.Sprintf(template, schedulerNames[tier], tier)},
	}
}

// schedule is a CronJob the operator created from template for the backend, with the
// annotations and schedule a set command gives it.
func schedule(t *testing.T, template, tier, name string) *batchv1.CronJob {
	t.Helper()
	cronJob := parseTemplate(t, template, tier)
	cronJob.Namespace = "kubescape"
	setCronJobForTriggerRequest(cronJob, name, "*/30 * * * *", "job-"+name)
	cronJob.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationNamespaceKey] = "team"
	cronJob.Spec.TimeZone = ptr.To("Etc/UTC")
	return cronJob
}

func newMigrationAPI(objects ...runtime.Object) (*k8sinterface.KubernetesApi, *fake.Clientset) {
	client := fake.NewSimpleClientset(objects...)
	return &k8sinterface.KubernetesApi{KubernetesClient: client}, client
}

func updatedNames(client *fake.Clientset) []string {
	var names []string
	for _, action := range client.Actions() {
		if update, ok := action.(k8stesting.UpdateAction); ok && action.GetResource().Resource == "cronjobs" {
			names = append(names, update.GetObject().(*batchv1.CronJob).Name)
		}
	}
	sort.Strings(names)
	return names
}

func TestMigrateScheduleCronJobsRerendersTheSchedulesThatStillPostToTheOperator(t *testing.T) {
	var objects []runtime.Object
	for tier := range scheduleTemplates {
		objects = append(objects, templateConfigMap(t, commandTemplate, tier), schedule(t, httpTemplate, tier, "old-"+tier), schedule(t, commandTemplate, tier, "new-"+tier))
	}
	other := schedule(t, httpTemplate, "vuln-scan", "not-a-schedule")
	other.Spec.JobTemplate.Spec.Template.Labels = map[string]string{"app": "something-else"}
	objects = append(objects, other)
	api, client := newMigrationAPI(objects...)

	require.NoError(t, MigrateScheduleCronJobs(context.Background(), api, "kubescape"))

	assert.Equal(t, []string{"old-kubescape-scan", "old-registry-scan", "old-vuln-scan"}, updatedNames(client))
	for tier := range scheduleTemplates {
		before := schedule(t, httpTemplate, tier, "old-"+tier)
		after, err := client.BatchV1().CronJobs("kubescape").Get(context.Background(), "old-"+tier, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, renderedPodSpec(parseTemplate(t, commandTemplate, tier), "old-"+tier), after.Spec.JobTemplate.Spec.Template.Spec, tier)
		assert.Equal(t, "old-"+tier, after.Spec.JobTemplate.Spec.Template.Spec.Volumes[0].ConfigMap.Name, "the request ConfigMap is the schedule's own")
		assert.False(t, postsToTriggerEndpoint(after.Spec.JobTemplate.Spec.Template.Spec))
		assert.Equal(t, before.Spec.Schedule, after.Spec.Schedule)
		assert.Equal(t, before.Spec.TimeZone, after.Spec.TimeZone)
		assert.Equal(t, before.Labels, after.Labels)
		assert.Equal(t, before.Spec.JobTemplate.Spec.Template.Labels, after.Spec.JobTemplate.Spec.Template.Labels)
		assert.Equal(t, before.Spec.JobTemplate.Spec.Template.Annotations, after.Spec.JobTemplate.Spec.Template.Annotations)
	}
}

func TestMigrateScheduleCronJobsLeavesSchedulesAloneWhenTheTemplateCannotHelp(t *testing.T) {
	tests := []struct {
		name    string
		objects []runtime.Object
	}{
		{name: "the template still posts to the operator", objects: []runtime.Object{templateConfigMap(t, httpTemplate, "vuln-scan"), schedule(t, httpTemplate, "vuln-scan", "old")}},
		{name: "the template is not installed", objects: []runtime.Object{schedule(t, httpTemplate, "vuln-scan", "old")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, client := newMigrationAPI(tt.objects...)
			require.NoError(t, MigrateScheduleCronJobs(context.Background(), api, "kubescape"))
			assert.Empty(t, updatedNames(client))
		})
	}
}

func TestMigrateScheduleCronJobsReportsTheFirstFailureAfterTryingEverySchedule(t *testing.T) {
	api, client := newMigrationAPI(templateConfigMap(t, commandTemplate, "vuln-scan"), schedule(t, httpTemplate, "vuln-scan", "old-a"), schedule(t, httpTemplate, "vuln-scan", "old-b"))
	boom := errors.New("conflict")
	client.PrependReactor("update", "cronjobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.UpdateAction).GetObject().(*batchv1.CronJob).Name == "old-a" {
			return true, nil, boom
		}
		return false, nil, nil
	})

	err := MigrateScheduleCronJobs(context.Background(), api, "kubescape")

	require.ErrorIs(t, err, boom)
	after, getErr := client.BatchV1().CronJobs("kubescape").Get(context.Background(), "old-b", metav1.GetOptions{})
	require.NoError(t, getErr)
	assert.False(t, postsToTriggerEndpoint(after.Spec.JobTemplate.Spec.Template.Spec), "the other schedule is still migrated")
}
