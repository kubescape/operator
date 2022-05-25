package mainhandler

import (
	"context"
	"encoding/json"
	"k8s-ca-websocket/cautils"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/k8s-interface/k8sinterface"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const RequestBodyPlaceholder = "request-body.json"
const VolumeNamePlaceholder = "request-body-volume"
const CronjobTemplatePlaceholder = "cronjobTemplate"

func fixK8sCronJobNameLimit(jobName string) string {
	return fixK8sNameLimit(jobName, 52)
}

// convert to K8s valid name, lower-case, don't end with '-', maximum X characters
// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
func fixK8sNameLimit(jobName string, nameLimit int) string {
	if len(jobName) > nameLimit {
		jobName = jobName[:nameLimit]
	}
	lastIdx := len(jobName) - 1
	for lastIdx >= 0 && jobName[lastIdx] == '-' {
		jobName = jobName[:lastIdx]
		lastIdx = len(jobName) - 1
	}
	if lastIdx == -1 {
		jobName = "invalid name was given"
	}
	jobName = k8sNamesRegex.ReplaceAllString(jobName, "-")
	return strings.ToLower(jobName)
}

func getCronJonTemplate(k8sAPI *k8sinterface.KubernetesApi, name string) (*v1.CronJob, error) {
	template, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// create cronJob
	jobTemplateStr := template.Data[CronjobTemplatePlaceholder]
	jobTemplateObj := &v1.CronJob{}
	if err := yaml.Unmarshal([]byte(jobTemplateStr), jobTemplateObj); err != nil {
		return nil, err
	}
	return jobTemplateObj, nil
}

func getJobParams(command *armoapi.Command) *armoapi.CronJobParams {

	if jobParams := command.GetCronJobParams(); jobParams != nil {
		return jobParams
	}

	return nil
}

func createConfigMapForTriggerRequest(k8sAPI *k8sinterface.KubernetesApi, name string, req *apis.Command) error {
	// create config map
	configMap := corev1.ConfigMap{}
	configMap.Name = name
	if configMap.Labels == nil {
		configMap.Labels = make(map[string]string)
	}
	configMap.Labels["app"] = name

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	reqByte, err := json.Marshal(req)
	if err != nil {
		return err
	}

	configMap.Data[RequestBodyPlaceholder] = string(reqByte)
	if _, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Create(context.Background(), &configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func setCronJobForTriggerRequest(jobTemplateObj *v1.CronJob, name, schedule, jobID string) {

	jobTemplateObj.Name = name
	if schedule != "" {
		jobTemplateObj.Spec.Schedule = schedule
	}

	// update volume name
	for i, v := range jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes {
		if v.Name == VolumeNamePlaceholder {
			jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap.Name = name
		}
	}

	// add annotations
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.cloud/jobid"] = jobID // deprecated

	// add annotations
	if jobTemplateObj.ObjectMeta.Labels == nil {
		jobTemplateObj.ObjectMeta.Labels = make(map[string]string)
	}
	jobTemplateObj.ObjectMeta.Labels["app"] = name

}
