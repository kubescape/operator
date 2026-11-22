package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	requestBodyFile     = "request-body.json"
	requestVolumeName   = "request-body-volume"
	cronjobTemplateName = "cronjobTemplate"
)

func fixK8sCronJobNameLimit(jobName string) string {
	return fixK8sNameLimit(jobName, 52)
}

// scheduledScanName names the CronJob of a scheduled scan of target. The random
// number at the end is what keeps two schedules of the same target apart, so a
// long target is cut to make room for it rather than the number being cut off.
func scheduledScanName(target string, random int64) string {
	suffix := fmt.Sprintf("-%d", random)
	return fixK8sNameLimit("ks-scheduled-scan-"+target, 52-len(suffix)) + suffix
}

// convert to K8s valid name, lower-case, don't end with '-', maximum X characters
// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
func fixK8sNameLimit(jobName string, nameLimit int) string {
	jobName = strings.ToLower(jobName)
	jobName = k8sNamesRegex.ReplaceAllString(jobName, "-")
	jobName = strings.Trim(jobName, "-")
	if jobName == "" {
		jobName = "invalid-name-was-given"
	}
	if nameLimit > 0 && len(jobName) > nameLimit {
		jobName = strings.TrimRight(jobName[:nameLimit], "-")
	}
	return jobName
}

func getCronJobTemplate(k8sAPI *k8sinterface.KubernetesApi, name, namespace string) (*v1.CronJob, error) {
	template, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// create cronJob
	jobTemplateStr, ok := template.Data[cronjobTemplateName]
	if !ok {
		return nil, fmt.Errorf("getCronJobTemplate: jobTemplate not found")
	}

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

func createConfigMapForTriggerRequest(k8sAPI *k8sinterface.KubernetesApi, namespace string, name string, req *armoapi.Commands) error {
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

	configMap.Data[requestBodyFile] = string(reqByte)
	if _, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(namespace).Create(context.Background(), &configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

// deleteRequestConfigMap removes the request ConfigMap of a CronJob that could
// not be created. A failure is only logged, so the caller can return the error
// that made the CronJob creation fail.
func deleteRequestConfigMap(k8sAPI *k8sinterface.KubernetesApi, namespace string, name string) {
	if err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(namespace).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		logger.L().Warning("failed to delete the request ConfigMap of a CronJob that was not created", helpers.String("name", name), helpers.Error(err))
	}
}

func setCronJobForTriggerRequest(jobTemplateObj *v1.CronJob, name, schedule, jobID string) {

	jobTemplateObj.Name = name
	if schedule != "" {
		jobTemplateObj.Spec.Schedule = schedule
	}

	// update volume name
	for i, v := range jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes {
		if v.Name == requestVolumeName {
			jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap.Name = name
		}
	}

	// add annotations
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationArmoCloudJobIDKeyDeprecated] = jobID // deprecated
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationJobIDKey] = jobID

	// add annotations
	if jobTemplateObj.ObjectMeta.Labels == nil {
		jobTemplateObj.ObjectMeta.Labels = make(map[string]string)
	}
	jobTemplateObj.ObjectMeta.Labels["app"] = name

}
