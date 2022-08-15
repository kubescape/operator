package mainhandler

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/kubescape/kontroller/utils"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const CronjobTemplateName = "vulnscan-cronjob-template"
const NamespaceAnnotationDeprecated = "armo.namespace" // deprecated
const NamespaceAnnotation = "app.kubescape/namespace"  // TODO: move to shared package

func (actionHandler *ActionHandler) setVulnScanCronJob() error {

	req := getVulnScanRequest(&actionHandler.command)

	name := fixK8sCronJobNameLimit(fmt.Sprintf("%s-%d", "vuln-scan-scheduled", rand.NewSource(time.Now().UnixNano()).Int63()))

	if err := createConfigMapForTriggerRequest(actionHandler.k8sAPI, name, req); err != nil {
		return err
	}

	jobTemplateObj, err := getCronJobTemplate(actionHandler.k8sAPI, CronjobTemplateName)
	if err != nil {
		return err
	}

	scanJobParams := getJobParams(&actionHandler.command)
	if scanJobParams == nil || scanJobParams.CronTabSchedule == "" {
		return fmt.Errorf("setVulnScanCronJob: CronTabSchedule not found")
	}
	setCronJobForTriggerRequest(jobTemplateObj, name, scanJobParams.CronTabSchedule, actionHandler.command.JobTracking.JobID)

	// add namespace annotation
	namespace := getNamespaceFromVulnScanCommand(&actionHandler.command)
	glog.Infof("setVulnScanCronJob: command namespace - '%s'", namespace)
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[NamespaceAnnotationDeprecated] = namespace // deprecated
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[NamespaceAnnotation] = namespace

	if _, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(utils.Namespace).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (actionHandler *ActionHandler) updateVulnScanCronJob() error {
	scanJobParams := getJobParams(&actionHandler.command)
	if scanJobParams == nil || scanJobParams.CronTabSchedule == "" {
		return fmt.Errorf("updateVulnScanCronJob: CronTabSchedule not found")
	}
	if scanJobParams.JobName == "" {
		return fmt.Errorf("updateVulnScanCronJob: jobName not found")
	}

	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(utils.Namespace).Get(context.Background(), scanJobParams.JobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobTemplateObj.Spec.Schedule = scanJobParams.CronTabSchedule
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[kubescapeUpdateJobIDAnnotationDeprecated] = actionHandler.command.JobTracking.JobID // deprecated
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[kubescapeUpdateJobIDAnnotation] = actionHandler.command.JobTracking.JobID

	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(utils.Namespace).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) deleteVulnScanCronJob() error {

	scanJobParams := getJobParams(&actionHandler.command)
	if scanJobParams == nil || scanJobParams.JobName == "" {
		return fmt.Errorf("deleteVulnScanCronJob: CronTabSchedule not found")
	}

	return actionHandler.deleteCronjob(scanJobParams.JobName)

}

func (actionHandler *ActionHandler) deleteCronjob(name string) error {
	if err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(utils.Namespace).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(utils.Namespace).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		return err
	}
	return nil

}
