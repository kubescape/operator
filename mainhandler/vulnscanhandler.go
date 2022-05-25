package mainhandler

import (
	"context"
	"fmt"
	"k8s-ca-websocket/cautils"
	"math/rand"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (actionHandler *ActionHandler) setVulnScanCronJob() error {

	req := getVulnScanRequest(&actionHandler.command)

	name := fixK8sCronJobNameLimit(fmt.Sprintf("%s-%d", "vuln-scan-scheduled", rand.NewSource(time.Now().UnixNano()).Int63()))

	if err := createConfigMapForTriggerRequest(actionHandler.k8sAPI, name, req); err != nil {
		return err
	}

	jobTemplateObj, err := getCronJonTemplate(actionHandler.k8sAPI, "vulnscan-cronjob-template")
	if err != nil {
		return err
	}

	setCronJobForTriggerRequest(jobTemplateObj, name, actionHandler.getCronTabSchedule(), actionHandler.command.JobTracking.JobID)

	if _, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (actionHandler *ActionHandler) updateVulnScanCronJob() error {
	scanJobParams := getJobParams(&actionHandler.command)
	if scanJobParams == nil {
		return fmt.Errorf("failed to convert scanJobParams list to scanJobParams")
	}

	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Get(context.Background(), scanJobParams.JobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobTemplateObj.Spec.Schedule = scanJobParams.CronTabSchedule
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.updatejobid"] = actionHandler.command.JobTracking.JobID

	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) deleteVulnScanCronJob() error {

	scanJobParams := getJobParams(&actionHandler.command)
	if scanJobParams == nil {
		return fmt.Errorf("failed to convert scanJobParams list to scanJobParams")
	}

	if err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Delete(context.Background(), scanJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Delete(context.Background(), scanJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}
	return nil
}
