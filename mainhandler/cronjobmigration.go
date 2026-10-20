package mainhandler

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	scheduleTierLabel = "armo.tier"
	triggerActionPath = "v1/triggerAction"
)

// scheduleTemplates maps the tier the chart puts on a schedule's pods to the template
// ConfigMap the schedule is rendered from.
var scheduleTemplates = map[string]string{
	"vuln-scan":      VulnScanCronjobTemplateName,
	"kubescape-scan": KubescapeCronJobTemplateName,
	"registry-scan":  registryCronjobTemplate,
}

// MigrateScheduleCronJobs re-renders the pods of the schedules the operator created for the
// backend from the current templates. A schedule is rendered once, when it is created, and
// an update command rewrites only its schedule and annotations, so a schedule created
// before the templates moved to OperatorCommands (helm-charts#964) still posts to the
// operator's trigger port, which the chart's NetworkPolicy no longer admits. Only the pod
// spec changes: name, schedule, labels, annotations and the request ConfigMap stay. A
// template that still renders the trigger call, or that is not installed, leaves its
// schedules alone. The first failed update is returned once every schedule was tried.
func MigrateScheduleCronJobs(ctx context.Context, k8sAPI *k8sinterface.KubernetesApi, namespace string) error {
	cronJobs, err := k8sAPI.KubernetesClient.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list schedules: %w", err)
	}
	templates := map[string]*batchv1.CronJob{}
	var firstErr error
	for i := range cronJobs.Items {
		cronJob := &cronJobs.Items[i]
		templateName, ok := scheduleTemplates[cronJob.Spec.JobTemplate.Spec.Template.Labels[scheduleTierLabel]]
		if !ok || !postsToTriggerEndpoint(cronJob.Spec.JobTemplate.Spec.Template.Spec) {
			continue
		}
		template, ok := templates[templateName]
		if !ok {
			template, err = getCronJobTemplate(k8sAPI, templateName, namespace)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				logger.L().Ctx(ctx).Error("failed to read the schedule template", helpers.String("template", templateName), helpers.Error(err))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			templates[templateName] = template
		}
		podSpec := renderedPodSpec(template, cronJob.Name)
		if postsToTriggerEndpoint(podSpec) {
			continue
		}
		cronJob.Spec.JobTemplate.Spec.Template.Spec = podSpec
		if _, err := k8sAPI.KubernetesClient.BatchV1().CronJobs(namespace).Update(ctx, cronJob, metav1.UpdateOptions{}); err != nil {
			logger.L().Ctx(ctx).Error("failed to migrate the schedule", helpers.String("name", cronJob.Name), helpers.Error(err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		logger.L().Ctx(ctx).Info("migrated the schedule to the current template", helpers.String("name", cronJob.Name), helpers.String("template", templateName))
	}
	return firstErr
}

// postsToTriggerEndpoint reports whether a pod still calls the operator's trigger endpoint
// over HTTP, the way the templates did before helm-charts#964.
func postsToTriggerEndpoint(spec corev1.PodSpec) bool {
	for _, container := range spec.Containers {
		for _, arg := range container.Args {
			if strings.Contains(arg, triggerActionPath) {
				return true
			}
		}
	}
	return false
}

// renderedPodSpec is the template's pod spec with the request volume pointing at the
// schedule's own ConfigMap, as it is at creation.
func renderedPodSpec(template *batchv1.CronJob, name string) corev1.PodSpec {
	spec := *template.Spec.JobTemplate.Spec.Template.Spec.DeepCopy()
	for i, v := range spec.Volumes {
		if v.Name == requestVolumeName && v.ConfigMap != nil {
			spec.Volumes[i].ConfigMap.Name = name
		}
	}
	return spec
}
