package mainhandler

import (
	"context"
	"fmt"
	"slices"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const scheduleTierLabel = "armo.tier"

// scheduleTemplates maps the tier the chart puts on a schedule's pods to the template
// ConfigMap the schedule is rendered from.
var scheduleTemplates = map[string]string{
	"vuln-scan":      VulnScanCronjobTemplateName,
	"kubescape-scan": KubescapeCronJobTemplateName,
	"registry-scan":  registryCronjobTemplate,
}

// MigrateScheduleCronJobs re-renders the pods of the schedules the operator created for the
// backend from the current templates. A schedule is rendered once, when it is created, and
// an update command rewrites only its schedule and annotations, so a schedule keeps the
// containers of the chart release it was created under after the chart changes them: before
// helm-charts#964 it posts to the operator's trigger port, which the chart's NetworkPolicy
// no longer admits, and after a later template change it can need a ConfigMap or image the
// chart no longer ships. A schedule whose containers differ from the template's is
// re-rendered. Only the pod spec changes: name, schedule, labels, annotations and the
// request ConfigMap stay. A CronJob that the operator did not create, such as the chart's
// own scheduler with the same tier label, and a template that is not installed leave the
// CronJob alone. The first failed update is returned once every schedule was tried.
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
		if !ok || !createdFromTemplate(cronJob) {
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
		if sameContainers(cronJob.Spec.JobTemplate.Spec.Template.Spec.Containers, podSpec.Containers) {
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

// createdFromTemplate reports whether the operator created the CronJob from a template. The
// operator points the template's request volume at a ConfigMap with the schedule's own name,
// and the chart's scheduler CronJobs name that volume differently.
func createdFromTemplate(cronJob *batchv1.CronJob) bool {
	return slices.ContainsFunc(cronJob.Spec.JobTemplate.Spec.Template.Spec.Volumes, func(v corev1.Volume) bool {
		return v.Name == requestVolumeName && v.ConfigMap != nil && v.ConfigMap.Name == cronJob.Name
	})
}

// sameContainers compares the fields that decide what a schedule's pod runs. The API server
// defaults none of them, so a schedule rendered from the template compares equal to it.
func sameContainers(current, rendered []corev1.Container) bool {
	return slices.EqualFunc(current, rendered, func(a, b corev1.Container) bool {
		return a.Name == b.Name && a.Image == b.Image && slices.Equal(a.Command, b.Command) && slices.Equal(a.Args, b.Args)
	})
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
