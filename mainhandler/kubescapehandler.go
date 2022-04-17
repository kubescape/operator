package mainhandler

import (
	"context"
	"fmt"
	"io"
	"k8s-ca-websocket/cautils"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/armosec/utils-go/httputils"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/yaml"

	// pkgcautils "github.com/armosec/utils-k8s-go/wlid"

	opapolicy "github.com/armosec/opa-utils/reporthandling"
	"github.com/golang/glog"
)

func (actionHandler *ActionHandler) deleteKubescapeCronJob() error {

	kubescapeJobParams, ok := actionHandler.command.Args["kubescapeJobParams"].(opapolicy.KubescapeJobParams)
	if !ok {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}
	err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Delete(context.Background(), kubescapeJobParams.Name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateKubescapeCronJob() error {
	kubescapeJobParams, ok := actionHandler.command.Args["kubescapeJobParams"].(opapolicy.KubescapeJobParams)
	if !ok {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}
	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Get(context.Background(), kubescapeJobParams.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobName := kubescapeJobParams.Name
	jobName = fixK8sCronJobNameLimit(jobName)
	jobTemplateObj.Name = jobName
	jobTemplateObj.Spec.Schedule = kubescapeJobParams.CronTabSchedule
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

func (actionHandler *ActionHandler) setKubescapeCronJob() error {
	// TODO: use "kubescapeJobParams" instead of "rules"
	rulesList, ok := actionHandler.command.Args["rules"].([]opapolicy.PolicyIdentifier)
	if !ok {
		return fmt.Errorf("failed to convert rules list to PolicyIdentifier")
	}
	configMap, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Get(context.Background(), "kubescape-cronjob-template", metav1.GetOptions{})
	if err != nil {
		return err

	}
	jobTemplateStr := configMap.Data["cronjobTemplate"]
	for ruleIdx := range rulesList {
		jobTemplateObj := &v1.CronJob{}
		if err := yaml.Unmarshal([]byte(jobTemplateStr), jobTemplateObj); err != nil {
			return err
		}
		ruleName := rulesList[ruleIdx].Name

		jobName := fmt.Sprintf("%s-%s", jobTemplateObj.Name, ruleName)
		jobName = fixK8sCronJobNameLimit(jobName)
		if !strings.Contains(jobName, ruleName) {
			rndInt := rand.NewSource(time.Now().UnixNano()).Int63()
			jobName = fmt.Sprintf("%s-%d-%s", jobTemplateObj.Name, rndInt, ruleName)
			jobName = fixK8sCronJobNameLimit(jobName)
		}
		jobTemplateObj.Name = jobName
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Command = []string{"curl"}
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Args = combineKubescapeCMDArgsWithFrameworkName(ruleName, jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Args)
		jobTemplateObj.Spec.Schedule = actionHandler.command.Designators[0].Attributes["cronTabSchedule"]
		if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
			jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
		}
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.jobid"] = actionHandler.command.JobTracking.JobID
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.framework"] = ruleName
		_, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func combineKubescapeCMDArgsWithFrameworkName(frameworkName string, currentArgs []string) []string {
	kubescapeScanCMDToken := "scan"
	kubescapeFrameworkCMDToken := "framework"
	for len(currentArgs) > 0 && !strings.HasPrefix(currentArgs[0], "-") {
		currentArgs = currentArgs[1:]
	}
	firstArgs := []string{kubescapeScanCMDToken}
	if frameworkName != "" {
		firstArgs = []string{kubescapeScanCMDToken, kubescapeFrameworkCMDToken, frameworkName}
	}
	return append(firstArgs, currentArgs...)
}

func fixK8sCronJobNameLimit(jobName string) string {
	return fixK8sNameLimit(jobName, 52)
}

func fixK8sJobNameLimit(jobName string) string {
	return fixK8sNameLimit(jobName, 63)
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

func (actionHandler *ActionHandler) kubescapeScan() error {

	request, err := actionHandler.getKubescapeV1ScanRequest()
	if err != nil {
		return err
	}

	resp, err := httputils.HttpPost(http.DefaultClient, kubescapeV1ScanURL().String(), nil, request)
	if err != nil {
		return err
	}
	response, err := getKubescapeV1ScanResponse(resp)
	if err != nil {
		return err
	}

	info := fmt.Sprintf("triggered successfully, scan ID: '%s'", response.ID)
	actionHandler.reporter.SendStatus(info, true)
	glog.Infof(info)

	// TODO
	// wait for scan to complete

	return nil
}

func (actionHandler *ActionHandler) runKubescapeJob() error {
	// TODO: use "kubescapeJobParams" instead of "rules"
	if err := convertRulesToRequest(actionHandler.command.Args); err != nil {
		return err
	}

	return actionHandler.kubescapeScan()

	namespaceName := cautils.CA_NAMESPACE
	configMap, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(namespaceName).Get(context.Background(), "kubescape-job-template", metav1.GetOptions{})
	if err != nil {
		return err

	}
	rulesList, ok := actionHandler.command.Args["rules"].([]opapolicy.PolicyIdentifier)
	if !ok {
		return fmt.Errorf("failed to convert rules list to PolicyIdentifier")
	}
	jobTemplateStr := configMap.Data["jobTemplate"]
	for ruleIdx := range rulesList {
		jobTemplateObj := &v1.Job{}
		if err := yaml.Unmarshal([]byte(jobTemplateStr), jobTemplateObj); err != nil {
			return err
		}
		// inject kubescape CLI parameters into pod spec
		ruleName := rulesList[ruleIdx].Name
		jobName := fmt.Sprintf("%s-%s-%s", jobTemplateObj.Name, ruleName, actionHandler.command.JobTracking.JobID)
		jobName = fixK8sJobNameLimit(jobName)
		if !strings.Contains(jobName, ruleName) {
			rndInt := rand.NewSource(time.Now().UnixNano()).Int63()
			jobName = fmt.Sprintf("%s-%d-%s", jobTemplateObj.Name, rndInt, ruleName)
			jobName = fixK8sJobNameLimit(jobName)
		}
		jobTemplateObj.Name = jobName

		jobTemplateObj.Spec.Template.Spec.Containers[0].Args = combineKubescapeCMDArgsWithFrameworkName(ruleName, jobTemplateObj.Spec.Template.Spec.Containers[0].Args)
		if jobTemplateObj.Spec.Template.Annotations == nil {
			jobTemplateObj.Spec.Template.Annotations = make(map[string]string)
		}
		jobTemplateObj.Spec.Template.Annotations["armo.jobid"] = actionHandler.command.JobTracking.JobID
		jobTemplateObj.Spec.Template.Annotations["armo.framework"] = ruleName
		_, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		// watch job status
		watchHand, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Watch(
			context.Background(), metav1.ListOptions{FieldSelector: fmt.Sprintf("metadata.name=%s", jobTemplateObj.Name)})
		if err != nil {
			return err
		}
		timerForError := time.NewTimer(4 * time.Minute)
		defer func() {
			if !timerForError.Stop() {
				<-timerForError.C
			}
		}()
		watchChan := watchHand.ResultChan()
		eventCount := int32(0) // ugly workaround for not reported failures
		backoffL := int32(6)
		if jobTemplateObj.Spec.BackoffLimit == nil {
			jobTemplateObj.Spec.BackoffLimit = &backoffL
		} else {
			backoffL = *jobTemplateObj.Spec.BackoffLimit
		}
		for {
			var event watch.Event
			select {
			case event = <-watchChan:
			case <-timerForError.C:
				glog.Errorf("New job watch - timer signal")
				logs, shouldReturn, returnValue := actionHandler.getJobPodLogs(namespaceName, jobTemplateObj)
				if shouldReturn {
					return fmt.Errorf("timer out signal, no pod logs: %v", returnValue)
				}
				return fmt.Errorf("timer out signal, pod logs: %s", logs)
			}
			if event.Type == watch.Error {
				glog.Errorf("New job watch chan loop error: %v", event.Object)
				watchHand.Stop()
				return fmt.Errorf("new job watch chan loop error: %v", event.Object)
			}

			jobTemplateObjReal, ok := event.Object.(*v1.Job)
			if !ok {
				glog.Errorf("New job watch - failed to convert job: %v", event)
				continue
			}
			eventCount++
			if jobTemplateObjReal.Status.Succeeded == 0 && jobTemplateObj.Status.Failed == 0 && jobTemplateObjReal.Status.Active == 0 {
				jobTemplateObjReal, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Get(context.Background(), jobTemplateObjReal.Name, metav1.GetOptions{})
				if err != nil {
					glog.Errorf("New job watch - failed to get job: %s", jobTemplateObj.Name)
					continue
				}
			}
			if jobTemplateObjReal.Status.Succeeded > 0 {
				glog.Infof("job %s succeeded", jobTemplateObj.Name)
				break
			} else if jobTemplateObjReal.Status.Failed > backoffL || eventCount > backoffL+1 {
				glog.Errorf("job %s failed", jobTemplateObj.Name)
				// reading logs of pod
				logs, shouldReturn, returnValue := actionHandler.getJobPodLogs(namespaceName, jobTemplateObjReal)
				if shouldReturn {
					return returnValue
				}
				glog.Errorf("job %s failed, error logs: %s", jobTemplateObjReal.Name, string(logs))

				return fmt.Errorf("job %s failed, error logs: %s", jobTemplateObjReal.Name, string(logs))
			} else {
				glog.Errorf("job %s status unknown: %+v", jobTemplateObjReal.Name, jobTemplateObjReal.Status)
			}
		}
	}
	return nil
}

func (actionHandler *ActionHandler) getJobPodLogs(namespaceName string, jobTemplateObjReal *v1.Job) ([]byte, bool, error) {
	podList, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(namespaceName).List(
		context.Background(), metav1.ListOptions{LabelSelector: fmt.Sprintf("job-name=%s", jobTemplateObjReal.Name)})
	if err != nil {
		return nil, true, fmt.Errorf("new job watch -failed to get pods: %v", err)
	}
	if len(podList.Items) < 1 {
		return nil, true, fmt.Errorf("new job watch - wrong number of pods: %v", len(podList.Items))
	}
	podLogOpts := corev1.PodLogOptions{Timestamps: true, Container: jobTemplateObjReal.Spec.Template.Spec.Containers[0].Name}
	logsObj := actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(namespaceName).GetLogs(podList.Items[0].Name, &podLogOpts)
	readerObj, err := logsObj.Stream(actionHandler.k8sAPI.Context)
	if err != nil {
		return nil, true, fmt.Errorf("failed to get pod logs stream: %v", err)
	}
	logs, err := io.ReadAll(readerObj)
	if err != nil {
		return nil, true, fmt.Errorf("failed to read pod logs stream: %v", err)
	}
	return logs, false, nil
}
