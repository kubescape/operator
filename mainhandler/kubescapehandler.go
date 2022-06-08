package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"math/rand"
	"net/http"
	"time"

	armoapi "github.com/armosec/armoapi-go/apis"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	utilsapisv1 "github.com/armosec/opa-utils/httpserver/apis/v1"
	"github.com/armosec/utils-go/httputils"
	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	WaitTimeForKubescapeScanResponse = 40
)

type kubescapeResponseData struct {
	reporter reporterlib.IReporter
	scanID   string
}

func (actionHandler *ActionHandler) deleteKubescapeCronJob() error {

	kubescapeJobParams := getKubescapeJobParams(&actionHandler.command)
	if kubescapeJobParams == nil {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}

	if err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Delete(context.Background(), kubescapeJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Delete(context.Background(), kubescapeJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}
	return nil
}

func getRegistryScanJobParams(command *armoapi.Command) *armoapi.CronJobParams {

	if jobParams := command.GetCronJobParams(); jobParams != nil {
		return jobParams
	}

	// fallback
	if jobParams, ok := command.Args["jobParams"]; ok {
		if jobParams, ok := jobParams.(armoapi.CronJobParams); ok {
			return &jobParams
		}
		b, err := json.Marshal(jobParams)
		if err != nil {
			return nil
		}
		jobParams := &armoapi.CronJobParams{}
		if err = json.Unmarshal(b, jobParams); err != nil {
			return nil
		}
		return jobParams
	}
	return nil
}

func (actionHandler *ActionHandler) updateKubescapeCronJob() error {
	jobParams := getRegistryScanJobParams(&actionHandler.command)
	if jobParams == nil {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}

	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Get(context.Background(), jobParams.JobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobTemplateObj.Spec.Schedule = actionHandler.getCronTabSchedule()
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armoJobIDAnnotation] = actionHandler.command.JobTracking.JobID

	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) setKubescapeCronJob() error {

	req, err := getKubescapeRequest(actionHandler.command.Args)
	if err != nil {
		return err
	}

	for i := range req.TargetNames {
		name := fixK8sCronJobNameLimit(fmt.Sprintf("%s-%s-%d", "ks-scheduled-scan", req.TargetNames[i], rand.NewSource(time.Now().UnixNano()).Int63()))

		// create config map
		if err := createTriggerRequestConfigMap(actionHandler.k8sAPI, name, req); err != nil {
			return err
		}

		jobTemplateObj, err := getCronJonTemplate(actionHandler.k8sAPI, "kubescape-cronjob-template")
		if err != nil {
			return err
		}

		setCronJobTemplate(jobTemplateObj, name, actionHandler.getCronTabSchedule(), actionHandler.command.JobTracking.JobID, req.TargetNames[i], req.TargetType, req.HostScanner)

		// create cronJob
		if _, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func HandleKubascapeResponse(payload interface{}) (bool, *time.Duration) {
	data := payload.(*kubescapeResponseData)
	glog.Infof("handle kubescape response for scan id %s", data.scanID)

	info := fmt.Sprintf("getting kubescape scanID %s job status", data.scanID)
	data.reporter.SendAction(info, true)

	resp, err := httputils.HttpGet(http.DefaultClient, getKubescapeV1ScanStatusURL(data.scanID).String(), nil)
	if err != nil {
		info := fmt.Sprintf("get scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		data.reporter.SendStatus(info, true)
		data.reporter.SendError(err, true, true)
		glog.Errorf("get scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		return false, nil
	}

	response, err := readKubescapeV1ScanResponse(resp)
	if err != nil {
		info := fmt.Sprintf("parse scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		data.reporter.SendStatus(info, true)
		data.reporter.SendError(err, true, true)
		glog.Errorf("parse scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		return false, nil
	}

	if response.Type == utilsapisv1.BusyScanResponseType {
		nextTimeRehandled := time.Duration(WaitTimeForKubescapeScanResponse * time.Second)
		info = fmt.Sprintf("Kubescape get job status for scanID '%s' is %s next handle time is %s", data.scanID, utilsapisv1.BusyScanResponseType, nextTimeRehandled.String())
		glog.Infof("%s", info)
		data.reporter.SendStatus(info, true)
		return true, &nextTimeRehandled
	}

	info = fmt.Sprintf("Kubescape get job status scanID '%s' finished succussfully", data.scanID)
	glog.Infof("%s", info)
	data.reporter.SendStatus(info, true)
	return false, nil
}

func (actionHandler *ActionHandler) kubescapeScan() error {

	request, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
	if err != nil {
		return err
	}

	body, err := json.Marshal(*request)
	if err != nil {
		return err
	}
	resp, err := httputils.HttpPost(http.DefaultClient, getKubescapeV1ScanURL().String(), nil, body)
	if err != nil {
		return err
	}
	response, err := readKubescapeV1ScanResponse(resp)
	if err != nil {
		return err
	}
	info := fmt.Sprintf("triggered successfully, scan ID: '%s'", response.ID)

	if response.Type == utilsapisv1.ErrorScanResponseType {
		info = fmt.Sprintf("Kubescape scanID '%s' returned an error: %s", response.ID, response.Response)
	}
	actionHandler.reporter.SendStatus(info, true)
	glog.Infof(info)

	data := &kubescapeResponseData{
		reporter: actionHandler.reporter,
		scanID:   response.ID,
	}

	nextHandledTime := time.Duration(WaitTimeForKubescapeScanResponse * time.Second)
	commandResponseData := createNewCommandResponseData(KubascapeResponse, HandleKubascapeResponse, data, &nextHandledTime)
	insertNewCommandResponseData(actionHandler.commandResponseChannel, commandResponseData)

	return nil
}

// runKubescapeJob - deprecated
func (actionHandler *ActionHandler) runKubescapeJob() error {

	return actionHandler.kubescapeScan()

	// 	namespaceName := cautils.CA_NAMESPACE
	// 	configMap, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(namespaceName).Get(context.Background(), "kubescape-job-template", metav1.GetOptions{})
	// 	if err != nil {
	// 		return err

	// 	}
	// 	rulesList, ok := actionHandler.command.Args["rules"].([]opapolicy.PolicyIdentifier)
	// 	if !ok {
	// 		return fmt.Errorf("failed to convert rules list to PolicyIdentifier")
	// 	}
	// 	jobTemplateStr := configMap.Data["jobTemplate"]
	// 	for ruleIdx := range rulesList {
	// 		jobTemplateObj := &v1.Job{}
	// 		if err := yaml.Unmarshal([]byte(jobTemplateStr), jobTemplateObj); err != nil {
	// 			return err
	// 		}
	// 		// inject kubescape CLI parameters into pod spec
	// 		ruleName := rulesList[ruleIdx].Name
	// 		jobName := fmt.Sprintf("%s-%s-%s", jobTemplateObj.Name, ruleName, actionHandler.command.JobTracking.JobID)
	// 		jobName = fixK8sJobNameLimit(jobName)
	// 		if !strings.Contains(jobName, ruleName) {
	// 			rndInt := rand.NewSource(time.Now().UnixNano()).Int63()
	// 			jobName = fmt.Sprintf("%s-%d-%s", jobTemplateObj.Name, rndInt, ruleName)
	// 			jobName = fixK8sJobNameLimit(jobName)
	// 		}
	// 		jobTemplateObj.Name = jobName

	// 		jobTemplateObj.Spec.Template.Spec.Containers[0].Args = combineKubescapeCMDArgsWithFrameworkName(ruleName, jobTemplateObj.Spec.Template.Spec.Containers[0].Args)
	// 		if jobTemplateObj.Spec.Template.Annotations == nil {
	// 			jobTemplateObj.Spec.Template.Annotations = make(map[string]string)
	// 		}
	// 		jobTemplateObj.Spec.Template.Annotations["armo.jobid"] = actionHandler.command.JobTracking.JobID
	// 		jobTemplateObj.Spec.Template.Annotations["armo.framework"] = ruleName
	// 		_, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{})
	// 		if err != nil {
	// 			return err
	// 		}
	// 		// watch job status
	// 		watchHand, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Watch(
	// 			context.Background(), metav1.ListOptions{FieldSelector: fmt.Sprintf("metadata.name=%s", jobTemplateObj.Name)})
	// 		if err != nil {
	// 			return err
	// 		}
	// 		timerForError := time.NewTimer(4 * time.Minute)
	// 		defer func() {
	// 			if !timerForError.Stop() {
	// 				<-timerForError.C
	// 			}
	// 		}()
	// 		watchChan := watchHand.ResultChan()
	// 		eventCount := int32(0) // ugly workaround for not reported failures
	// 		backoffL := int32(6)
	// 		if jobTemplateObj.Spec.BackoffLimit == nil {
	// 			jobTemplateObj.Spec.BackoffLimit = &backoffL
	// 		} else {
	// 			backoffL = *jobTemplateObj.Spec.BackoffLimit
	// 		}
	// 		for {
	// 			var event watch.Event
	// 			select {
	// 			case event = <-watchChan:
	// 			case <-timerForError.C:
	// 				glog.Errorf("New job watch - timer signal")
	// 				logs, shouldReturn, returnValue := actionHandler.getJobPodLogs(namespaceName, jobTemplateObj)
	// 				if shouldReturn {
	// 					return fmt.Errorf("timer out signal, no pod logs: %v", returnValue)
	// 				}
	// 				return fmt.Errorf("timer out signal, pod logs: %s", logs)
	// 			}
	// 			if event.Type == watch.Error {
	// 				glog.Errorf("New job watch chan loop error: %v", event.Object)
	// 				watchHand.Stop()
	// 				return fmt.Errorf("new job watch chan loop error: %v", event.Object)
	// 			}

	// 			jobTemplateObjReal, ok := event.Object.(*v1.Job)
	// 			if !ok {
	// 				glog.Errorf("New job watch - failed to convert job: %v", event)
	// 				continue
	// 			}
	// 			eventCount++
	// 			if jobTemplateObjReal.Status.Succeeded == 0 && jobTemplateObj.Status.Failed == 0 && jobTemplateObjReal.Status.Active == 0 {
	// 				jobTemplateObjReal, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Get(context.Background(), jobTemplateObjReal.Name, metav1.GetOptions{})
	// 				if err != nil {
	// 					glog.Errorf("New job watch - failed to get job: %s", jobTemplateObj.Name)
	// 					continue
	// 				}
	// 			}
	// 			if jobTemplateObjReal.Status.Succeeded > 0 {
	// 				glog.Infof("job %s succeeded", jobTemplateObj.Name)
	// 				break
	// 			} else if jobTemplateObjReal.Status.Failed > backoffL || eventCount > backoffL+1 {
	// 				glog.Errorf("job %s failed", jobTemplateObj.Name)
	// 				// reading logs of pod
	// 				logs, shouldReturn, returnValue := actionHandler.getJobPodLogs(namespaceName, jobTemplateObjReal)
	// 				if shouldReturn {
	// 					return returnValue
	// 				}
	// 				glog.Errorf("job %s failed, error logs: %s", jobTemplateObjReal.Name, string(logs))

	// 				return fmt.Errorf("job %s failed, error logs: %s", jobTemplateObjReal.Name, string(logs))
	// 			} else {
	// 				glog.Errorf("job %s status unknown: %+v", jobTemplateObjReal.Name, jobTemplateObjReal.Status)
	// 			}
	// 		}
	// 	}
	// 	return nil
	// }

	// func (actionHandler *ActionHandler) getJobPodLogs(namespaceName string, jobTemplateObjReal *v1.Job) ([]byte, bool, error) {
	// 	podList, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(namespaceName).List(
	// 		context.Background(), metav1.ListOptions{LabelSelector: fmt.Sprintf("job-name=%s", jobTemplateObjReal.Name)})
	// 	if err != nil {
	// 		return nil, true, fmt.Errorf("new job watch -failed to get pods: %v", err)
	// 	}
	// 	if len(podList.Items) < 1 {
	// 		return nil, true, fmt.Errorf("new job watch - wrong number of pods: %v", len(podList.Items))
	// 	}
	// 	podLogOpts := corev1.PodLogOptions{Timestamps: true, Container: jobTemplateObjReal.Spec.Template.Spec.Containers[0].Name}
	// 	logsObj := actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(namespaceName).GetLogs(podList.Items[0].Name, &podLogOpts)
	// 	readerObj, err := logsObj.Stream(actionHandler.k8sAPI.Context)
	// 	if err != nil {
	// 		return nil, true, fmt.Errorf("failed to get pod logs stream: %v", err)
	// 	}
	// 	logs, err := io.ReadAll(readerObj)
	// 	if err != nil {
	// 		return nil, true, fmt.Errorf("failed to read pod logs stream: %v", err)
	// 	}
	// 	return logs, false, nil
}

func (actionHandler *ActionHandler) getCronTabSchedule() string {
	if kubescapeJobParams := getKubescapeJobParams(&actionHandler.command); kubescapeJobParams != nil {
		return kubescapeJobParams.CronTabSchedule
	}
	if schedule, ok := actionHandler.command.Args["cronTabSchedule"]; ok {
		if s, k := schedule.(string); k {
			return s
		}
	}
	if len(actionHandler.command.Designators) > 0 {
		if schedule, ok := actionHandler.command.Designators[0].Attributes["cronTabSchedule"]; ok {
			return schedule
		}
	}

	return ""
}

func getKubescapeJobParams(command *armoapi.Command) *armoapi.CronJobParams {

	if jobParams := command.GetCronJobParams(); jobParams != nil {
		return jobParams
	}

	// fallback
	if jobParams, ok := command.Args["kubescapeJobParams"]; ok {
		if kubescapeJobParams, ok := jobParams.(armoapi.CronJobParams); ok {
			return &kubescapeJobParams
		}
		b, err := json.Marshal(jobParams)
		if err != nil {
			return nil
		}
		kubescapeJobParams := &armoapi.CronJobParams{}
		if err = json.Unmarshal(b, kubescapeJobParams); err != nil {
			return nil
		}
		return kubescapeJobParams
	}
	return nil
}
