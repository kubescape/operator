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

	if err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.Namespace).Delete(context.Background(), kubescapeJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.Namespace).Delete(context.Background(), kubescapeJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateKubescapeCronJob() error {
	jobParams := getKubescapeJobParams(&actionHandler.command)
	if jobParams == nil {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}

	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.Namespace).Get(context.Background(), jobParams.JobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobTemplateObj.Spec.Schedule = getCronTabSchedule(actionHandler.command)
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armoUpdateJobIDAnnotationDeprecated] = actionHandler.command.JobTracking.JobID // deprecated
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armoUpdateJobIDAnnotation] = actionHandler.command.JobTracking.JobID

	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.Namespace).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
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

		jobTemplateObj, err := getCronJobTemplate(actionHandler.k8sAPI, "kubescape-cronjob-template")
		if err != nil {
			return err
		}

		setCronJobTemplate(jobTemplateObj, name, getCronTabSchedule(actionHandler.command), actionHandler.command.JobTracking.JobID, req.TargetNames[i], req.TargetType, req.HostScanner)

		// create cronJob
		if _, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.Namespace).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func HandleKubascapeResponse(payload interface{}) (bool, *time.Duration) {
	data := payload.(*kubescapeResponseData)
	glog.Infof("handle kubescape response for scan id %s", data.scanID)

	info := fmt.Sprintf("getting kubescape scanID %s job status", data.scanID)
	errChan := make(chan error)
	data.reporter.SendDetails(info, true, errChan)
	if err := <-errChan; err != nil {
		glog.Errorf("HandleKubascapeResponse failed to send error report.  %s", err.Error())
	}

	resp, err := httputils.HttpGet(http.DefaultClient, getKubescapeV1ScanStatusURL(data.scanID).String(), nil)
	if err != nil {
		info := fmt.Sprintf("get scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		data.reporter.SendDetails(info, true, errChan)
		if err := <-errChan; err != nil {
			glog.Errorf("HandleKubascapeResponse failed to send status report.  %s", err.Error())
		}
		data.reporter.SendError(err, true, true, errChan)
		if err := <-errChan; err != nil {
			glog.Errorf("HandleKubascapeResponse::error in HTTP GET + failed to send error report.  %s", err.Error())
		}
		glog.Errorf("get scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		return false, nil
	}

	response, err := readKubescapeV1ScanResponse(resp)
	if err != nil {
		info := fmt.Sprintf("parse scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		data.reporter.SendDetails(info, true, errChan)
		if err := <-errChan; err != nil {
			glog.Errorf("HandleKubascapeResponse::readKubescapeV1ScanResponse failed to send status report.  %s", err.Error())
		}
		data.reporter.SendError(err, true, true, errChan)
		if err := <-errChan; err != nil {
			glog.Errorf("HandleKubascapeResponse::readKubescapeV1ScanResponse failed to send error report.  %s", err.Error())
		}
		glog.Errorf("parse scanID job status with scanID '%s' returned an error: %s", data.scanID, err.Error())
		return false, nil
	}

	if response.Type == utilsapisv1.BusyScanResponseType {
		nextTimeRehandled := time.Duration(WaitTimeForKubescapeScanResponse * time.Second)
		info = fmt.Sprintf("Kubescape get job status for scanID '%s' is %s next handle time is %s", data.scanID, utilsapisv1.BusyScanResponseType, nextTimeRehandled.String())
		glog.Infof("%s", info)
		data.reporter.SendDetails(info, true, errChan)
		if err := <-errChan; err != nil {
			glog.Errorf("HandleKubascapeResponse::BusyScanResponseType failed to send status report.  %s", err.Error())
		}
		return true, &nextTimeRehandled
	}

	info = fmt.Sprintf("Kubescape get job status scanID '%s' finished succussfully", data.scanID)
	glog.Infof("%s", info)
	data.reporter.SendDetails(info, true, errChan)
	if err := <-errChan; err != nil {
		glog.Errorf("HandleKubascapeResponse::Done failed to send status report.  %s", err.Error())
	}
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
	errChan := make(chan error)
	actionHandler.reporter.SendDetails(info, true, errChan)
	if err := <-errChan; err != nil {
		glog.Errorf("kubescapeScan::Done failed to send status report.  %s", err.Error())
	}
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

func getCronTabSchedule(command armoapi.Command) string {
	if kubescapeJobParams := getKubescapeJobParams(&command); kubescapeJobParams != nil {
		return kubescapeJobParams.CronTabSchedule
	}
	if schedule, ok := command.Args["cronTabSchedule"]; ok {
		if s, k := schedule.(string); k {
			return s
		}
	}
	if len(command.Designators) > 0 {
		if schedule, ok := command.Designators[0].Attributes["cronTabSchedule"]; ok {
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
