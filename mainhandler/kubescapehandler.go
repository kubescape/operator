package mainhandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-go/httputils"
	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	WaitTimeForKubescapeScanResponse = 40
	KubescapeCronJobTemplateName     = "kubescape-cronjob-template"
	maxKubescapeStatusFailures       = 3
	maxPendingStatusWriteAttempts    = 3
)

type kubescapeResponseData struct {
	scanID             string
	sessionObj         *utils.SessionObj
	statusFailures     int
	pendingWriteNeeded bool
	terminalReady      bool
	terminalError      error
}

func (data *kubescapeResponseData) complete(ctx context.Context, err error) (bool, *time.Duration) {
	data.terminalReady = true
	data.terminalError = err
	return data.writeTerminalStatus(ctx)
}

func (data *kubescapeResponseData) writeTerminalStatus(ctx context.Context) (bool, *time.Duration) {
	if data.pendingWriteNeeded {
		if err := data.sessionObj.SetOperatorCommandStatus(ctx, utils.WithPending(), utils.WithPayload([]byte(data.scanID))); err == nil {
			data.pendingWriteNeeded = false
		}
	}
	var err error
	if data.terminalError != nil {
		err = data.sessionObj.SetOperatorCommandStatus(ctx, utils.WithError(data.terminalError), utils.WithPayload([]byte(data.scanID)))
	} else {
		err = data.sessionObj.SetOperatorCommandStatus(ctx, utils.WithSuccess(), utils.WithPayload([]byte(data.scanID)))
	}
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write terminal scan status; retrying", helpers.String("scanID", data.scanID), helpers.Error(err))
		delay := time.Duration(WaitTimeForKubescapeScanResponse * time.Second)
		return true, &delay
	}
	data.pendingWriteNeeded = false
	return false, nil
}

func (data *kubescapeResponseData) statusReadFailed(ctx context.Context, err error) (bool, *time.Duration) {
	data.statusFailures++
	if data.statusFailures < maxKubescapeStatusFailures {
		logger.L().Ctx(ctx).Info("scan status temporarily unavailable; retrying", helpers.String("scanID", data.scanID), helpers.Error(err))
		delay := time.Duration(WaitTimeForKubescapeScanResponse * time.Second)
		return true, &delay
	}
	return data.complete(ctx, fmt.Errorf("scan status unavailable for scanID '%s' after %d attempts: %w", data.scanID, data.statusFailures, err))
}

func (actionHandler *ActionHandler) deleteKubescapeCronJob(ctx context.Context) error {
	_, span := otel.Tracer("").Start(ctx, "actionHandler.deleteKubescapeCronJob")
	defer span.End()

	if !actionHandler.config.Components().KubescapeScheduler.Enabled {
		return errors.New("KubescapeScheduler is not enabled")
	}

	kubescapeJobParams := getKubescapeJobParams(actionHandler.sessionObj.Command)
	if kubescapeJobParams == nil {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}

	if err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(actionHandler.config.Namespace()).Delete(context.Background(), kubescapeJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(actionHandler.config.Namespace()).Delete(context.Background(), kubescapeJobParams.JobName, metav1.DeleteOptions{}); err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateKubescapeCronJob(ctx context.Context) error {
	_, span := otel.Tracer("").Start(ctx, "actionHandler.updateKubescapeCronJob")
	defer span.End()

	if !actionHandler.config.Components().KubescapeScheduler.Enabled {
		return errors.New("KubescapeScheduler is not enabled")
	}

	jobParams := getKubescapeJobParams(actionHandler.sessionObj.Command)
	if jobParams == nil {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}

	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(actionHandler.config.Namespace()).Get(context.Background(), jobParams.JobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobTemplateObj.Spec.Schedule = getCronTabSchedule(actionHandler.sessionObj.Command)
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationUpdateJobID] = actionHandler.sessionObj.Command.JobTracking.JobID

	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(actionHandler.config.Namespace()).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) setKubescapeCronJob(ctx context.Context) error {
	_, span := otel.Tracer("").Start(ctx, "actionHandler.setKubescapeCronJob")
	defer span.End()

	if !actionHandler.config.Components().KubescapeScheduler.Enabled {
		return errors.New("KubescapeScheduler is not enabled")
	}

	req, err := getKubescapeRequest(actionHandler.sessionObj.Command.Args, actionHandler.config.DefaultFrameworks())
	if err != nil {
		return err
	}

	for i := range req.TargetNames {
		name := fixK8sCronJobNameLimit(fmt.Sprintf("%s-%s-%d", "ks-scheduled-scan", req.TargetNames[i], rand.NewSource(time.Now().UnixNano()).Int63()))

		// create config map
		if err := createTriggerRequestConfigMap(actionHandler.k8sAPI, actionHandler.config.Namespace(), name, req); err != nil {
			return err
		}

		jobTemplateObj, err := getCronJobTemplate(actionHandler.k8sAPI, KubescapeCronJobTemplateName, actionHandler.config.Namespace())
		if err != nil {
			return err
		}

		setCronJobTemplate(jobTemplateObj, name, getCronTabSchedule(actionHandler.sessionObj.Command), actionHandler.sessionObj.Command.JobTracking.JobID, req.TargetNames[i], req.TargetType, req.HostScanner)

		// create cronJob
		if _, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(actionHandler.config.Namespace()).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func HandleKubescapeResponse(ctx context.Context, config config.IConfig, payload interface{}) (bool, *time.Duration) {
	data := payload.(*kubescapeResponseData)
	logger.L().Info(fmt.Sprintf("handle kubescape response for scan id %s", data.scanID))
	if data.terminalReady {
		return data.writeTerminalStatus(ctx)
	}
	if data.pendingWriteNeeded {
		if err := data.sessionObj.SetOperatorCommandStatus(ctx, utils.WithPending(), utils.WithPayload([]byte(data.scanID))); err == nil {
			data.pendingWriteNeeded = false
		}
	}

	resp, err := httputils.HttpGetWithContext(ctx, KubescapeHttpClient, getKubescapeV1ScanStatusURL(config, data.scanID).String(), nil)
	if err != nil {
		logger.L().Ctx(ctx).Error("get scanID job status returned an error", helpers.String("scanID", data.scanID), helpers.Error(err))
		return data.statusReadFailed(ctx, err)
	}

	response, err := readKubescapeV1ScanResponse(resp)
	if err != nil {
		logger.L().Ctx(ctx).Error("parse scanID job status returned an error", helpers.String("scanID", data.scanID), helpers.Error(err))
		return data.statusReadFailed(ctx, err)
	}
	data.statusFailures = 0
	if response.ID != data.scanID {
		return data.complete(ctx, fmt.Errorf("scan outcome unavailable for scanID '%s': status returned scanID %q", data.scanID, response.ID))
	}

	if response.Type == utilsapisv1.BusyScanResponseType {
		nextTimeRehandled := time.Duration(WaitTimeForKubescapeScanResponse * time.Second)
		logger.L().Info(fmt.Sprintf("Kubescape get job status for scanID '%s' is %s next handle time is %s", data.scanID, utilsapisv1.BusyScanResponseType, nextTimeRehandled.String()))
		return true, &nextTimeRehandled
	}

	if response.Type == utilsapisv1.NotBusyScanResponseType && response.ID == data.scanID && response.Outcome == "succeeded" {
		logger.L().Info(fmt.Sprintf("Kubescape get job status scanID '%s' finished successfully", data.scanID))
		return data.complete(ctx, nil)
	}

	message := fmt.Sprintf("scan outcome unavailable for scanID '%s' (type=%q, outcome=%q)", data.scanID, response.Type, response.Outcome)
	if response.Type == utilsapisv1.NotBusyScanResponseType && response.ID == data.scanID {
		switch response.Outcome {
		case "failed":
			message = "scan failed"
		case "cancelled":
			message = "scan cancelled"
		}
		if (response.Outcome == "failed" || response.Outcome == "cancelled") && response.Error != "" {
			message = response.Error
		}
	}
	return data.complete(ctx, errors.New(message))
}

func (actionHandler *ActionHandler) kubescapeScan(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.kubescapeScan")
	defer span.End()

	if !actionHandler.config.Components().Kubescape.Enabled {
		return errors.New("kubescape is not enabled")
	}
	if details := actionHandler.sessionObj.ParentCommandDetails; details != nil && details.Command.Status.Started && !details.Command.Status.Completed && len(details.Command.Status.Payload) > 0 {
		// A restarted operator receives unfinished OperatorCommands again. The
		// pending status carries the scanner's scan ID, so resume its poll instead
		// of dispatching a second scan.
		data := &kubescapeResponseData{scanID: string(details.Command.Status.Payload), sessionObj: actionHandler.sessionObj}
		if retry, delay := HandleKubescapeResponse(ctx, actionHandler.config, data); retry {
			commandResponseData := createNewCommandResponseData(KubescapeResponse, HandleKubescapeResponse, data, delay)
			insertNewCommandResponseData(actionHandler.commandResponseChannel, commandResponseData)
		}
		return nil
	}

	request, err := getKubescapeV1ScanRequest(actionHandler.sessionObj.Command.Args, actionHandler.config.DefaultFrameworks(), actionHandler.config.ExcludeControls())
	if err != nil {
		return err
	}

	// append security framework if TriggerSecurityFramework is true
	if actionHandler.config.TriggerSecurityFramework() {
		appendSecurityFramework(request)
	}

	body, err := json.Marshal(*request)
	if err != nil {
		return err
	}
	headers := map[string]string{}
	otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(headers))
	resp, err := httputils.HttpPostWithContext(ctx, KubescapeHttpClient, getKubescapeV1ScanURL(actionHandler.config).String(), headers, body, -1, func(resp *http.Response) bool { return true })
	if err != nil {
		return err
	}
	response, err := readKubescapeV1ScanResponse(resp)
	if err != nil {
		return err
	}

	if response.Type == utilsapisv1.ErrorScanResponseType {
		err := fmt.Errorf("Kubescape scan rejected: %v", response.Response)
		logger.L().Info("Kubescape scan returned an error", helpers.String("scanID", response.ID), helpers.Error(err))
		return err
	}
	if actionHandler.sessionObj.ParentCommandDetails != nil {
		if response.Type != utilsapisv1.BusyScanResponseType {
			return fmt.Errorf("Kubescape returned unexpected async scan response type %q", response.Type)
		}
		if _, err := uuid.Parse(response.ID); err != nil {
			return fmt.Errorf("Kubescape returned invalid scan ID: %w", err)
		}
	}
	logger.L().Info("Kubescape scan triggered successfully", helpers.String("scanID", response.ID))

	data := &kubescapeResponseData{
		scanID:     response.ID,
		sessionObj: actionHandler.sessionObj,
	}

	if actionHandler.sessionObj.ParentCommandDetails != nil {
		data.pendingWriteNeeded = true
		for range maxPendingStatusWriteAttempts {
			if err := actionHandler.sessionObj.SetOperatorCommandStatus(ctx, utils.WithPending(), utils.WithPayload([]byte(response.ID))); err == nil {
				data.pendingWriteNeeded = false
				break
			}
		}
		if data.pendingWriteNeeded {
			logger.L().Ctx(ctx).Error("accepted scan ID could not be saved to OperatorCommand status; polling will retry", helpers.String("scanID", response.ID))
		}
		nextHandledTime := WaitTimeForKubescapeScanResponse * time.Second
		commandResponseData := createNewCommandResponseData(KubescapeResponse, HandleKubescapeResponse, data, &nextHandledTime)
		insertNewCommandResponseData(actionHandler.commandResponseChannel, commandResponseData)
	}

	return nil
}

func getCronTabSchedule(command *armoapi.Command) string {
	if kubescapeJobParams := getKubescapeJobParams(command); kubescapeJobParams != nil {
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
