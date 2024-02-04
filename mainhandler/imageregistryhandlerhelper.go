package mainhandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/docker/docker/api/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/utils"
	"go.opentelemetry.io/otel"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (actionHandler *ActionHandler) updateSecret(sessionObj *utils.SessionObj, secretName string, authConfig *types.AuthConfig) error {
	secretObj, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(actionHandler.config.Namespace()).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	var registriesAuth []registryAuth
	registriesAuthStr, ok := secretObj.Data[registriesAuthFieldInSecret]
	if !ok {
		return fmt.Errorf("failed to get registriesAuthFieldInSecret")
	}
	err = json.Unmarshal(registriesAuthStr, &registriesAuth)

	if err != nil {
		return err
	}
	if len(registriesAuth) != 1 {
		return fmt.Errorf("registriesAuth length is: %v and not 1", len(registriesAuth))
	}

	registriesAuth[0].Username = authConfig.Username
	registriesAuth[0].Password = authConfig.Password

	authMarshal, err := json.Marshal(registriesAuth)
	if err != nil {
		return err
	}
	secretObj.Data[registriesAuthFieldInSecret] = authMarshal
	_, err = actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(actionHandler.config.Namespace()).Update(context.Background(), secretObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (actionHandler *ActionHandler) updateConfigMap(sessionObj *utils.SessionObj, configMapName string, registryScan *registryScan) error {
	configMapObj, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(actionHandler.config.Namespace()).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	command, err := registryScan.getCommandForConfigMap()
	if err != nil {
		return err
	}
	configMapObj.Data[requestBodyFile] = string(command)

	_, err = actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(actionHandler.config.Namespace()).Update(context.Background(), configMapObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateCronJob(sessionObj *utils.SessionObj, cronJobName string) error {
	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(actionHandler.config.Namespace()).Get(context.Background(), cronJobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobTemplateObj.Spec.Schedule = getCronTabSchedule(actionHandler.command)
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}

	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationUpdateJobIDDeprecated] = actionHandler.command.JobTracking.JobID // deprecated
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationUpdateJobID] = actionHandler.command.JobTracking.JobID

	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(actionHandler.config.Namespace()).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateRegistryScanCronJob(ctx context.Context, sessionObj *utils.SessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.updateRegistryScanCronJob")
	defer span.End()

	if !actionHandler.config.Components().KubevulnScheduler.Enabled {
		return errors.New("KubevulnScheduler is not enabled")
	}

	jobParams := actionHandler.command.GetCronJobParams()
	if jobParams == nil {
		logger.L().Info("In updateRegistryScanCronJob failed with error: jobParams is nil")
		sessionObj.Reporter.SetDetails("GetCronJobParams")
		return fmt.Errorf("jobParams is nil")
	}

	name := jobParams.JobName
	registryScan, err := actionHandler.loadRegistryScan(ctx, sessionObj)
	if err != nil {
		// could be old update command. On this case, there is no secret and configmap
		logger.L().Ctx(ctx).Error("In updateRegistryScanCronJob: loadRegistryScan failed", helpers.Error(err))
		return actionHandler.updateCronTabSchedule(ctx, name, jobParams.CronTabSchedule, sessionObj)
	}

	// if there is password, get secret and update it (same name)
	if registryScan.isPrivate() && (registryScan.authConfig().Password != "" || registryScan.authConfig().Username != "") {
		err = actionHandler.updateSecret(sessionObj, name, registryScan.authConfig())
		if err != nil {
			logger.L().Ctx(ctx).Error("In updateRegistryScanCronJob: updateSecret failed", helpers.Error(err))
			sessionObj.Reporter.SetDetails("updateSecret")
			return err
		}
		logger.L().Info(fmt.Sprintf("updateRegistryScanCronJob: secret: %v updated successfully", name))
	}

	err = actionHandler.updateConfigMap(sessionObj, name, registryScan)
	if err != nil {
		logger.L().Ctx(ctx).Error("In updateRegistryScanCronJob: updateConfigMap failed", helpers.Error(err))
		sessionObj.Reporter.SetDetails("updateConfigMap")
		return err
	}
	logger.L().Info(fmt.Sprintf("updateRegistryScanCronJob: configmap: %v updated successfully", name))

	return actionHandler.updateCronTabSchedule(ctx, name, jobParams.CronTabSchedule, sessionObj)
}

func (actionHandler *ActionHandler) updateCronTabSchedule(ctx context.Context, name, schedule string, sessionObj *utils.SessionObj) error {
	if schedule != "" {
		err := actionHandler.updateCronJob(sessionObj, name)
		if err != nil {
			logger.L().Ctx(ctx).Error("In updateRegistryScanCronJob: updateCronJob failed", helpers.Error(err))
			sessionObj.Reporter.SetDetails("updateRegistryScanCronJob")
			return err
		}
		logger.L().Info(fmt.Sprintf("updateRegistryScanCronJob: cronjob: %v updated successfully", name))
	}
	return nil
}

func (actionHandler *ActionHandler) setRegistryScanCronJob(ctx context.Context, sessionObj *utils.SessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.setRegistryScanCronJob")
	defer span.End()

	if !actionHandler.config.Components().KubevulnScheduler.Enabled {
		return errors.New("KubevulnScheduler is not enabled")
	}

	// If command has credentials on it, create secret with it.
	// Create configmap with command to trigger operator. Command includes secret name (if there were credentials).
	// Create cronjob which will send request to operator to trigger scan using the configmap (and secret) data.

	if getCronTabSchedule(sessionObj.Command) == "" {
		return fmt.Errorf("schedule cannot be empty")
	}

	registryScan, err := actionHandler.loadRegistryScan(ctx, sessionObj)
	if err != nil {
		logger.L().Ctx(ctx).Error("In parseRegistryCommand", helpers.Error(err))
		sessionObj.Reporter.SetDetails("loadRegistryScan")
		return fmt.Errorf("scanRegistries failed with err %v", err)
	}

	// name is registryScanConfigmap name + random string - configmap, cronjob and secret
	nameSuffix := rand.NewSource(time.Now().UnixNano()).Int63()
	name := fixK8sCronJobNameLimit(fmt.Sprintf("%s-%d", registryScanConfigmap, nameSuffix))
	if registryScan.isPrivate() {
		err = registryScan.createTriggerRequestSecret(actionHandler.k8sAPI, name, registryScan.registryInfo.RegistryName)
		if err != nil {
			logger.L().Info("In setRegistryScanCronJob: createTriggerRequestSecret failed", helpers.Error(err))
			sessionObj.Reporter.SetDetails("createTriggerRequestSecret")
			return err
		}
		logger.L().Info("setRegistryScanCronJob: secret created successfully")
	}

	// create configmap with POST data to trigger websocket
	err = registryScan.createTriggerRequestConfigMap(actionHandler.k8sAPI, name, registryScan.registryInfo.RegistryName, sessionObj.Command)
	if err != nil {
		logger.L().Info("In setRegistryScanCronJob: createTriggerRequestConfigMap failed", helpers.Error(err))
		sessionObj.Reporter.SetDetails("createTriggerRequestConfigMap")
		return err
	}
	logger.L().Info("setRegistryScanCronJob: configmap created successfully")

	err = registryScan.createTriggerRequestCronJob(actionHandler.k8sAPI, name, registryScan.registryInfo.RegistryName, sessionObj.Command)
	if err != nil {
		logger.L().Info("In setRegistryScanCronJob: createTriggerRequestCronJob failed", helpers.Error(err))
		sessionObj.Reporter.SetDetails("createTriggerRequestCronJob")
		return err
	}
	logger.L().Info(fmt.Sprintf("setRegistryScanCronJob: cronjob: %s created successfully", name))

	return err
}

func (actionHandler *ActionHandler) deleteRegistryScanCronJob(ctx context.Context) error {
	_, span := otel.Tracer("").Start(ctx, "actionHandler.deleteRegistryScanCronJo")
	defer span.End()

	if !actionHandler.config.Components().KubevulnScheduler.Enabled {
		return errors.New("KubevulnScheduler is not enabled")
	}

	// Delete cronjob, configmap and secret (if exists)
	jobParams := actionHandler.command.GetCronJobParams()
	if jobParams == nil {
		logger.L().Error("updateRegistryScanCronJob: failed to get jobParams")
		return fmt.Errorf("failed to get jobParams")
	}

	name := jobParams.JobName
	err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(actionHandler.config.Namespace()).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		err = actionHandler.k8sAPI.KubernetesClient.BatchV1beta1().CronJobs(actionHandler.config.Namespace()).Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil {
			logger.L().Error("deleteRegistryScanCronJob: deleteCronJob failed", helpers.Error(err))
			return err
		}
	}
	logger.L().Info(fmt.Sprintf("deleteRegistryScanCronJob: cronjob: %v deleted successfully", name))

	// delete secret
	err = actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(actionHandler.config.Namespace()).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		// if secret not found, it means was configured without credentials
		if !strings.Contains(err.Error(), "not found") {
			logger.L().Error("deleteRegistryScanCronJob: deleteSecret failed", helpers.Error(err))
		}
	}
	logger.L().Info(fmt.Sprintf("deleteRegistryScanCronJob: secret: %v deleted successfully", name))

	// delete configmap
	err = actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(actionHandler.config.Namespace()).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		logger.L().Error("deleteRegistryScanCronJob: deleteConfigMap failed", helpers.Error(err))
	}
	logger.L().Info(fmt.Sprintf("deleteRegistryScanCronJob: configmap: %v deleted successfully", name))

	return nil
}
