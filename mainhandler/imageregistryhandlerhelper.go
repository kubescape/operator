package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/docker/docker/api/types"
	"github.com/kubescape/operator/utils"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (actionHandler *ActionHandler) updateSecret(sessionObj *utils.SessionObj, secretName string, authConfig *types.AuthConfig) error {
	secretObj, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(armotypes.KubescapeNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
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
	_, err = actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(armotypes.KubescapeNamespace).Update(context.Background(), secretObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (actionHandler *ActionHandler) updateConfigMap(sessionObj *utils.SessionObj, configMapName string, registryScan *registryScan) error {
	configMapObj, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(armotypes.KubescapeNamespace).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	command, err := registryScan.getCommandForConfigMap()
	if err != nil {
		return err
	}
	configMapObj.Data[requestBodyFile] = string(command)

	_, err = actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(armotypes.KubescapeNamespace).Update(context.Background(), configMapObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateCronJob(sessionObj *utils.SessionObj, cronJobName string) error {
	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(armotypes.KubescapeNamespace).Get(context.Background(), cronJobName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobTemplateObj.Spec.Schedule = getCronTabSchedule(actionHandler.command)
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}

	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationUpdateJobIDDeprecated] = actionHandler.command.JobTracking.JobID // deprecated
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationUpdateJobID] = actionHandler.command.JobTracking.JobID

	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(armotypes.KubescapeNamespace).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateRegistryScanCronJob(sessionObj *utils.SessionObj) error {
	jobParams := actionHandler.command.GetCronJobParams()
	if jobParams == nil {
		glog.Infof("In updateRegistryScanCronJob failed with error: jobParams is nil")
		sessionObj.Reporter.SetDetails("GetCronJobParams")
		return fmt.Errorf("jobParams is nil")
	}

	registryScan, err := actionHandler.loadRegistryScan(sessionObj)
	if err != nil {
		glog.Errorf("In updateRegistryScanCronJob: loadRegistryScan failed with error: %v", err.Error())
		sessionObj.Reporter.SetDetails("loadRegistryScan")
		return err
	}

	name := jobParams.JobName

	// if there is password, get secret and update it (same name)
	if registryScan.isPrivate() && (registryScan.authConfig().Password != "" || registryScan.authConfig().Username != "") {
		err = actionHandler.updateSecret(sessionObj, name, registryScan.authConfig())
		if err != nil {
			glog.Errorf("In updateRegistryScanCronJob: updateSecret failed with error: %v", err.Error())
			sessionObj.Reporter.SetDetails("updateSecret")
			return err
		}
		glog.Infof("updateRegistryScanCronJob: secret: %v updated successfully", name)
	}

	err = actionHandler.updateConfigMap(sessionObj, name, registryScan)
	if err != nil {
		glog.Errorf("In updateRegistryScanCronJob: updateConfigMap failed with error: %v", err.Error())
		sessionObj.Reporter.SetDetails("updateConfigMap")
		return err
	}
	glog.Infof("updateRegistryScanCronJob: configmap: %v updated successfully", name)

	if jobParams.CronTabSchedule != "" {
		err = actionHandler.updateCronJob(sessionObj, name)
		if err != nil {
			glog.Errorf("In updateRegistryScanCronJob: updateCronJob failed with error: %v", err.Error())
			sessionObj.Reporter.SetDetails("updateRegistryScanCronJob")
			return err
		}
		glog.Infof("updateRegistryScanCronJob: cronjob: %v updated successfully", name)
	}
	return nil

}

func (actionHandler *ActionHandler) setRegistryScanCronJob(sessionObj *utils.SessionObj) error {
	// If command has credentials on it, create secret with it.
	// Create configmap with command to trigger operator. Command includes secret name (if there were credentials).
	// Create cronjob which will send request to operator to trigger scan using the configmap (and secret) data.

	if getCronTabSchedule(sessionObj.Command) == "" {
		return fmt.Errorf("schedule cannot be empty")
	}

	registryScan, err := actionHandler.loadRegistryScan(sessionObj)
	if err != nil {
		glog.Errorf("In parseRegistryCommand: error: %v", err.Error())
		sessionObj.Reporter.SetDetails("loadRegistryScan")
		return fmt.Errorf("scanRegistries failed with err %v", err)
	}

	// name is registryScanConfigmap name + random string - configmap, cronjob and secret
	nameSuffix := rand.NewSource(time.Now().UnixNano()).Int63()
	name := fixK8sCronJobNameLimit(fmt.Sprintf("%s-%d", registryScanConfigmap, nameSuffix))
	if registryScan.isPrivate() {
		err = registryScan.createTriggerRequestSecret(actionHandler.k8sAPI, name, registryScan.registryInfo.RegistryName)
		if err != nil {
			glog.Infof("In setRegistryScanCronJob: createTriggerRequestSecret failed with error: %s", err.Error())
			sessionObj.Reporter.SetDetails("createTriggerRequestSecret")
			return err
		}
		glog.Info("setRegistryScanCronJob: secret created successfully")
	}

	// create configmap with POST data to trigger websocket
	err = registryScan.createTriggerRequestConfigMap(actionHandler.k8sAPI, name, registryScan.registryInfo.RegistryName, sessionObj.Command)
	if err != nil {
		glog.Infof("In setRegistryScanCronJob: createTriggerRequestConfigMap failed with error: %s", err.Error())
		sessionObj.Reporter.SetDetails("createTriggerRequestConfigMap")
		return err
	}
	glog.Info("setRegistryScanCronJob: configmap created successfully")

	err = registryScan.createTriggerRequestCronJob(actionHandler.k8sAPI, name, registryScan.registryInfo.RegistryName, sessionObj.Command)
	if err != nil {
		glog.Infof("In setRegistryScanCronJob: createTriggerRequestCronJob failed with error: %s", err.Error())
		sessionObj.Reporter.SetDetails("createTriggerRequestCronJob")
		return err
	}
	glog.Infof("setRegistryScanCronJob: cronjob: %s created successfully", name)

	return err
}

func (actionHandler *ActionHandler) deleteRegistryScanCronJob() error {
	// Delete cronjob, configmap and secret (if exists)
	jobParams := actionHandler.command.GetCronJobParams()
	if jobParams == nil {
		glog.Infof("updateRegistryScanCronJob: failed to get jobParams")
		return fmt.Errorf("failed to get jobParams")
	}

	name := jobParams.JobName
	err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(armotypes.KubescapeNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		err = actionHandler.k8sAPI.KubernetesClient.BatchV1beta1().CronJobs(armotypes.KubescapeNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil {
			glog.Infof("deleteRegistryScanCronJob: deleteCronJob failed with error: %v", err.Error())
			return err
		}
	}
	glog.Infof("deleteRegistryScanCronJob: cronjob: %v deleted successfully", name)

	// delete secret
	err = actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(armotypes.KubescapeNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		// if secret not found, it means was configured without credentials
		if !strings.Contains(err.Error(), "not found") {
			glog.Infof("deleteRegistryScanCronJob: deleteSecret failed with error: %v", err.Error())
		}
	}
	glog.Infof("deleteRegistryScanCronJob: secret: %v deleted successfully", name)

	// delete configmap
	err = actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(armotypes.KubescapeNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		glog.Infof("deleteRegistryScanCronJob: deleteConfigMap failed with error: %v", err.Error())
	}
	glog.Infof("deleteRegistryScanCronJob: configmap: %v deleted successfully", name)

	return nil
}
