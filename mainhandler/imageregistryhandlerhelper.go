package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"math/rand"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/golang/glog"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	registryCronjobTemplate = "registry-scan-cronjob-template"
	registryNameAnnotation  = "armo.cloud/registryname"
)

func (registryScanHandler *registryScanHandler) getRegistryScanV1ScanCommand(registryName string) (string, error) {
	/*
			scan registry command:
			{
		    "commands": [{
		        "CommandName": "scanRegistry",
		        "args": {
		            "registryInfo-v1": {
		                "registryName": "gcr.io/elated-pottery-310110"
		            }
		        }
		    }]
		}
	*/
	scanRegistryCommand := apis.Command{}
	scanRegistryCommand.CommandName = apis.TypeScanRegistry
	registryInfo := make(map[string]string, 0)
	registryInfo[registryNameField] = registryName

	scanRegistryCommand.Args = make(map[string]interface{}, 0)
	scanRegistryCommand.Args[registryInfoV1] = registryInfo

	scanRegistryCommands := apis.Commands{}
	scanRegistryCommands.Commands = append(scanRegistryCommands.Commands, scanRegistryCommand)

	scanV1Bytes, err := json.Marshal(scanRegistryCommands)
	if err != nil {
		return "", err
	}

	return string(scanV1Bytes), nil
}

func (registryScanHandler *registryScanHandler) createTriggerRequestConfigMap(k8sAPI *k8sinterface.KubernetesApi, name, registryName string, webSocketScanCMD apis.Command) error {
	configMap := corev1.ConfigMap{}
	configMap.Name = name
	if configMap.Labels == nil {
		configMap.Labels = make(map[string]string)
	}
	configMap.Labels["app"] = name

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}

	// command is POST request to trigger websocket
	command, err := registryScanHandler.getRegistryScanV1ScanCommand(registryName)
	if err != nil {
		return err
	}

	// command will be mounted into cronjob by using this configmap
	configMap.Data[requestBodyFile] = string(command)

	if _, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Create(context.Background(), &configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	glog.Infof("createTriggerRequestConfigMap: created configmap: %s", name)
	return nil
}

func (actionHandler *ActionHandler) updateRegistryScanCronJob() error {
	jobParams := actionHandler.command.GetCronJobParams()
	if jobParams == nil {
		glog.Infof("updateRegistryScanCronJob: failed to get jobParams")
		return fmt.Errorf("failed to get failed to get jobParams")
	}

	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Get(context.Background(), jobParams.JobName, metav1.GetOptions{})
	if err != nil {
		glog.Infof("updateRegistryScanCronJob: failed to get cronjob: %s", jobParams.JobName)
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
	glog.Infof("updateRegistryScanCronJob: cronjob: %v updated successfully", jobParams.JobName)
	return nil

}

func (actionHandler *ActionHandler) setRegistryScanCronJob(sessionObj *cautils.SessionObj) error {
	registryScanHandler := NewRegistryScanHandler()

	// parse registry name from command
	registryName, err := actionHandler.parseRegistryNameArg(sessionObj)
	if err != nil {
		glog.Infof("setRegistryScanCronJob: error parsing registry name from command: %s", err.Error())
		return err
	}

	// name is registryScanConfigmap name + random string - configmap and cronjob
	name := fixK8sCronJobNameLimit(fmt.Sprintf("%s-%d", registryScanConfigmap, rand.NewSource(time.Now().UnixNano()).Int63()))

	// create configmap with POST data to trigger websocket
	err = registryScanHandler.createTriggerRequestConfigMap(actionHandler.k8sAPI, name, registryName, sessionObj.Command)
	if err != nil {
		glog.Infof("setRegistryScanCronJob: error creating configmap : %s", err.Error())
		return err
	}

	// cronjob template is stored as configmap in cluster
	jobTemplateObj, err := getCronJonTemplate(actionHandler.k8sAPI, registryCronjobTemplate)
	if err != nil {
		glog.Infof("setRegistryScanCronJob: error retrieving cronjob template : %s", err.Error())
		return err
	}

	registryScanHandler.setCronJobTemplate(jobTemplateObj, name, actionHandler.getCronTabSchedule(), actionHandler.command.JobTracking.JobID, registryName)

	// create cronJob
	if _, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
		glog.Infof("setRegistryScanCronJob: cronjob: %s creation failed. err: %s", name, err.Error())
		return err
	}
	glog.Infof("setRegistryScanCronJob: cronjob: %s created successfully", name)
	return err
}

func (registryScanHandler *registryScanHandler) setCronJobTemplate(jobTemplateObj *v1.CronJob, name, schedule, jobID, registryName string) {

	jobTemplateObj.Name = name
	if schedule != "" {
		jobTemplateObj.Spec.Schedule = schedule
	}

	// update volume name
	for i, v := range jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes {
		if v.Name == requestVolumeName {
			if jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap != nil {
				jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap.Name = name
			}
		}
	}

	// add annotations
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}

	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[registryNameAnnotation] = registryName

	// add annotations
	if jobTemplateObj.ObjectMeta.Labels == nil {
		jobTemplateObj.ObjectMeta.Labels = make(map[string]string)
	}
	jobTemplateObj.ObjectMeta.Labels["app"] = name

}

func (actionHandler *ActionHandler) deleteRegistryScanCronJob() error {
	jobParams := actionHandler.command.GetCronJobParams()
	if jobParams == nil {
		glog.Infof("updateRegistryScanCronJob: failed to get jobParams")
		return fmt.Errorf("failed to get jobParams")
	}

	return actionHandler.deleteCronjob(jobParams.JobName)
}
