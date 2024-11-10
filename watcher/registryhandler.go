package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/backend/pkg/command"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/strings/slices"
	"sigs.k8s.io/yaml"
	"time"
)

const (
	registryCronjobTemplate = "registry-scan-cronjob-template"
	cronjobTemplateName     = "cronjobTemplate"
)

var (
	secretGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	configMapGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "configmaps",
	}

	cronJobGVR = schema.GroupVersionResource{
		Group:    "batch",
		Version:  "v1",
		Resource: "cronjobs",
	}
)

type RegistryCommandsHandler struct {
	ctx             context.Context
	k8sAPI          *k8sinterface.KubernetesApi
	commands        chan v1alpha1.OperatorCommand
	commandsWatcher *CommandWatchHandler
}

func NewRegistryCommandsHandler(ctx context.Context, k8sAPI *k8sinterface.KubernetesApi, commandsWatcher *CommandWatchHandler) *RegistryCommandsHandler {
	return &RegistryCommandsHandler{
		ctx:             ctx,
		k8sAPI:          k8sAPI,
		commands:        make(chan v1alpha1.OperatorCommand, 100),
		commandsWatcher: commandsWatcher,
	}
}

func (ch *RegistryCommandsHandler) Start() {
	ch.commandsWatcher.RegisterForCommands(ch.commands)

	for {
		select {
		case cmd := <-ch.commands:
			if !isRegistryCommand(cmd.Spec.CommandType) {
				continue
			}
			status := v1alpha1.OperatorCommandStatus{
				Executer:  "operator",
				Started:   true,
				StartedAt: &metav1.Time{Time: time.Now()},
			}
			var err error

			switch cmd.Spec.CommandType {
			case string(command.OperatorCommandTypeCreateRegistry), string(command.OperatorCommandTypeUpdateRegistry):
				err = ch.upsertRegistry(cmd)
			case string(command.OperatorCommandTypeDeleteRegistry):
				err = ch.deleteRegistry(cmd)
			}

			status.Completed = true
			status.CompletedAt = &metav1.Time{Time: time.Now()}
			if err != nil {
				status.Error = &v1alpha1.OperatorCommandStatusError{Message: err.Error()}
			}
			ch.patchCommandStatus(&cmd, status)

		case <-ch.ctx.Done():
			logger.L().Ctx(ch.ctx).Info("RegistryCommandsHandler: context done")
			return
		}
	}
}

func (ch *RegistryCommandsHandler) patchCommandStatus(command *v1alpha1.OperatorCommand, status v1alpha1.OperatorCommandStatus) {
	patchBytes, err := json.Marshal(map[string]v1alpha1.OperatorCommandStatus{"status": status})
	if err != nil {
		logger.L().Error("patchCommandStatus - failed to marshal status patch", helpers.Error(err))
		return
	}

	_, err = ch.k8sAPI.GetDynamicClient().Resource(v1alpha1.SchemaGroupVersionResource).Namespace(command.Namespace).Patch(
		ch.ctx,
		command.Name,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
		"status",
	)
	if err != nil {
		logger.L().Error("patchCommandStatus - failed to patch command status", helpers.Error(err))
	}
	logger.L().Info("patchCommandStatus: command status patched successfully")
}

func (ch *RegistryCommandsHandler) deleteRegistry(cmd v1alpha1.OperatorCommand) error {
	registry, err := armotypes.UnmarshalRegistry(cmd.Spec.Body)
	if err != nil {
		logger.L().Error("deleteRegistry - failed to unmarshal command payload", helpers.Error(err))
		return err
	}
	resourceName := registry.GetBase().ResourceName
	err = ch.k8sAPI.KubernetesClient.BatchV1().CronJobs(armotypes.KubescapeNamespace).Delete(context.Background(), resourceName, metav1.DeleteOptions{})
	if err != nil {
		logger.L().Error("deleteRegistry - failed to delete cronjob resource", helpers.Error(err))
		return err
	}
	err = ch.k8sAPI.KubernetesClient.CoreV1().Secrets(armotypes.KubescapeNamespace).Delete(context.Background(), resourceName, metav1.DeleteOptions{})
	if err != nil {
		logger.L().Error("deleteRegistry - failed to delete secret resource", helpers.Error(err))
		return err
	}
	err = ch.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(armotypes.KubescapeNamespace).Delete(context.Background(), resourceName, metav1.DeleteOptions{})
	if err != nil {
		logger.L().Error("deleteRegistry - failed to delete configmap resource", helpers.Error(err))
		return err
	}

	logger.L().Info("deleteRegistry: registry deleted successfully")
	return nil
}

func (ch *RegistryCommandsHandler) upsertRegistry(cmd v1alpha1.OperatorCommand) error {
	registry, err := armotypes.UnmarshalRegistry(cmd.Spec.Body)
	if err != nil {
		logger.L().Error("upsertRegistry - failed to unmarshal command payload", helpers.Error(err))
		return err
	}

	secret, err := createSecretObject(registry)
	if err != nil {
		logger.L().Error("upsertRegistry - failed to create secret resource", helpers.Error(err))
		return err
	}
	if err = ch.upsertResource(secret, secretGVR, secret.Name); err != nil {
		logger.L().Error("upsertRegistry - failed to upsert secret resource", helpers.Error(err))
		return err
	}

	configMap, err := createConfigMapObject(registry)
	if err != nil {
		logger.L().Error("upsertRegistry - failed to create config map resource", helpers.Error(err))
		return err
	}
	if err = ch.upsertResource(configMap, configMapGVR, configMap.Name); err != nil {
		logger.L().Error("upsertRegistry - failed to upsert config map resource", helpers.Error(err))
		return err
	}

	cronJob, err := createCronJobObject(ch.k8sAPI, registry)
	if err != nil {
		logger.L().Error("upsertRegistry - failed to create cron job resource", helpers.Error(err))
		return err
	}
	if err = ch.upsertResource(cronJob, cronJobGVR, cronJob.Name); err != nil {
		logger.L().Error("upsertRegistry - failed to upsert cron job resource", helpers.Error(err))
		return err
	}

	logger.L().Info("upsertRegistry: registry upserted successfully")
	return nil
}

func (ch *RegistryCommandsHandler) upsertResource(resource interface{}, gvr schema.GroupVersionResource, name string) error {
	applyOpts := metav1.ApplyOptions{
		FieldManager: "application/apply-patch",
		Force:        true,
	}
	unstructuredResource, err := runtime.DefaultUnstructuredConverter.ToUnstructured(resource)
	if err != nil {
		return err
	}
	_, err = ch.k8sAPI.DynamicClient.Resource(gvr).Namespace(armotypes.KubescapeNamespace).Apply(ch.ctx, name, &unstructured.Unstructured{Object: unstructuredResource}, applyOpts)
	return err
}

func createCronJobObject(k8sAPI *k8sinterface.KubernetesApi, registry armotypes.ContainerImageRegistry) (*batchv1.CronJob, error) {
	template, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(armotypes.KubescapeNamespace).Get(context.Background(), registryCronjobTemplate, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	jobTemplateStr, ok := template.Data[cronjobTemplateName]
	if !ok {
		return nil, fmt.Errorf("getCronJobTemplate: jobTemplate not found")
	}
	cronjob := &batchv1.CronJob{}
	if err := yaml.Unmarshal([]byte(jobTemplateStr), cronjob); err != nil {
		return nil, err
	}
	cronjob.Name = registry.GetBase().ResourceName
	cronjob.Spec.Schedule = registry.GetBase().ScanFrequency
	for i, v := range cronjob.Spec.JobTemplate.Spec.Template.Spec.Volumes {
		if v.Name == armotypes.RegistryRequestVolumeName {
			if cronjob.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap != nil {
				cronjob.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap.Name = registry.GetBase().ResourceName
			}
		}
	}
	cronjob.ObjectMeta.Labels = map[string]string{"app": registry.GetBase().ResourceName}

	return cronjob, nil
}

func createSecretObject(registry armotypes.ContainerImageRegistry) (*v1.Secret, error) {
	secret := v1.Secret{}
	secret.Name = registry.GetBase().ResourceName
	secret.Kind = armotypes.K8sKindSecret
	secret.APIVersion = armotypes.K8sApiVersionV1
	secret.Type = v1.SecretTypeOpaque
	secret.Namespace = armotypes.KubescapeNamespace
	secret.StringData = make(map[string]string)
	registryAuthBytes, err := json.Marshal(registry.ExtractSecret())
	if err != nil {
		return nil, err
	}
	secret.StringData[armotypes.RegistryAuthFieldInSecret] = string(registryAuthBytes)

	return &secret, err
}

func createConfigMapObject(registry armotypes.ContainerImageRegistry) (*v1.ConfigMap, error) {
	configMap := v1.ConfigMap{}
	configMap.Name = registry.GetBase().ResourceName
	configMap.Kind = armotypes.K8sKindConfigMap
	configMap.APIVersion = armotypes.K8sApiVersionV1
	configMap.Namespace = armotypes.KubescapeNamespace
	configMap.Labels = map[string]string{"app": registry.GetBase().ResourceName}
	cmd, err := getCommandForConfigMap(registry, registry.GetBase().ResourceName)
	if err != nil {
		return nil, err
	}
	configMap.Data = map[string]string{armotypes.RegistryCommandBody: cmd}

	return &configMap, nil
}

func getCommandForConfigMap(imageRegistry armotypes.ContainerImageRegistry, resourceName string) (string, error) {
	scanRegistryCommand := apis.Command{}
	scanRegistryCommand.CommandName = apis.TypeScanRegistryV2
	scanRegistryCommand.Args = map[string]interface{}{}
	scanRegistryCommand.Args[armotypes.RegistryInfoArgKey] = *imageRegistry.GetBase()
	scanRegistryCommand.Args[armotypes.RegistrySecretNameArgKey] = resourceName

	scanRegistryCommands := apis.Commands{}
	scanRegistryCommands.Commands = append(scanRegistryCommands.Commands, scanRegistryCommand)

	scanV1Bytes, err := json.Marshal(scanRegistryCommands)
	if err != nil {
		return "", err
	}

	return string(scanV1Bytes), nil
}

var registryCommands = []string{
	string(command.OperatorCommandTypeCreateRegistry),
	string(command.OperatorCommandTypeUpdateRegistry),
	string(command.OperatorCommandTypeDeleteRegistry),
}

func isRegistryCommand(commandType string) bool {
	return slices.Contains(registryCommands, commandType)
}
