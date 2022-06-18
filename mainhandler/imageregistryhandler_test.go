package mainhandler

import (
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/strings/slices"
)

func TestParseConfigMapData(t *testing.T) {
	registryScanHandler := NewRegistryScanHandler()
	var configData map[string]interface{}

	// Test Include
	configDataStr := `
	{
		"registries": 
		"[ {     \"registry\": \"gcr.io/blu\",     \"depth\": 2,     \"include\": [       \"armo-vuln\" , \"armo-vuln2\"    ] }\n]\n"
	}
		`
	err := json.Unmarshal([]byte(configDataStr), &configData)
	assert.NoError(t, err)
	if err := registryScanHandler.ParseConfigMapData(configData); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}
	assert.Equal(t, registryScanHandler.registryScan[0].registry.hostname, "gcr.io")
	assert.Equal(t, registryScanHandler.registryScan[0].registry.projectID, "blu")
	assert.True(t, slices.Contains(registryScanHandler.registryScan[0].registryScanConfig.Include, "armo-vuln"))
	assert.True(t, slices.Contains(registryScanHandler.registryScan[0].registryScanConfig.Include, "armo-vuln2"))
	assert.Equal(t, registryScanHandler.registryScan[0].registry.hostname, "gcr.io")
	assert.Equal(t, registryScanHandler.registryScan[0].registry.projectID, "blu")

	// Test Exclude
	configDataStr = `
	{
		"registries": 
		"[ {     \"registry\": \"gcr.io/blu\",     \"depth\": 2,     \"include\": [      ], \"exclude\": [  \"armo-vuln\" , \"armo-vuln2\" ] }\n]\n"
	}
		`

	err = json.Unmarshal([]byte(configDataStr), &configData)
	assert.NoError(t, err)
	if err := registryScanHandler.ParseConfigMapData(configData); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}
	assert.Equal(t, registryScanHandler.registryScan[1].registry.hostname, "gcr.io")
	assert.Equal(t, registryScanHandler.registryScan[1].registry.projectID, "blu")
	assert.True(t, slices.Contains(registryScanHandler.registryScan[1].registryScanConfig.Exclude, "armo-vuln"))
	assert.True(t, slices.Contains(registryScanHandler.registryScan[1].registryScanConfig.Exclude, "armo-vuln2"))

	// Test no ProjectID
	configDataStr = `
	{
		"registries": 
		"[ {     \"registry\": \"gcr.io\",     \"depth\": 2,     \"include\": [      ], \"exclude\": [  \"armo-vuln\" , \"armo-vuln2\" ] }\n]\n"
	}
		`

	err = json.Unmarshal([]byte(configDataStr), &configData)
	assert.NoError(t, err)
	if err := registryScanHandler.ParseConfigMapData(configData); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}
	assert.Equal(t, registryScanHandler.registryScan[2].registry.hostname, "gcr.io")
	assert.Equal(t, registryScanHandler.registryScan[2].registry.projectID, "")
	assert.True(t, slices.Contains(registryScanHandler.registryScan[2].registryScanConfig.Exclude, "armo-vuln"))
	assert.True(t, slices.Contains(registryScanHandler.registryScan[2].registryScanConfig.Exclude, "armo-vuln2"))

	// Test both include and exclude -> error
	configDataStr = `
	{
		"registries": 
		"[ {     \"registry\": \"gcr.io\",     \"depth\": 2,     \"include\": [\"blu\"], \"exclude\": [  \"armo-vuln\" , \"armo-vuln2\" ] }\n]\n"
	}
		`

	err = json.Unmarshal([]byte(configDataStr), &configData)
	assert.NoError(t, err)
	assert.Error(t, registryScanHandler.ParseConfigMapData(configData))

}

func TestPParseSecretsData(t *testing.T) {
	registryScanHandler := NewRegistryScanHandler()
	var secretData map[string]interface{}
	registryName := "blu"
	secretDataStr := `
	{
		"registriesAuth":
	"[{\"registry\": \"mock\",\"auth_method\": \"accesstoken\",\"username\": \"username\",\"password\": \"pass\"} ]"
	}
		`
	err := json.Unmarshal([]byte(secretDataStr), &secretData)
	err = registryScanHandler.ParseSecretsData(secretData, registryName)
	assert.Error(t, err)

	secretDataStr = `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJ1c2VybmFtZSI6ICJvYXV0aDJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJwYXNzd29yZCI6ICJwYXNzIgogICAgIH0KICAgXQo="}
		`
	err = json.Unmarshal([]byte(secretDataStr), &secretData)
	assert.NoError(t, err)
	if err = registryScanHandler.ParseSecretsData(secretData, registryName); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}
	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Username, "oauth2accesstoken")
	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Password, "pass")

	secretDataStr = `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJhY2Vzc3Rva2VuIiwKICAgICAgICAgInVzZXJuYW1lIjogIm9hdXRoMmFjY2Vzc3Rva2VuIiwKICAgICAgICAgInBhc3N3b3JkIjogInBhc3MiCiAgICAgfSwKICAgICB7CiAgICAgICAgICJyZWdpc3RyeSI6ICJibGEiLAogICAgICAgICAiYXV0aF9tZXRob2QiOiAiYWNlc3N0b2tlbiIsCiAgICAgICAgICJ1c2VybmFtZSI6ICJvYXV0aDJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJwYXNzd29yZCI6ICJwYXNzIgogICAgIH0sCiAgICAgewogICAgICAgICAicmVnaXN0cnkiOiAibm9hdXRoIgogICAgIH0KICAgXQo="}
	`
	err = json.Unmarshal([]byte(secretDataStr), &secretData)
	registryName = "blu"
	assert.NoError(t, err)
	if err := registryScanHandler.ParseSecretsData(secretData, registryName); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}

	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Username, "oauth2accesstoken")
	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Password, "pass")

	secretDataStr = `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJ1c2VybmFtZSI6ICJvYXV0aDJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJwYXNzd29yZCI6ICJwYXNzIgogICAgIH0sCiAgICAgewogICAgICAgICAicmVnaXN0cnkiOiBbImJsYSJdLAogICAgICAgICAiYXV0aF9tZXRob2QiOiAiYWNjZXNzdG9rZW4iLAogICAgICAgICAidXNlcm5hbWUiOiAib2F1dGgyYWNjZXNzdG9rZW4iLAogICAgICAgICAicGFzc3dvcmQiOiAicGFzcyIKICAgICB9LAogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogIm5vYXV0aCIKICAgICB9CiAgIF0K"}
 `
	err = json.Unmarshal([]byte(secretDataStr), &secretData)
	registryName = "blu"
	assert.NoError(t, err)
	assert.Error(t, registryScanHandler.ParseSecretsData(secretData, registryName))
}

// func TestLocalRegistryScan(t *testing.T) {
// 	registryScanHandler := NewRegistryScanHandler()
// 	var secretData map[string]interface{}
// 	var configData map[string]interface{}
// 	registryName := "127.0.0.1:5000"
// 	secretDataStr := `
// 	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJ1c2VybmFtZSI6ICJvYXV0aDJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJwYXNzd29yZCI6ICJwYXNzIgogICAgIH0KICAgXQo="}
// 		`
// 	err := json.Unmarshal([]byte(secretDataStr), &secretData)
// 	assert.NoError(t, err)
// 	if err := registryScanHandler.ParseSecretsData(secretData, registryName); err != nil {
// 		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
// 	}

// 	configDataStr := `
// 	{
// 		"registries":
// 		"[ {     \"registry\": \"127.0.0.1:5000\",     \"depth\": 2,     \"include\": [      ], \"exclude\": [  \"armo-vuln\" , \"armo-vuln2\" ] }\n]\n"
// 	}
// 		`

// 	err = json.Unmarshal([]byte(configDataStr), &configData)
// 	assert.NoError(t, err)
// 	if err := registryScanHandler.ParseConfigMapData(configData); err != nil {
// 		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
// 	}

// 	assert.True(t, slices.Contains(registryScanHandler.registryScan[0].registryScanConfig.Exclude, "armo-vuln"))

// 	for _, reg := range registryScanHandler.registryScan {
// 		err = registryScanHandler.GetImagesForScanning(reg)

// 		sessionObj := &cautils.SessionObj{Reporter: datastructures.NewBaseReportMock("test-guid", "test-reporter")}
// 		webSocketScanCMDList, err := convertImagesToWebsocketScanCommand(reg.mapImageToTags, sessionObj, &reg)
// 		if err != nil {
// 			t.Errorf("convertImagesToWebsocketScanCommand failed with err %v", err)
// 		}
// 		err = sendAllImagesToVulnScan(webSocketScanCMDList)
// 		if err != nil {
// 			t.Errorf("sendAllImagesToVulnScanByMemLimit failed with err %v", err)
// 		}
// 	}

// }

func TestParseSecretsDataAndConfigMap(t *testing.T) {
	registryScanHandler := NewRegistryScanHandler()
	var secretData map[string]interface{}
	var configData map[string]interface{}
	registryName := "blu"
	secretDataStr := `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJ1c2VybmFtZSI6ICJvYXV0aDJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJwYXNzd29yZCI6ICJwYXNzIgogICAgIH0KICAgXQo="}
		`
	err := json.Unmarshal([]byte(secretDataStr), &secretData)
	assert.NoError(t, err)
	if err := registryScanHandler.ParseSecretsData(secretData, registryName); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}

	configDataStr := `
	{
		"registries": 
		"[ {     \"registry\": \"blu\",     \"depth\": 2,     \"include\": [      ], \"exclude\": [  \"armo-vuln\" , \"armo-vuln2\" ] }\n]\n"
	}
		`

	err = json.Unmarshal([]byte(configDataStr), &configData)
	assert.NoError(t, err)
	if err := registryScanHandler.ParseConfigMapData(configData); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}
	assert.Equal(t, registryScanHandler.registryScan[0].registryAuth.Username, "oauth2accesstoken")
	assert.Equal(t, registryScanHandler.registryScan[0].registryAuth.Password, "pass")
	assert.Equal(t, registryScanHandler.registryScan[0].registryScanConfig.Registry, "blu")
	assert.True(t, slices.Contains(registryScanHandler.registryScan[0].registryScanConfig.Exclude, "armo-vuln"))

}

func TestGetRegistryScanV1ScanCommand(t *testing.T) {
	registryScanHandler := NewRegistryScanHandler()
	c, err := registryScanHandler.getRegistryScanV1ScanCommand("blue")
	assert.NoError(t, err)

	var command apis.Commands

	if err = json.Unmarshal([]byte(c), &command); err != nil {
		t.Errorf("error unmarshalling resitry scan command error = %v", err)
	}

	assert.Equal(t, len(command.Commands), 1)
	assert.Equal(t, command.Commands[0].CommandName, apis.TypeScanRegistry)

	name := command.Commands[0].Args[registryInfoV1].(map[string]interface{})
	assert.Equal(t, name[registryNameField], "blue")

}

func TestSetCronJobTemplate(t *testing.T) {
	registryScanHandler := NewRegistryScanHandler()

	cronjob := v1.CronJob{}

	v := corev1.Volume{Name: requestVolumeName}
	cronjob.Spec.JobTemplate.Spec.Template.Spec.Volumes = []corev1.Volume{v}
	v.ConfigMap = &corev1.ConfigMapVolumeSource{}

	registryScanHandler.setCronJobTemplate(&cronjob, "blu", "* 0 * * *", "10", "registry")

	assert.Equal(t, cronjob.Name, "blu")
	assert.Equal(t, cronjob.Labels["app"], "blu")
	assert.Equal(t, cronjob.Spec.Schedule, "* 0 * * *")
	assert.Equal(t, cronjob.Spec.JobTemplate.Spec.Template.Annotations[registryNameAnnotation], "registry")
	assert.Equal(t, len(cronjob.Spec.JobTemplate.Spec.Template.Spec.Volumes), 1)
	assert.Equal(t, cronjob.Spec.JobTemplate.Spec.Template.Spec.Volumes[0].Name, requestVolumeName)

	cronjob.Spec.JobTemplate.Spec.Template.Spec.Volumes = nil
	assert.Equal(t, cronjob.Name, "blu")
	assert.Equal(t, cronjob.Labels["app"], "blu")
	assert.Equal(t, cronjob.Spec.Schedule, "* 0 * * *")
	assert.Equal(t, cronjob.Spec.JobTemplate.Spec.Template.Annotations[registryNameAnnotation], "registry")

}
