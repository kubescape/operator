package mainhandler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
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
	"[{\"registry\": \"mock\",\"auth_method\": \"ips\",\"username\": \"username\",\"password\": \"pass\"} ]"
	}
		`
	err := json.Unmarshal([]byte(secretDataStr), &secretData)
	err = registryScanHandler.ParseSecretsData(secretData, registryName)
	assert.Error(t, err)

	secretDataStr = `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJpcHMiLAogICAgICAgICAidXNlcm5hbWUiOiAib2F1dGgyYWNjZXNzdG9rZW4iLAogICAgICAgICAicGFzc3dvcmQiOiAicGFzcyIKICAgICB9CiAgIF0K"}
		`
	err = json.Unmarshal([]byte(secretDataStr), &secretData)
	assert.NoError(t, err)
	if err = registryScanHandler.ParseSecretsData(secretData, registryName); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}
	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Username, "oauth2accesstoken")
	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Password, "pass")

	secretDataStr = `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJpcHMiLAogICAgICAgICAidXNlcm5hbWUiOiAib2F1dGgyYWNjZXNzdG9rZW4iLAogICAgICAgICAicGFzc3dvcmQiOiAicGFzcyIKICAgICB9LAogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsYSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJpcHMiLAogICAgICAgICAidXNlcm5hbWUiOiAib2F1dGgyYWNjZXNzdG9rZW4iLAogICAgICAgICAicGFzc3dvcmQiOiAicGFzcyIKICAgICB9LAogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogIm5vYXV0aCIKICAgICB9CiAgIF0K"}
	`
	err = json.Unmarshal([]byte(secretDataStr), &secretData)
	registryName = "bla"
	assert.NoError(t, err)
	if err := registryScanHandler.ParseSecretsData(secretData, registryName); err != nil {
		t.Errorf("registryScanHandler.ParseConfigMapData() error = %v", err)
	}

	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Username, "oauth2accesstoken")
	assert.Equal(t, registryScanHandler.mapRegistryToAuth[registryName].Password, "pass")

	secretDataStr = `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJpcHMiLAogICAgICAgICAidXNlcm5hbWUiOiAib2F1dGgyYWNjZXNzdG9rZW4iLAogICAgICAgICAicGFzc3dvcmQiOiAicGFzcyIKICAgICB9LAogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogWyJibGEiXSwKICAgICAgICAgImF1dGhfbWV0aG9kIjogImlwcyIsCiAgICAgICAgICJ1c2VybmFtZSI6ICJvYXV0aDJhY2Nlc3N0b2tlbiIsCiAgICAgICAgICJwYXNzd29yZCI6ICJwYXNzIgogICAgIH0sCiAgICAgewogICAgICAgICAicmVnaXN0cnkiOiAibm9hdXRoIgogICAgIH0KICAgXQo="}
 `
	err = json.Unmarshal([]byte(secretDataStr), &secretData)
	registryName = "bla"
	assert.NoError(t, err)
	assert.Error(t, registryScanHandler.ParseSecretsData(secretData, registryName))
}

func TestParseSecretsDataAndConfigMap(t *testing.T) {
	registryScanHandler := NewRegistryScanHandler()
	var secretData map[string]interface{}
	var configData map[string]interface{}
	registryName := "blu"
	secretDataStr := `
	{"registriesAuth":"WwogICAgIHsKICAgICAgICAgInJlZ2lzdHJ5IjogImJsdSIsCiAgICAgICAgICJhdXRoX21ldGhvZCI6ICJpcHMiLAogICAgICAgICAidXNlcm5hbWUiOiAib2F1dGgyYWNjZXNzdG9rZW4iLAogICAgICAgICAicGFzc3dvcmQiOiAicGFzcyIKICAgICB9CiAgIF0K"}
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
