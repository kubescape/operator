package cautils

import (
	"fmt"
	"os"
)

var (
	CA_NAMESPACE           = ""
	CA_SERVICE_NAME        = ""
	CA_SERVICE_PORT        = ""
	CA_PORATL_BACKEND      = ""
	CA_CLUSTER_NAME        = ""
	CA_POSTMAN             = ""
	CA_CUSTOMER_GUID       = ""
	CA_LOGIN_SECRET_NAME   = ""
	CA_DASHBOARD_BACKEND   = ""
	CA_OCIMAGE_URL         = ""
	CA_USE_DOCKER          = false
	CA_IGNORE_VERIFY_CACLI = false
)

// InjectedEnvironments the environment vars that the webhook injects
var (
	InjectedEnvironments = []string{"CAA_LITTLE_BOY", "CAA_ENABLE_DISCOVERY", "CAA_CONTAINER_NAME", "CAA_CONTAINER_IMAGE_NAME", "CAA_ORACLE_SERVER", "CAA_HOME", "CAA_NOTIFICATION_SERVER",
		"CAA_LOADNAMES", "CAA_GUID", "LD_PRELOAD", "CAA_ENABLE_GOLANG_HOOK", "CAA_OVERRIDDEN_CMD", "CAA_OVERRIDDEN_ARGS", "CAA_POD_NAME"}
	InjectedVolumes      = []string{"caa-home-vol"}
	InjectedVolumeMounts = []string{"caa-home-vol"}
)

// LoadEnvironmentVaribles -
func LoadEnvironmentVaribles() (err error) {

	if CA_NAMESPACE, err = testEnvironmentVarible("CA_NAMESPACE"); err != nil {
		return err
	}
	if CA_SERVICE_NAME, err = testEnvironmentVarible("CA_SERVICE_NAME"); err != nil {
		return err
	}
	if CA_SERVICE_PORT, err = testEnvironmentVarible("CA_SERVICE_PORT"); err != nil {
		return err
	}
	if CA_PORATL_BACKEND, err = testEnvironmentVarible("CA_PORATL_BACKEND"); err != nil {
		return err
	}
	if CA_CLUSTER_NAME, err = testEnvironmentVarible("CA_CLUSTER_NAME"); err != nil {
		return err
	}
	if CA_POSTMAN, err = testEnvironmentVarible("CA_POSTMAN"); err != nil {
		return err
	}
	if CA_CUSTOMER_GUID, err = testEnvironmentVarible("CA_CUSTOMER_GUID"); err != nil {
		return err
	}
	if CA_LOGIN_SECRET_NAME, err = testEnvironmentVarible("CA_LOGIN_SECRET_NAME"); err != nil {
		return err
	}
	if CA_DASHBOARD_BACKEND, err = testEnvironmentVarible("CA_DASHBOARD_BACKEND"); err != nil {
		return err
	}
	if CA_OCIMAGE_URL, err = testEnvironmentVarible("CA_OCIMAGE_URL"); err != nil {
		return err
	}

	// environment varible not mandatory
	if ignore, _ := testEnvironmentVarible("CA_IGNORE_VERIFY_CACLI"); ignore != "" {
		CA_IGNORE_VERIFY_CACLI = true
	}

	// environment varible not mandatory
	if useDocker, _ := testEnvironmentVarible("CA_USE_DOCKER"); useDocker != "" {
		if useDocker == "true" {
			CA_USE_DOCKER = true
		}
	}

	SetKindReverseMap()

	return nil
}
func testEnvironmentVarible(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("missing/empty environment variable %s", key)
	}
	return v, nil
}
