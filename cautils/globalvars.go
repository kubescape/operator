package cautils

import (
	"fmt"
	"os"
	"strconv"

	"github.com/golang/glog"
)

var (
	CA_NAMESPACE                                       = ""
	CA_CLUSTER_NAME                                    = ""
	CA_POSTMAN                                         = ""
	CA_CUSTOMER_GUID                                   = ""
	CA_LOGIN_SECRET_NAME                               = ""
	CA_DASHBOARD_BACKEND                               = ""
	CA_OCIMAGE_URL                                     = ""
	CA_VULNSCAN                                        = ""
	RestAPIPort                                        = ""
	CA_USE_DOCKER                                      = false
	CA_DEBUG_SIGNER                                    = false
	CA_IGNORE_VERIFY_CACLI                             = false
	NotificationServerURL                              = ""
	CA_NOTIFICATION_SERVER_SERVICE_PORT_REST_API       = ""
	CA_NOTIFICATION_SERVER_SERVICE_HOST                = ""
	ScanDisabled                                 bool  = false
	SignerSemaphore                              int64 = 4
)

// LoadEnvironmentVaribles -
func LoadEnvironmentVaribles() (err error) {

	if CA_NAMESPACE, err = testEnvironmentVarible("CA_NAMESPACE"); err != nil {
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
	if CA_VULNSCAN, err = testEnvironmentVarible("CA_VULNSCAN"); err != nil {
		// ignore
	}
	if skipClair, err := testEnvironmentVarible("SKIP_CLAIR"); err == nil {
		if skipClair == "true" {
			ScanDisabled = true
		}
	}
	if RestAPIPort, err = testEnvironmentVarible("CA_WEBSOCKET_PORT"); err != nil {
		RestAPIPort = "4002"
	}
	if NotificationServerURL, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER"); err != nil {
		// return err
		glog.Warningf("missing CA_NOTIFICATION_SERVER env")
	}
	if CA_NOTIFICATION_SERVER_SERVICE_PORT_REST_API, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER_SERVICE_PORT_REST_API"); err != nil {
		return err
	}
	if CA_NOTIFICATION_SERVER_SERVICE_HOST, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER_SERVICE_HOST"); err != nil {
		return err
	}
	if signerSemaphore, err := testEnvironmentVarible("CA_SIGNER_SEMAPHORE"); err == nil {
		i, err := strconv.ParseInt(signerSemaphore, 10, 64)
		if err != nil {
			return fmt.Errorf("Failed to convert '%s' from 'CA_SIGNER_SEMAPHORE' to int64, reason: %s", signerSemaphore, err.Error())
		}
		SignerSemaphore = i
	}

	// environment variable not mandatory
	if ignore, _ := testEnvironmentVarible("CA_IGNORE_VERIFY_CACLI"); ignore != "" {
		CA_IGNORE_VERIFY_CACLI = true
	}

	// environment variable not mandatory
	if useDocker, _ := testEnvironmentVarible("CA_USE_DOCKER"); useDocker != "" {
		if useDocker == "true" {
			CA_USE_DOCKER = true
		}
	}

	// environment variable not mandatory
	if useDocker, _ := testEnvironmentVarible("CA_DEBUG_SIGNER"); useDocker != "" {
		if useDocker == "true" {
			CA_DEBUG_SIGNER = true
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
