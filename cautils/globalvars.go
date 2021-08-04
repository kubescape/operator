package cautils

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	pkgcautils "github.com/armosec/capacketsgo/cautils"

	"github.com/golang/glog"
)

var (
	CA_NAMESPACE                    = ""
	CA_CLUSTER_NAME                 = ""
	CA_POSTMAN                      = ""
	CA_CUSTOMER_GUID                = ""
	CA_LOGIN_SECRET_NAME            = ""
	CA_DASHBOARD_BACKEND            = ""
	CA_OCIMAGE_URL                  = ""
	CA_VULNSCAN                     = ""
	RestAPIPort                     = "4002"
	CA_USE_DOCKER                   = false
	CA_DEBUG_SIGNER                 = false
	CA_IGNORE_VERIFY_CACLI          = false
	NotificationServerWSURL         = ""
	NotificationServerRESTURL       = ""
	ScanDisabled              bool  = false
	SignerSemaphore           int64 = 4
)

var ClusterConfig = &pkgcautils.ClusterConfig{}

// LoadEnvironmentVaribles -
func LoadEnvironmentVaribles() (err error) {
	ClusterConfig, err = pkgcautils.LoadConfig("", true)
	if err != nil {
		glog.Warning(err.Error())
	}
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
		CA_LOGIN_SECRET_NAME = "ca-login"
	}
	if CA_DASHBOARD_BACKEND, err = testEnvironmentVarible("CA_DASHBOARD_BACKEND"); err != nil {
		return err
	}
	if CA_OCIMAGE_URL, err = testEnvironmentVarible("CA_OCIMAGE_URL"); err != nil {
		return err
	} else {
		if !strings.HasPrefix(CA_OCIMAGE_URL, "http") {
			CA_OCIMAGE_URL = fmt.Sprintf("http://%s/v1", CA_OCIMAGE_URL)
		}
	}
	if CA_VULNSCAN, err = testEnvironmentVarible("CA_VULNSCAN"); err != nil || CA_VULNSCAN == "" {
		ScanDisabled = true
	} else {
		if !strings.HasPrefix(CA_VULNSCAN, "http") {
			CA_VULNSCAN = fmt.Sprintf("http://%s", CA_VULNSCAN)
		}
	}

	if skipClair, err := testEnvironmentVarible("SKIP_CLAIR"); err == nil {
		if skipClair == "true" {
			ScanDisabled = true
		}
	}
	if RestAPIPort, err = testEnvironmentVarible("CA_PORT"); err != nil || RestAPIPort == "" {
		RestAPIPort = "4002"
	}
	if NotificationServerWSURL, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER_WS"); err != nil {
		// return err
		glog.Warningf("missing CA_NOTIFICATION_SERVER_REST env")
	}
	if NotificationServerRESTURL, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER_REST"); err != nil {
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
