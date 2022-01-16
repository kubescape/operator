package cautils

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/armosec/utils-k8s-go/armometadata"

	"github.com/golang/glog"
)

type SystemModeRunner string

const (
	SystemModeAll  SystemModeRunner = "ALL"
	SystemModeScan SystemModeRunner = "SCAN"
)

var (
	CA_NAMESPACE              string           = ""
	CA_CLUSTER_NAME           string           = ""
	CA_POSTMAN                string           = ""
	CA_CUSTOMER_GUID          string           = ""
	CA_DASHBOARD_BACKEND      string           = ""
	CA_OCIMAGE_URL            string           = ""
	CA_VULNSCAN               string           = ""
	RestAPIPort               string           = "4002"
	CA_USE_DOCKER             bool             = false
	CA_DEBUG_SIGNER           bool             = false
	CA_IGNORE_VERIFY_CACLI    bool             = false
	NotificationServerWSURL   string           = ""
	NotificationServerRESTURL string           = ""
	ScanDisabled              bool             = false
	SignerSemaphore           int64            = 4
	SystemMode                SystemModeRunner = SystemModeAll
)

var ClusterConfig = &armometadata.ClusterConfig{}

// LoadEnvironmentVaribles -
func LoadEnvironmentVaribles() (err error) {
	ClusterConfig, err = armometadata.LoadConfig("", true)
	if err != nil {
		glog.Warning(err.Error())
	}

	if systemMode, _ := testEnvironmentVarible("CA_SYSTEM_MODE"); systemMode != "" {
		SystemMode = SystemModeRunner(systemMode)
	}

	loadMandatoryVariables()

	// armo components helm chart
	// if SystemMode == SystemModeScan {

	// }

	if SystemMode == SystemModeAll || SystemMode == SystemModeScan {
		// vuln
		if CA_VULNSCAN, err = testEnvironmentVarible("CA_VULNSCAN"); err != nil || CA_VULNSCAN == "" {
			ScanDisabled = true
			// TODO - set default
		} else {
			if !strings.HasPrefix(CA_VULNSCAN, "http") {
				CA_VULNSCAN = fmt.Sprintf("http://%s", CA_VULNSCAN)
			}
			if NotificationServerWSURL, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER_WS"); err != nil {
				// TODO - set default
				glog.Errorf("CA_NOTIFICATION_SERVER_WS not set. Won't be able to run on-demand commands")
				// return err
			}
		}
	}

	if SystemMode == SystemModeAll {

		if CA_DASHBOARD_BACKEND, err = testEnvironmentVarible("CA_DASHBOARD_BACKEND"); err != nil {
			return err
		}
		if CA_OCIMAGE_URL, err = testEnvironmentVarible("CA_OCIMAGE_URL"); err != nil {
			// CA_USE_DOCKER = true
			return err
		} else {
			if !strings.HasPrefix(CA_OCIMAGE_URL, "http") {
				CA_OCIMAGE_URL = fmt.Sprintf("http://%s/v1", CA_OCIMAGE_URL)
			}
		}

		if RestAPIPort, err = testEnvironmentVarible("CA_PORT"); err != nil || RestAPIPort == "" {
			RestAPIPort = "4002"
		}
		if NotificationServerWSURL, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER_WS"); err != nil {
			// TODO - set default
			return err
		}
		if NotificationServerRESTURL, err = testEnvironmentVarible("CA_NOTIFICATION_SERVER_REST"); err != nil {
			// TODO - set default
			return err
		}

		if signerSemaphore, err := testEnvironmentVarible("CA_SIGNER_SEMAPHORE"); err == nil {
			i, err := strconv.ParseInt(signerSemaphore, 10, 64)
			if err != nil {
				return fmt.Errorf("failed to convert '%s' from 'CA_SIGNER_SEMAPHORE' to int64, reason: %s", signerSemaphore, err.Error())
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

	}

	return nil
}

func AdoptClusterName(clusterName string) string {
	return strings.ReplaceAll(clusterName, "/", "-")
}

func loadMandatoryVariables() (err error) {
	if CA_NAMESPACE, err = testEnvironmentVarible("CA_NAMESPACE"); err != nil {
		return err
	}
	if CA_CLUSTER_NAME, err = testEnvironmentVarible("CA_CLUSTER_NAME"); err != nil {

		return err
	}
	CA_CLUSTER_NAME = AdoptClusterName(CA_CLUSTER_NAME)

	if CA_POSTMAN, err = testEnvironmentVarible("CA_POSTMAN"); err != nil {
		return err
	}
	if CA_CUSTOMER_GUID, err = testEnvironmentVarible("CA_CUSTOMER_GUID"); err != nil {
		return err
	}

	return nil
}
func testEnvironmentVarible(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("missing/empty environment variable %s", key)
	}
	return v, nil
}
