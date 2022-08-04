package utils

import (
	"fmt"
	"os"
	"strings"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"

	"github.com/golang/glog"
)

var (
	Namespace                 string = ""
	ClusterName               string = ""
	PostmanURL                string = ""
	AccountID                 string = ""
	CA_VULNSCAN               string = ""
	RestAPIPort               string = "4002"
	NotificationServerWSURL   string = ""
	NotificationServerRESTURL string = ""
)

var ClusterConfig = &utilsmetadata.ClusterConfig{}

func LoadEnvironmentVariables() (err error) {
	pathToConfig := os.Getenv(ConfigEnvironmentVariable) // if empty, will load config from default path
	ClusterConfig, err = utilsmetadata.LoadConfig(pathToConfig, true)
	if err != nil {
		glog.Warning(err.Error())
	}

	loadMandatoryVariables()

	if CA_VULNSCAN, err = testEnvironmentVariable(VulnScanEnvironmentVariable); err != nil {
		// TODO: set default
	} else {
		if !strings.HasPrefix(CA_VULNSCAN, "http") {
			CA_VULNSCAN = fmt.Sprintf("http://%s", CA_VULNSCAN)
		}
		if NotificationServerWSURL, err = testEnvironmentVariable(NotificationServerWebsocketEnvironmentVariable); err != nil {
			// TODO: set default
			glog.Errorf("%s not set. Won't be able to run on-demand commands", NotificationServerWebsocketEnvironmentVariable)
		}
	}

	return nil
}

func AdoptClusterName(clusterName string) string {
	return strings.ReplaceAll(clusterName, "/", "-")
}

func loadMandatoryVariables() (err error) {
	if Namespace, err = testEnvironmentVariable(NamespaceEnvironmentVariable); err != nil {
		return err
	}
	if ClusterName, err = testEnvironmentVariable(ClusterNameEnvironmentVariable); err != nil {

		return err
	}
	ClusterName = AdoptClusterName(ClusterName)

	if PostmanURL, err = testEnvironmentVariable(PostmanEnvironmentVariable); err != nil {
		return err
	}
	if AccountID, err = testEnvironmentVariable(CustomerGuidEnvironmentVariable); err != nil {
		return err
	}

	return nil
}
func testEnvironmentVariable(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("missing/empty environment variable %s", key)
	}
	return v, nil
}
