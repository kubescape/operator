package cautils

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

// LoadEnvironmentVariables -
func LoadEnvironmentVariables() (err error) {
	pathToConfig := os.Getenv("CA_CONFIG") // if empty, will load config from default path
	ClusterConfig, err = utilsmetadata.LoadConfig(pathToConfig, true)
	if err != nil {
		glog.Warning(err.Error())
	}

	loadMandatoryVariables()

	// vuln
	if CA_VULNSCAN, err = testEnvironmentVariable("CA_VULNSCAN"); err != nil {
		// TODO - set default
	} else {
		if !strings.HasPrefix(CA_VULNSCAN, "http") {
			CA_VULNSCAN = fmt.Sprintf("http://%s", CA_VULNSCAN)
		}
		if NotificationServerWSURL, err = testEnvironmentVariable("CA_NOTIFICATION_SERVER_WS"); err != nil {
			// TODO - set default
			glog.Errorf("CA_NOTIFICATION_SERVER_WS not set. Won't be able to run on-demand commands")
			// return err
		}
	}

	return nil
}

func AdoptClusterName(clusterName string) string {
	return strings.ReplaceAll(clusterName, "/", "-")
}

func loadMandatoryVariables() (err error) {
	if Namespace, err = testEnvironmentVariable("CA_NAMESPACE"); err != nil {
		return err
	}
	if ClusterName, err = testEnvironmentVariable("CA_CLUSTER_NAME"); err != nil {

		return err
	}
	ClusterName = AdoptClusterName(ClusterName)

	if PostmanURL, err = testEnvironmentVariable("CA_POSTMAN"); err != nil {
		return err
	}
	if AccountID, err = testEnvironmentVariable("CA_CUSTOMER_GUID"); err != nil {
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
