package utils

import (
	"fmt"
	"os"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
)

var (
	Namespace   string = "default" // default namespace
	RestAPIPort string = "4002"    // default port
)

var ClusterConfig = &utilsmetadata.ClusterConfig{}

func LoadEnvironmentVariables() (err error) {
	pathToConfig := os.Getenv(ConfigEnvironmentVariable) // if empty, will load config from default path
	ClusterConfig, err = utilsmetadata.LoadConfig(pathToConfig, true)
	if err != nil {
		return err
	}

	if ClusterConfig.ClusterName == "" {
		return fmt.Errorf("missing cluster name in config")
	}
	if ClusterConfig.CustomerGUID == "" {
		return fmt.Errorf("missing customer guid in config")
	}

	if ns := os.Getenv(NamespaceEnvironmentVariable); ns == "" {
		Namespace = ns // override default namespace
	}

	if port := os.Getenv(PortEnvironmentVariable); port != "" {
		RestAPIPort = port // override default port
	}

	return nil
}
