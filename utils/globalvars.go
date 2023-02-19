package utils

import (
	"context"
	"fmt"
	"os"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

var (
	Namespace              string        = "default" // default namespace
	RestAPIPort            string        = "4002"    // default port
	CleanUpRoutineInterval time.Duration = 10 * time.Minute
)

var ClusterConfig = &utilsmetadata.ClusterConfig{}

func LoadEnvironmentVariables(ctx context.Context) (err error) {
	pathToConfig := os.Getenv(ConfigEnvironmentVariable) // if empty, will load config from default path
	ClusterConfig, err = utilsmetadata.LoadConfig(pathToConfig)
	if err != nil {
		return err
	}

	if ClusterConfig.ClusterName == "" {
		return fmt.Errorf("missing cluster name in config")
	}
	if ClusterConfig.AccountID == "" {
		return fmt.Errorf("missing customer guid in config")
	}

	if ns := os.Getenv(NamespaceEnvironmentVariable); ns != "" {
		Namespace = ns // override default namespace
	}

	if port := os.Getenv(PortEnvironmentVariable); port != "" {
		RestAPIPort = port // override default port
	}

	if cleanUpDelay := os.Getenv(CleanUpDelayEnvironmentVariable); cleanUpDelay != "" {
		dur, err := time.ParseDuration(cleanUpDelay)
		if err != nil {
			logger.L().Ctx(ctx).Error("could not set cleanUpRoutineInterval from environment variable", helpers.Error(err))
		} else {
			CleanUpRoutineInterval = dur
		}
	}

	return nil
}
