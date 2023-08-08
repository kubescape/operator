package utils

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

var (
	Namespace                string        = "default" // default namespace
	RestAPIPort              string        = "4002"    // default port
	CleanUpRoutineInterval   time.Duration = 10 * time.Minute
	ConcurrencyWorkers       int           = 3
	TriggerSecurityFramework bool          = false
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

	if securityFramework := os.Getenv(TriggerSecurityFrameworkEnvironmentVariable); securityFramework != "" {
		TriggerSecurityFramework, err = strconv.ParseBool(securityFramework)
		if err != nil {
			logger.L().Ctx(ctx).Error("could not set TriggerSecurityFramework from environment variable", helpers.Error(err))
			TriggerSecurityFramework = false
		}
	}

	if cleanUpDelay := os.Getenv(CleanUpDelayEnvironmentVariable); cleanUpDelay != "" {
		dur, err := time.ParseDuration(cleanUpDelay)
		if err != nil {
			logger.L().Ctx(ctx).Error("could not set cleanUpRoutineInterval from environment variable", helpers.Error(err))
		} else {
			CleanUpRoutineInterval = dur
		}
	}
	ConcurrencyWorkers, _ = parseIntEnvVar(ConcurrencyEnvironmentVariable, ConcurrencyWorkers)

	return nil
}

func parseIntEnvVar(varName string, defaultValue int) (int, error) {
	varValue, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue, nil
	}

	intValue, err := strconv.Atoi(varValue)
	if err != nil {
		return defaultValue, fmt.Errorf("failed to parse %s env var as int: %w", varName, err)
	}

	return intValue, nil
}
