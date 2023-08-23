package config

import (
	"fmt"
	"os"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	v1 "github.com/kubescape/backend/pkg/servicediscovery/v1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/spf13/viper"
)

type Component struct {
	Enabled bool `json:"enabled"`
}

type Components struct {
	Gateway            Component `mapstructure:"gateway"`
	HostScanner        Component `mapstructure:"hostScanner"`
	Kollector          Component `mapstructure:"kollector"`
	Kubescape          Component `mapstructure:"kubescape"`
	KubescapeScheduler Component `mapstructure:"kubescapeScheduler"`
	Kubevuln           Component `mapstructure:"kubevuln"`
	KubevulnScheduler  Component `mapstructure:"kubevulnScheduler"`
	NodeAgent          Component `mapstructure:"nodeAgent"`
	Operator           Component `mapstructure:"operator"`
	OtelCollector      Component `mapstructure:"otelCollector"`
	Persistence        Component `mapstructure:"persistence"`
	Storage            Component `mapstructure:"storage"`
}

func LoadComponents(path string) (Components, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("components")
	viper.SetConfigType("json")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Components{}, err
	}

	var c Components
	err = viper.Unmarshal(&c)
	return c, err
}

type Config struct {
	Namespace                string        `mapstructure:"namespace"`
	RestAPIPort              string        `mapstructure:"port"`
	CleanUpRoutineInterval   time.Duration `mapstructure:"cleanupDelay"`
	ConcurrencyWorkers       int           `mapstructure:"workerConcurrency"`
	TriggerSecurityFramework bool          `mapstructure:"triggerSecurityFramework"`
	MatchingRulesFilename    string        `mapstructure:"matchingRulesFilename"`
}

func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	viper.SetDefault("namespace", "kubescape")
	viper.SetDefault("port", "4002")
	viper.SetDefault("cleanupDelay", 10*time.Minute)
	viper.SetDefault("workerConcurrency", 3)
	viper.SetDefault("triggerSecurityFramework", false)
	viper.SetDefault("matchingRulesFilename", "/etc/config/matchingRules.json")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return Config{}, err
	}

	var c Config
	err = viper.Unmarshal(&c)
	return c, err
}

func LoadClusterConfig() (utilsmetadata.ClusterConfig, error) {
	pathAndFileName, present := os.LookupEnv("CONFIG")
	if !present {
		pathAndFileName = "/etc/config/clusterData.json"
	}

	clusterConfig, err := utilsmetadata.LoadConfig(pathAndFileName)
	if err != nil {
		return utilsmetadata.ClusterConfig{}, err
	}

	if clusterConfig.ClusterName == "" {
		return utilsmetadata.ClusterConfig{}, fmt.Errorf("missing cluster name in config")
	}
	if clusterConfig.AccountID == "" {
		return utilsmetadata.ClusterConfig{}, fmt.Errorf("missing customer guid in config")
	}

	return *clusterConfig, err
}

func GetServiceURLs(filePath string) (schema.IBackendServices, error) {
	pathAndFileName, present := os.LookupEnv("SERVICES")
	if !present {
		pathAndFileName = filePath
	}
	logger.L().Debug("discovery service URLs from file", helpers.String("path", pathAndFileName))

	return servicediscovery.GetServices(
		v1.NewServiceDiscoveryFileV1(pathAndFileName),
	)
}
