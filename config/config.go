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

type Capabilities struct {
	ConfigurationScan    string `json:"configurationScan"`
	ContinuousScan       string `json:"continuousScan"`
	NetworkGenerator     string `json:"networkGenerator"`
	NodeScan             string `json:"nodeScan"`
	Otel                 string `json:"otel"`
	Relevancy            string `json:"relevancy"`
	RuntimeObservability string `json:"runtimeObservability"`
	Seccomp              string `json:"seccomp"`
	VulnerabilityScan    string `json:"vulnerabilityScan"`
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
	ServiceDiscovery   Component `mapstructure:"serviceDiscovery"`
	Storage            Component `mapstructure:"storage"`
}

type Server struct {
	Account      string `json:"account"`
	DiscoveryURL string `json:"discoveryUrl"`
	OtelURL      string `json:"otelUrl"`
}

type Configurations struct {
	Persistence string `json:"persistence"`
	Server      Server `json:"server"`
}

type CapabilitiesConfig struct {
	Capabilities   Capabilities   `mapstructure:"capabilities"`
	Components     Components     `mapstructure:"components"`
	Configurations Configurations `mapstructure:"configurations"`
}

func LoadCapabilitiesConfig(path string) (CapabilitiesConfig, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("capabilities")
	viper.SetConfigType("json")

	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return CapabilitiesConfig{}, err
	}

	var c CapabilitiesConfig
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
	// EventDeduplicationInterval is the interval during which duplicate events will be silently dropped from processing via continuous scanning
	EventDeduplicationInterval time.Duration `mapstructure:"eventDeduplicationInterval"`
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
	viper.SetDefault("eventDeduplicationInterval", 2 * time.Minute)

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

func ValidateConfig(clusterConfig utilsmetadata.ClusterConfig, components CapabilitiesConfig) error {
	if clusterConfig.AccountID == "" && components.Components.ServiceDiscovery.Enabled {
		return fmt.Errorf("missing customer guid in config")
	}
	if clusterConfig.ClusterName == "" {
		return fmt.Errorf("missing cluster name in config")
	}
	return nil
}
