package config

import (
	"fmt"
	"os"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	v1 "github.com/kubescape/backend/pkg/servicediscovery/v1"
	"github.com/kubescape/backend/pkg/utils"
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
}

// IConfig is an interface for all config types used in the operator
type IConfig interface {
	Namespace() string
	AccountID() string
	AccessKey() string
	ClusterName() string
	EventReceiverURL() string
	GatewayWebsocketURL() string
	ConcurrencyWorkers() int
	Components() Components
	ContinuousScanEnabled() bool
	CleanUpRoutineInterval() time.Duration
	MatchingRulesFilename() string
	TriggerSecurityFramework() bool
	KubescapeURL() string
	KubevulnURL() string
}

// OperatorConfig implements IConfig
type OperatorConfig struct {
	serviceConfig        Config
	components           CapabilitiesConfig
	clusterConfig        utilsmetadata.ClusterConfig
	accountId            string
	accessKey            string
	eventReceiverRestURL string
}

func NewOperatorConfig(components CapabilitiesConfig, clusterConfig utilsmetadata.ClusterConfig, creds *utils.Credentials, eventReceiverRestURL string, serviceConfig Config) *OperatorConfig {
	return &OperatorConfig{
		components:           components,
		serviceConfig:        serviceConfig,
		clusterConfig:        clusterConfig,
		accountId:            creds.Account,
		accessKey:            creds.AccessKey,
		eventReceiverRestURL: eventReceiverRestURL,
	}
}

func (c *OperatorConfig) ContinuousScanEnabled() bool {
	return c.components.Capabilities.ContinuousScan == "enable"
}

func (c *OperatorConfig) KubevulnURL() string {
	return c.clusterConfig.KubevulnURL
}

func (c *OperatorConfig) KubescapeURL() string {
	return c.clusterConfig.KubescapeURL
}
func (c *OperatorConfig) TriggerSecurityFramework() bool {
	return c.serviceConfig.TriggerSecurityFramework
}

func (c *OperatorConfig) Namespace() string {
	return c.serviceConfig.Namespace
}

func (c *OperatorConfig) CleanUpRoutineInterval() time.Duration {
	return c.serviceConfig.CleanUpRoutineInterval
}
func (c *OperatorConfig) MatchingRulesFilename() string {
	return c.serviceConfig.MatchingRulesFilename
}

func (c *OperatorConfig) GatewayWebsocketURL() string {
	return c.clusterConfig.GatewayWebsocketURL
}
func (c *OperatorConfig) ConcurrencyWorkers() int {
	return c.serviceConfig.ConcurrencyWorkers
}

func (c *OperatorConfig) Components() Components {
	return c.components.Components
}

func (c *OperatorConfig) AccountID() string {
	return c.accountId
}

func (c *OperatorConfig) AccessKey() string {
	return c.accessKey
}

func (c *OperatorConfig) ClusterName() string {
	return c.clusterConfig.ClusterName
}

func (c *OperatorConfig) EventReceiverURL() string {
	return c.eventReceiverRestURL
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

func ValidateConfig(config IConfig) error {
	if config.AccountID() == "" && config.Components().ServiceDiscovery.Enabled {
		return fmt.Errorf("missing account id")
	}

	if config.ClusterName() == "" {
		return fmt.Errorf("missing cluster name in config")
	}
	return nil
}
