package config

import (
	"fmt"
	"os"
	"slices"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/servicediscovery"
	"github.com/kubescape/backend/pkg/servicediscovery/schema"
	v2 "github.com/kubescape/backend/pkg/servicediscovery/v2"
	"github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	exporters "github.com/kubescape/operator/admission/exporter"
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
	NodeSbomGeneration   string `json:"nodeSbomGeneration"`
	Seccomp              string `json:"seccomp"`
	VulnerabilityScan    string `json:"vulnerabilityScan"`
	AdmissionController  string `json:"admissionController"`
}

type Components struct {
	HostScanner        Component `mapstructure:"hostScanner"`
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

type ServiceScanConfig struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
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
	Capabilities      Capabilities      `mapstructure:"capabilities"`
	Components        Components        `mapstructure:"components"`
	Configurations    Configurations    `mapstructure:"configurations"`
	ServiceScanConfig ServiceScanConfig `mapstructure:"serviceScanConfig"`
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
	EventDeduplicationInterval time.Duration                 `mapstructure:"eventDeduplicationInterval"`
	HTTPExporterConfig         *exporters.HTTPExporterConfig `mapstructure:"httpExporterConfig"`
	ExcludeNamespaces          []string                      `mapstructure:"excludeNamespaces"`
	IncludeNamespaces          []string                      `mapstructure:"includeNamespaces"`
	// PodScanGuardTime specifies the minimum age a pod without a parent must have before it is scanned
	PodScanGuardTime time.Duration `mapstructure:"podScanGuardTime"`
}

// IConfig is an interface for all config types used in the operator
type IConfig interface {
	Namespace() string
	AccountID() string
	AccessKey() string
	ClusterName() string
	EventReceiverURL() string
	ConcurrencyWorkers() int
	Components() Components
	AdmissionControllerEnabled() bool
	ContinuousScanEnabled() bool
	NodeSbomGenerationEnabled() bool
	CleanUpRoutineInterval() time.Duration
	MatchingRulesFilename() string
	TriggerSecurityFramework() bool
	KubescapeURL() string
	KubevulnURL() string
	SkipNamespace(ns string) bool
	GuardTime() time.Duration
}

// OperatorConfig implements IConfig
type OperatorConfig struct {
	serviceConfig Config
	components    CapabilitiesConfig
	clusterConfig utilsmetadata.ClusterConfig
	accountId     string
	accessKey     string
}

var _ IConfig = (*OperatorConfig)(nil)

func NewOperatorConfig(components CapabilitiesConfig, clusterConfig utilsmetadata.ClusterConfig, creds *utils.Credentials, eventReceiverRestURL string, serviceConfig Config) *OperatorConfig {
	return &OperatorConfig{
		components:    components,
		serviceConfig: serviceConfig,
		clusterConfig: clusterConfig,
		accountId:     creds.Account,
		accessKey:     creds.AccessKey,
	}
}

func (c *OperatorConfig) ContinuousScanEnabled() bool {
	return c.clusterConfig.ContinuousPostureScan
}

func (c *OperatorConfig) AdmissionControllerEnabled() bool {
	return c.components.Capabilities.AdmissionController == "enable"
}

func (c *OperatorConfig) NodeSbomGenerationEnabled() bool {
	return c.components.Capabilities.NodeSbomGeneration == "enable"
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

func (c *OperatorConfig) HttpExporterConfig() *exporters.HTTPExporterConfig {
	return c.serviceConfig.HTTPExporterConfig
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

func (c *OperatorConfig) SkipNamespace(ns string) bool {
	if includeNamespaces := c.serviceConfig.IncludeNamespaces; len(includeNamespaces) > 0 {
		if !slices.Contains(includeNamespaces, ns) {
			// skip ns not in IncludeNamespaces
			return true
		}
	} else if excludeNamespaces := c.serviceConfig.ExcludeNamespaces; len(excludeNamespaces) > 0 {
		if slices.Contains(excludeNamespaces, ns) {
			// skip ns in ExcludeNamespaces
			return true
		}
	}
	return false
}

func (c *OperatorConfig) EventReceiverURL() string {
	return ""
}

func (c *OperatorConfig) GuardTime() time.Duration {
	return c.serviceConfig.PodScanGuardTime
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
	viper.SetDefault("eventDeduplicationInterval", 2*time.Minute)
	viper.SetDefault("podScanGuardTime", time.Hour)

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
		v2.NewServiceDiscoveryFileV2(pathAndFileName),
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
