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
	"github.com/kubescape/operator/admission/rulesupdate"
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

// NodeAgentAutoscalerResourcePercentages defines the resource percentages for autoscaling
type NodeAgentAutoscalerResourcePercentages struct {
	RequestCPU    int `json:"requestCPU" mapstructure:"requestCPU"`
	RequestMemory int `json:"requestMemory" mapstructure:"requestMemory"`
	LimitCPU      int `json:"limitCPU" mapstructure:"limitCPU"`
	LimitMemory   int `json:"limitMemory" mapstructure:"limitMemory"`
}

// NodeAgentAutoscalerResourceBounds defines min/max resource bounds
type NodeAgentAutoscalerResourceBounds struct {
	CPU    string `json:"cpu" mapstructure:"cpu"`
	Memory string `json:"memory" mapstructure:"memory"`
}

// NodeAgentAutoscalerConfig defines the configuration for node agent autoscaling
type NodeAgentAutoscalerConfig struct {
	Enabled             bool                                   `json:"enabled" mapstructure:"enabled"`
	NodeGroupLabel      string                                 `json:"nodeGroupLabel" mapstructure:"nodeGroupLabel"`
	ResourcePercentages NodeAgentAutoscalerResourcePercentages `json:"resourcePercentages" mapstructure:"resourcePercentages"`
	MinResources        NodeAgentAutoscalerResourceBounds      `json:"minResources" mapstructure:"minResources"`
	MaxResources        NodeAgentAutoscalerResourceBounds      `json:"maxResources" mapstructure:"maxResources"`
	ReconcileInterval   time.Duration                          `json:"reconcileInterval" mapstructure:"reconcileInterval"`
	TemplatePath        string                                 `json:"templatePath" mapstructure:"templatePath"`
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
	PodScanGuardTime              time.Duration                  `mapstructure:"podScanGuardTime"`
	RegistryScanningSkipTlsVerify bool                           `mapstructure:"registryScanningSkipTlsVerify"`
	RegistryScanningInsecure      bool                           `mapstructure:"registryScanningInsecure"`
	ExcludeJsonPaths              []string                       `mapstructure:"excludeJsonPaths"`
	RulesUpdateConfig             rulesupdate.RulesUpdaterConfig `mapstructure:"rulesUpdateConfig"`
	SkipProfilesWithoutInstances  bool                           `mapstructure:"skipProfilesWithoutInstances"`
	NodeAgentAutoscaler           NodeAgentAutoscalerConfig      `mapstructure:"nodeAgentAutoscaler"`
}

// IConfig is an interface for all config types used in the operator
type IConfig interface {
	Namespace() string
	AccountID() string
	AccessKey() string
	ClusterName() string
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
	RegistryScanningSkipTlsVerify() bool
	RegistryScanningInsecure() bool
	ExcludeJsonPaths() []string
	SkipProfilesWithoutInstances() bool
	RulesUpdateEnabled() bool
	NodeAgentAutoscalerConfig() NodeAgentAutoscalerConfig
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

func NewOperatorConfig(components CapabilitiesConfig, clusterConfig utilsmetadata.ClusterConfig, creds *utils.Credentials, serviceConfig Config) *OperatorConfig {
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

func (c *OperatorConfig) GuardTime() time.Duration {
	return c.serviceConfig.PodScanGuardTime
}

func (c *OperatorConfig) RegistryScanningSkipTlsVerify() bool {
	return c.serviceConfig.RegistryScanningSkipTlsVerify
}

func (c *OperatorConfig) RegistryScanningInsecure() bool {
	return c.serviceConfig.RegistryScanningInsecure
}

func (c *OperatorConfig) ExcludeJsonPaths() []string {
	return c.serviceConfig.ExcludeJsonPaths
}

func (c *OperatorConfig) SkipProfilesWithoutInstances() bool {
	return c.serviceConfig.SkipProfilesWithoutInstances
}

func (c *OperatorConfig) RulesUpdateEnabled() bool {
	return c.serviceConfig.RulesUpdateConfig.Enabled
}

func (c *OperatorConfig) NodeAgentAutoscalerConfig() NodeAgentAutoscalerConfig {
	return c.serviceConfig.NodeAgentAutoscaler
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
	viper.SetDefault("registryScanningSkipTlsVerify", false)
	viper.SetDefault("registryScanningInsecure", false)
	viper.SetDefault("rulesUpdateConfig.enabled", false)
	viper.SetDefault("rulesUpdateConfig.interval", 5*time.Minute)
	viper.SetDefault("rulesUpdateConfig.namespace", "default")

	// Node agent autoscaler defaults
	viper.SetDefault("nodeAgentAutoscaler.enabled", false)
	viper.SetDefault("nodeAgentAutoscaler.nodeGroupLabel", "node.kubernetes.io/instance-type")
	viper.SetDefault("nodeAgentAutoscaler.resourcePercentages.requestCPU", 2)
	viper.SetDefault("nodeAgentAutoscaler.resourcePercentages.requestMemory", 2)
	viper.SetDefault("nodeAgentAutoscaler.resourcePercentages.limitCPU", 5)
	viper.SetDefault("nodeAgentAutoscaler.resourcePercentages.limitMemory", 5)
	viper.SetDefault("nodeAgentAutoscaler.minResources.cpu", "100m")
	viper.SetDefault("nodeAgentAutoscaler.minResources.memory", "180Mi")
	viper.SetDefault("nodeAgentAutoscaler.maxResources.cpu", "2000m")
	viper.SetDefault("nodeAgentAutoscaler.maxResources.memory", "4Gi")
	viper.SetDefault("nodeAgentAutoscaler.reconcileInterval", 5*time.Minute)
	viper.SetDefault("nodeAgentAutoscaler.templatePath", "/etc/templates/daemonset-template.yaml")

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
