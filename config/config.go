package config

import (
	"fmt"
	"os"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/spf13/viper"
)

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
