package mainhandler

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/sbomexport"
)

// newSBOMExporter returns the SBOM exporter when the sbomExport capability is
// on, and nil when it is off or cannot run. It needs nodeSbomGeneration: it
// exports the SBOMs node-agent makes, and SBOMWatch, which feeds it, only runs
// with it.
func (mainHandler *MainHandler) newSBOMExporter() *sbomexport.Exporter {
	if !mainHandler.config.SBOMExportEnabled() {
		return nil
	}
	if !mainHandler.config.NodeSbomGenerationEnabled() {
		logger.L().Warning("SBOM export is off: the sbomExport capability needs nodeSbomGeneration")
		return nil
	}
	exporter, err := sbomexport.New(sbomExportOptions(mainHandler.config), mainHandler.k8sAPI.KubernetesClient, mainHandler.ksStorageClient)
	if err != nil {
		logger.L().Error("SBOM export is off: invalid configuration", helpers.Error(err))
		return nil
	}
	return exporter
}

// sbomExportOptions reads the exporter's options from the operator
// configuration. The root project defaults to the cluster name.
func sbomExportOptions(cfg config.IConfig) sbomexport.Options {
	export := cfg.SBOMExportConfig()
	rootProject := export.DependencyTrack.RootProject
	if rootProject == "" {
		rootProject = cfg.ClusterName()
	}
	return sbomexport.Options{
		URL:            export.DependencyTrack.URL,
		APIKeyFile:     export.DependencyTrack.APIKeyFile,
		RootProject:    rootProject,
		ResyncInterval: export.ResyncInterval,
		SkipNamespace:  cfg.SkipNamespace,
	}
}
