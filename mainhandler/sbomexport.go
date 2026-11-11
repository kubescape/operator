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
// configuration.
func sbomExportOptions(cfg config.IConfig) sbomexport.Options {
	export := cfg.SBOMExportConfig()
	dt := export.DependencyTrack
	return sbomexport.Options{
		URL:        dt.URL,
		APIKeyFile: dt.APIKeyFile,
		Cluster:    cfg.ClusterName(),
		Layout: sbomexport.Layout{
			Root:    sbomexport.Collection{Name: dt.RootProject.Name, Version: dt.RootProject.Version, Create: dt.RootProject.Create},
			Parent:  sbomexport.Collection{Name: dt.Project.Parent.Name, Version: dt.Project.Parent.Version, Create: dt.Project.Parent.Create},
			Name:    dt.Project.Name,
			Version: dt.Project.Version,
		},
		MaxSBOMSize:    export.MaxSBOMSize,
		ResyncInterval: export.ResyncInterval,
		SkipNamespace:  cfg.SkipNamespace,
	}
}
