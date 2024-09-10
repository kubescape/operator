package mainhandler

import (
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/probes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/config"
)

func notWaitAtAll(_ config.IConfig) {
}

func isActionNeedToWait(action apis.Command) waitFunc {
	if f, ok := actionNeedToBeWaitOnStartUp[action.CommandName]; ok {
		return f
	}
	return notWaitAtAll
}

func waitForVulnScanReady(config config.IConfig) {
	fullURL := getVulnScanURL(config)
	// replace path
	fullURL.Path = fmt.Sprintf("v1/%s", probes.ReadinessPath)

	timer := time.NewTimer(time.Duration(1) * time.Minute)

	for {
		timer.Reset(time.Duration(1) * time.Second)
		<-timer.C
		resp, err := httputils.HttpGet(VulnScanHttpClient, fullURL.String(), nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 203 {
			logger.L().Info("image vulnerability scanning is available")
			break
		}

	}
}

func waitForKubescapeReady(config config.IConfig) {
	fullURL := getKubescapeV1ScanURL(config)
	fullURL.Path = "readyz"
	timer := time.NewTimer(time.Duration(1) * time.Minute)

	for {
		timer.Reset(time.Duration(1) * time.Second)
		<-timer.C
		resp, err := httputils.HttpHead(KubescapeHttpClient, fullURL.String(), nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 203 {
			logger.L().Info("kubescape service is ready")
			break
		}

	}
}
