package mainhandler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/probes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/config"
)

var (
	readinessPollInterval = time.Second
	readinessProbeTimeout = 5 * time.Second
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

	ticker := time.NewTicker(readinessPollInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), readinessProbeTimeout)
		resp, err := httputils.HttpGetWithContext(ctx, VulnScanHttpClient, fullURL.String(), nil)
		if err != nil {
			cancel()
			continue
		}
		statusCode := resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		cancel()
		if statusCode >= 200 && statusCode <= 203 {
			logger.L().Info("image vulnerability scanning is available")
			break
		}
	}
}

func waitForKubescapeReady(config config.IConfig) {
	fullURL := getKubescapeV1ScanURL(config)
	fullURL.Path = "readyz"

	ticker := time.NewTicker(readinessPollInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), readinessProbeTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, fullURL.String(), nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := KubescapeHttpClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		statusCode := resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		cancel()
		if statusCode >= 200 && statusCode <= 203 {
			logger.L().Info("kubescape service is ready")
			break
		}
	}
}
