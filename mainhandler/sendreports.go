package mainhandler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const dailyReportTimeout = 30 * time.Second

func (mainHandler *MainHandler) sendDailyReport(ctx context.Context, buildNumber string) error {
	ctx, cancel := context.WithTimeout(ctx, dailyReportTimeout)
	defer cancel()

	// The backend constructor uses context.TODO for Kubernetes reads. Keep its
	// payload defaults, but collect cluster metadata with our bounded context.
	report := versioncheck.NewVersionCheckRequest(mainHandler.config.AccountID(), buildNumber, "", "", "daily-report", nil)
	if client := os.Getenv(versioncheck.CLIENT_ENV); client != "" {
		report.ClientBuild = client
	}
	if client := mainHandler.k8sAPI.KubernetesClient; client != nil {
		if svc, err := client.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{}); err == nil {
			report.ClusterID = string(svc.UID)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); err == nil {
			report.Nodes = len(nodes.Items)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	// The backend HTTP helper does not propagate context or set a timeout.
	// Daily reports do not compare Operator versions to Kubescape releases.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://version-check.ks-services.co", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: dailyReportTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.L().Ctx(ctx).Warning("failed to close daily report response", helpers.Error(err))
		}
	}()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("daily report returned HTTP %d", resp.StatusCode)
	}
	var response versioncheck.VersionCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	if response.Message != "" {
		logger.L().Info(response.Message)
	}
	return nil
}
