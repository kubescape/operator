package exporters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/admission/rules"
	"github.com/kubescape/storage/pkg/apiauth"
)

type HTTPExporterConfig struct {
	// URL is the URL to send the HTTP request to
	URL string `json:"url"`
	// Headers is a map of headers to send in the HTTP request
	Headers map[string]string `json:"headers"`
	// Timeout is the timeout for the HTTP request
	TimeoutSeconds int `json:"timeoutSeconds"`
	// Method is the HTTP method to use for the HTTP request
	Method             string `json:"method"`
	MaxAlertsPerMinute int    `json:"maxAlertsPerMinute"`
	// MaxRetries is the maximum number of retry attempts for transient errors (default 3, 0 disables retries)
	MaxRetries *int `json:"maxRetries"`
	// InitialRetryInterval is the initial backoff interval for retries (default 500ms)
	InitialRetryInterval time.Duration `json:"initialRetryInterval"`
	// MaxRetryInterval is the maximum backoff interval cap for retries (default 5s)
	MaxRetryInterval time.Duration `json:"maxRetryInterval"`
	// TokenFile is the path to a projected service-account token; when set, it is sent as a bearer token to the URL's host
	TokenFile string `json:"tokenFile"`
}

// we will have a CRD-like json struct to send in the HTTP request
type HTTPExporter struct {
	config      HTTPExporterConfig
	Host        string `json:"host"`
	ClusterName string `json:"clusterName"`
	ClusterUID  string `json:"clusterUID"`
	httpClient  *http.Client
	// alertCount is the number of alerts sent in the last minute, used to limit the number of alerts sent, so we don't overload the system or reach the rate limit
	alertCount         int
	alertCountLock     sync.Mutex
	alertCountStart    time.Time
	alertLimitNotified bool
	cloudMetadata      *apitypes.CloudMetadata
	// sleepFn is used for backoff delays in exportMessage, customizable in tests
	sleepFn func(d time.Duration)
}

var _ Exporter = (*HTTPExporter)(nil)

const (
	defaultMaxRetries           = 3
	defaultInitialRetryInterval = 500 * time.Millisecond
	defaultMaxRetryInterval     = 5 * time.Second
)

type HTTPAlertsList struct {
	Kind       string             `json:"kind"`
	ApiVersion string             `json:"apiVersion"`
	Spec       HTTPAlertsListSpec `json:"spec"`
}

type HTTPAlertsListSpec struct {
	Alerts        []apitypes.RuntimeAlert `json:"alerts"`
	ProcessTree   apitypes.ProcessTree    `json:"processTree"`
	CloudMetadata apitypes.CloudMetadata  `json:"cloudMetadata"`
}

func (config *HTTPExporterConfig) Validate() error {
	if config.Method == "" {
		config.Method = "POST"
	} else if config.Method != "POST" && config.Method != "PUT" {
		return fmt.Errorf("method must be POST or PUT")
	}
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 5
	}
	if config.MaxAlertsPerMinute == 0 {
		config.MaxAlertsPerMinute = 100
	}
	if config.MaxRetries == nil {
		defaultRetries := defaultMaxRetries
		config.MaxRetries = &defaultRetries
	} else if *config.MaxRetries < 0 {
		zero := 0
		config.MaxRetries = &zero
	}
	if config.InitialRetryInterval <= 0 {
		config.InitialRetryInterval = defaultInitialRetryInterval
	}
	if config.MaxRetryInterval <= 0 {
		config.MaxRetryInterval = defaultMaxRetryInterval
	}
	if config.MaxRetryInterval < config.InitialRetryInterval {
		config.MaxRetryInterval = config.InitialRetryInterval
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	hasContentType := false
	for key, val := range config.Headers {
		if strings.EqualFold(key, "Content-Type") {
			hasContentType = true
			if val == "" {
				config.Headers[key] = "application/json"
			}
		}
	}
	if !hasContentType {
		config.Headers["Content-Type"] = "application/json"
	}
	if config.URL == "" {
		return fmt.Errorf("URL is required")
	}
	return nil
}

// InitHTTPExporter initializes an HTTPExporter with the given URL, headers, timeout, and method
func InitHTTPExporter(config HTTPExporterConfig, clusterName string, cloudMetadata *apitypes.CloudMetadata, clusterUID string) (*HTTPExporter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}
	if config.TokenFile != "" {
		u, err := url.Parse(config.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %w", err)
		}
		httpClient.Transport = apiauth.NewTransport(httpClient.Transport, apiauth.NewFileTokenSource(config.TokenFile), u.Host)
	}

	return &HTTPExporter{
		ClusterName:   clusterName,
		ClusterUID:    clusterUID,
		config:        config,
		httpClient:    httpClient,
		cloudMetadata: cloudMetadata,
		sleepFn:       time.Sleep,
	}, nil
}

func (exporter *HTTPExporter) sendAlertLimitReached(alertCount int, since time.Time) {
	httpAlert := apitypes.RuntimeAlert{
		Message:   "Alert limit reached",
		HostName:  exporter.Host,
		AlertType: apitypes.AlertTypeRule, // TODO: change this to a new alert type. @bez
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      "AlertLimitReached",
			Severity:       1000, // Replace with ruleengine.RulePrioritySystemIssue once node agent is bumping the types pkg @amitschendel.
			FixSuggestions: "Check logs for more information",
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ClusterName: exporter.ClusterName,
			ClusterUID:  exporter.ClusterUID,
			NodeName:    "Operator",
		},
	}

	logger.L().Error("Alert limit reached", helpers.Int("alerts", alertCount), helpers.String("since", since.Format(time.RFC3339)))
	exporter.sendInAlertList(httpAlert, apitypes.ProcessTree{})
}

func (exporter *HTTPExporter) SendAdmissionAlert(ruleFailure rules.RuleFailure) {
	// Over the limit every alert is dropped until the window resets. Only the
	// first one is replaced by the AlertLimitReached notice.
	if limit := exporter.checkAlertLimit(); limit.overLimit {
		if limit.notify {
			exporter.sendAlertLimitReached(limit.alertCount, limit.since)
		}
		return
	}
	// populate the RuntimeAlert struct with the data from the failedRule
	k8sDetails := ruleFailure.GetRuntimeAlertK8sDetails()
	k8sDetails.ClusterName = exporter.ClusterName
	k8sDetails.ClusterUID = exporter.ClusterUID

	httpAlert := apitypes.RuntimeAlert{
		Message:  ruleFailure.GetRuleAlert().RuleDescription,
		HostName: exporter.Host,
		// Admission alerts originate from the operator inside the cluster.
		// Set the platform explicitly: the backend otherwise infers it from
		// PodName and would classify a pod-less alert as a Linux host alert.
		AlertSourcePlatform:    apitypes.AlertSourcePlatformK8sAgent,
		AlertType:              apitypes.AlertTypeAdmission,
		BaseRuntimeAlert:       ruleFailure.GetBaseRuntimeAlert(),
		AdmissionAlert:         ruleFailure.GetAdmissionsAlert(),
		RuntimeAlertK8sDetails: k8sDetails,
		RuleAlert:              ruleFailure.GetRuleAlert(),
		RuleID:                 ruleFailure.GetRuleId(),
	}
	exporter.sendInAlertList(httpAlert, apitypes.ProcessTree{})
}

func (exporter *HTTPExporter) sendInAlertList(httpAlert apitypes.RuntimeAlert, processTree apitypes.ProcessTree) {
	// create the HTTPAlertsListSpec struct
	// TODO: accumulate alerts and send them in a batch
	httpAlertsListSpec := HTTPAlertsListSpec{
		Alerts:        []apitypes.RuntimeAlert{httpAlert},
		ProcessTree:   processTree,
		CloudMetadata: exporter.getCloudMetadata(),
	}
	// create the HTTPAlertsList struct
	httpAlertsList := HTTPAlertsList{
		Kind:       "RuntimeAlerts",
		ApiVersion: "kubescape.io/v1",
		Spec:       httpAlertsListSpec,
	}

	// create the JSON representation of the HTTPAlertsList struct
	bodyBytes, err := json.Marshal(httpAlertsList)
	if err != nil {
		logger.L().Error("failed to marshal HTTPAlertsList", helpers.Error(err))
		return
	}

	exporter.exportMessage("runtimealerts", bodyBytes)
}

// alertLimitCheck is the result of counting one alert against
// MaxAlertsPerMinute. alertCount and since describe the current window.
type alertLimitCheck struct {
	overLimit  bool
	notify     bool
	alertCount int
	since      time.Time
}

// checkAlertLimit counts one alert in the current one-minute window. notify is
// set only for the first alert over the limit in a window. It is decided under
// alertCountLock, so concurrent callers send at most one AlertLimitReached
// notice per window.
func (exporter *HTTPExporter) checkAlertLimit() alertLimitCheck {
	exporter.alertCountLock.Lock()
	defer exporter.alertCountLock.Unlock()

	if exporter.alertCountStart.IsZero() {
		exporter.alertCountStart = time.Now()
	}

	if time.Since(exporter.alertCountStart) > time.Minute {
		exporter.alertCountStart = time.Now()
		exporter.alertCount = 0
		exporter.alertLimitNotified = false
	}

	exporter.alertCount++
	check := alertLimitCheck{
		overLimit:  exporter.alertCount > exporter.config.MaxAlertsPerMinute,
		alertCount: exporter.alertCount,
		since:      exporter.alertCountStart,
	}
	if check.overLimit && !exporter.alertLimitNotified {
		exporter.alertLimitNotified = true
		check.notify = true
	}
	return check
}

func (exporter *HTTPExporter) SendRegistryStatus(guid string, status apitypes.RegistryScanStatus, statusMessage string, time time.Time) {
	updateRegistryStatusCRD := apitypes.GenericCRD[apitypes.ContainerImageRegistryScanStatusUpdate]{
		Kind:       apitypes.RegistryScanStatusesKind,
		ApiVersion: "kubescape.io/v1",
		Metadata:   apitypes.Metadata{},
		Spec: apitypes.ContainerImageRegistryScanStatusUpdate{
			GUID:              guid,
			ScanStatus:        status,
			ScanStatusMessage: statusMessage,
			ScanTime:          time,
		},
	}

	bodyBytes, err := json.Marshal(updateRegistryStatusCRD)
	if err != nil {
		logger.L().Error("failed to marshal updateRegistryStatusCRD", helpers.Error(err))
		return
	}

	exporter.exportMessage(apitypes.RegistryScanStatusesKindPath, bodyBytes)
}

// isRetryableStatus returns true if an HTTP status code indicates a transient condition
// that can be retried (e.g., rate limits and server errors).
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusInternalServerError ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

const maxRetryAfterSeconds = int64(math.MaxInt64) / int64(time.Second)

// parseRetryAfter attempts to parse a Retry-After header as either seconds or an HTTP-date.
func parseRetryAfter(header string) (time.Duration, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(header, 10, 64); err == nil && seconds >= 0 {
		if seconds > maxRetryAfterSeconds {
			return time.Duration(math.MaxInt64), true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if targetTime, err := http.ParseTime(header); err == nil {
		delay := time.Until(targetTime)
		if delay < 0 {
			delay = 0
		}
		return delay, true
	}
	return 0, false
}

// computeBackoff calculates the exponential backoff duration for attempt (0-indexed).
func (exporter *HTTPExporter) computeBackoff(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if retryAfter, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
			if retryAfter > exporter.config.MaxRetryInterval {
				return exporter.config.MaxRetryInterval
			}
			return retryAfter
		}
	}

	backoff := float64(exporter.config.InitialRetryInterval) * math.Pow(2, float64(attempt))
	if math.IsNaN(backoff) || backoff > float64(exporter.config.MaxRetryInterval) {
		return exporter.config.MaxRetryInterval
	}
	return time.Duration(backoff)
}

func (exporter *HTTPExporter) exportMessage(path string, bodyBytes []byte) {
	maxRetries := 0
	if exporter.config.MaxRetries != nil {
		maxRetries = *exporter.config.MaxRetries
	}
	targetURL := fmt.Sprintf("%s/v1/%s", exporter.config.URL, path)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		bodyReader := bytes.NewReader(bodyBytes)
		req, err := http.NewRequest(exporter.config.Method, targetURL, bodyReader)
		if err != nil {
			logger.L().Error("failed to create HTTP request", helpers.Error(err))
			return
		}
		for key, value := range exporter.config.Headers {
			req.Header.Set(key, value)
		}

		resp, err := exporter.httpClient.Do(req)
		if err != nil {
			if attempt < maxRetries {
				delay := exporter.computeBackoff(attempt, nil)
				logger.L().Warning("failed to send HTTP request, retrying",
					helpers.Error(err),
					helpers.Int("attempt", attempt+1),
					helpers.Int("maxRetries", maxRetries),
					helpers.String("backoff", delay.String()))
				if exporter.sleepFn != nil {
					exporter.sleepFn(delay)
				}
				continue
			}
			logger.L().Error("failed to send HTTP request, retries exhausted", helpers.Error(err), helpers.Int("attempts", attempt+1))
			return
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Success: discard the body and return
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				logger.L().Error("failed to clear response body", helpers.Error(err))
			}
			_ = resp.Body.Close()
			return
		}

		statusCode := resp.StatusCode
		retryable := isRetryableStatus(statusCode)
		var delay time.Duration
		if retryable {
			delay = exporter.computeBackoff(attempt, resp)
		}

		// Discard and close response body
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if retryable && attempt < maxRetries {
			logger.L().Warning("received transient non-2xx status code, retrying",
				helpers.Int("status", statusCode),
				helpers.Int("attempt", attempt+1),
				helpers.Int("maxRetries", maxRetries),
				helpers.String("backoff", delay.String()))
			if exporter.sleepFn != nil {
				exporter.sleepFn(delay)
			}
			continue
		}

		if retryable {
			logger.L().Error("received transient non-2xx status code, retries exhausted",
				helpers.Int("status", statusCode),
				helpers.Int("attempts", attempt+1))
		} else {
			logger.L().Error("received non-retryable non-2xx status code",
				helpers.Int("status", statusCode))
		}
		return
	}
}

func (exporter *HTTPExporter) getCloudMetadata() apitypes.CloudMetadata {
	if exporter.cloudMetadata == nil {
		return apitypes.CloudMetadata{}
	}

	metadata := *exporter.cloudMetadata
	return metadata
}
