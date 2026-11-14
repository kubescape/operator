package mainhandler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestAcceptedCRDScanRemainsPendingUntilScannerFinishes(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	var posted bool
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/scan", r.URL.Path)
		posted = true
		_, _ = w.Write([]byte(`{"id":"` + scanID + `","type":"busy"}`))
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })

	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{Components: config.Components{Kubescape: config.Component{Enabled: true}}},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
		nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)

	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	var patches []v1alpha1.OperatorCommandStatus
	var patchAttempts int
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		patchAttempts++
		if patchAttempts == 1 {
			return true, nil, errors.New("temporary Kubernetes status failure")
		}
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patches = append(patches, body.Status)
		return true, &unstructured.Unstructured{}, nil
	})
	command := &apis.Command{CommandName: apis.TypeRunKubescape, Args: map[string]interface{}{
		utils.KubescapeScanV1: map[string]interface{}{},
	}}
	session := utils.SessionObj{Command: command, ParentCommandDetails: &utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
		StartedAt: time.Now(),
		Client:    &k8sinterface.KubernetesApi{DynamicClient: dynamic},
	}}
	responseQueue := make(chan *CommandResponseData, 1)
	timerQueue := make(chan *timerData, 1)
	h := &MainHandler{config: cfg, k8sAPI: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
		commandResponseChannel: &commandResponseChannelData{commandResponseChannel: &responseQueue, limitedGoRoutinesCommandResponseChannel: &timerQueue}}
	job := utils.Job{}
	job.SetContext(context.Background())
	job.SetObj(session)
	h.handleRequest(job)
	require.True(t, posted)
	require.Equal(t, 2, patchAttempts, "accepted scan ID must be retried after a transient status write failure")
	require.Len(t, patches, 1)
	require.True(t, patches[0].Started)
	require.False(t, patches[0].Completed, "accepting an asynchronous scan must not complete its OperatorCommand")
	require.Equal(t, []byte(scanID), patches[0].Payload)
	select {
	case timer := <-timerQueue:
		timer.timer.Stop()
	default:
		t.Fatal("scan completion poll was not queued")
	}
}

func TestInvalidScannerDispatchDoesNotLeaveACommandPending(t *testing.T) {
	for _, tc := range []struct {
		name, response string
	}{
		{"scanner rejected scan", `{"id":"99a48a8c-0795-42f3-b009-75f7eab1df75","type":"error","response":"deliberate rejection"}`},
		{"scanner omitted scan ID", `{"type":"busy"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/v1/scan", r.URL.Path)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer scanner.Close()
			previousClient := KubescapeHttpClient
			KubescapeHttpClient = scanner.Client()
			t.Cleanup(func() { KubescapeHttpClient = previousClient })
			cfg, err := config.NewOperatorConfig(
				config.CapabilitiesConfig{Components: config.Components{Kubescape: config.Component{Enabled: true}}},
				utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
				nil, config.Config{Namespace: "kubescape"})
			require.NoError(t, err)
			dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
			var patches []v1alpha1.OperatorCommandStatus
			dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
				var body struct {
					Status v1alpha1.OperatorCommandStatus `json:"status"`
				}
				if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
					return true, nil, err
				}
				patches = append(patches, body.Status)
				return true, &unstructured.Unstructured{}, nil
			})
			command := &apis.Command{CommandName: apis.TypeRunKubescape, Args: map[string]interface{}{
				utils.KubescapeScanV1: map[string]interface{}{},
			}}
			session := utils.SessionObj{Command: command, ParentCommandDetails: &utils.OperatorCommandDetails{
				Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
				StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
			}}
			responseQueue := make(chan *CommandResponseData, 1)
			timerQueue := make(chan *timerData, 1)
			h := &MainHandler{config: cfg, k8sAPI: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
				commandResponseChannel: &commandResponseChannelData{commandResponseChannel: &responseQueue, limitedGoRoutinesCommandResponseChannel: &timerQueue}}
			job := utils.Job{}
			job.SetContext(context.Background())
			job.SetObj(session)
			h.handleRequest(job)
			require.Len(t, patches, 1)
			require.True(t, patches[0].Completed)
			require.NotNil(t, patches[0].Error)
			require.Empty(t, timerQueue, "an invalid dispatch must not schedule a terminal poll")
		})
	}
}

func TestFailedScannerOutcomeCompletesOperatorCommandWithError(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/status", r.URL.Path)
		require.Equal(t, scanID, r.URL.Query().Get("ID"))
		_, _ = w.Write([]byte(`{"id":"` + scanID + `","type":"notBusy","outcome":"failed","error":"deliberate scan failure"}`))
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })

	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
		nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)

	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	var patched v1alpha1.OperatorCommandStatus
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patched = body.Status
		return true, &unstructured.Unstructured{}, nil
	})
	session := &utils.SessionObj{ParentCommandDetails: &utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
		StartedAt: time.Now(),
		Client:    &k8sinterface.KubernetesApi{DynamicClient: dynamic},
	}}
	retry, delay := HandleKubescapeResponse(context.Background(), cfg, &kubescapeResponseData{scanID: scanID, sessionObj: session})
	require.False(t, retry)
	require.Nil(t, delay)
	require.True(t, patched.Completed)
	require.NotNil(t, patched.Error)
	require.Contains(t, patched.Error.Message, "deliberate scan failure")
	require.Equal(t, []byte(scanID), patched.Payload)
}

func TestPendingScanRedeliveryPollsSameIDWithoutStartingAnotherScan(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	var posts, statusGets int
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/scan":
			posts++
			w.WriteHeader(http.StatusInternalServerError)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			statusGets++
			require.Equal(t, scanID, r.URL.Query().Get("ID"))
			_, _ = w.Write([]byte(`{"id":"` + scanID + `","type":"notBusy","outcome":"succeeded"}`))
		default:
			t.Errorf("unexpected scanner request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{Components: config.Components{Kubescape: config.Component{Enabled: true}}},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
		nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	var patches []v1alpha1.OperatorCommandStatus
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patches = append(patches, body.Status)
		return true, &unstructured.Unstructured{}, nil
	})
	command := &apis.Command{CommandName: apis.TypeRunKubescape, Args: map[string]interface{}{
		utils.KubescapeScanV1: map[string]interface{}{},
	}}
	crd := &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"},
		Status: v1alpha1.OperatorCommandStatus{Started: true, Completed: false, Payload: []byte(scanID)}}
	session := utils.SessionObj{Command: command, ParentCommandDetails: &utils.OperatorCommandDetails{
		Command: crd, StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
	}}
	responseQueue := make(chan *CommandResponseData, 1)
	timerQueue := make(chan *timerData, 1)
	h := &MainHandler{config: cfg, k8sAPI: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
		commandResponseChannel: &commandResponseChannelData{commandResponseChannel: &responseQueue, limitedGoRoutinesCommandResponseChannel: &timerQueue}}
	job := utils.Job{}
	job.SetContext(context.Background())
	job.SetObj(session)
	h.handleRequest(job)
	require.Zero(t, posts)
	require.Equal(t, 1, statusGets)
	require.Len(t, patches, 1)
	require.True(t, patches[0].Completed)
	require.Nil(t, patches[0].Error)
	require.Equal(t, []byte(scanID), patches[0].Payload)
}

func TestScannerStatusOutcomesDoNotInventSuccess(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	for _, tc := range []struct {
		name, response, wantError string
		wantRetry                 bool
	}{
		{"success", `{"id":"` + scanID + `","type":"notBusy","outcome":"succeeded"}`, "", false},
		{"failure without detail", `{"id":"` + scanID + `","type":"notBusy","outcome":"failed"}`, "scan failed", false},
		{"cancelled without detail", `{"id":"` + scanID + `","type":"notBusy","outcome":"cancelled"}`, "scan cancelled", false},
		{"unknown after scanner restart", `{"id":"` + scanID + `","type":"notBusy","outcome":"unknown"}`, "outcome unavailable", false},
		{"old scanner without outcome", `{"type":"notBusy"}`, "outcome unavailable", false},
		{"wrong scan ID", `{"id":"other-id","type":"notBusy","outcome":"succeeded"}`, "outcome unavailable", false},
		{"wrong busy scan ID", `{"id":"other-id","type":"busy"}`, "outcome unavailable", false},
		{"still running", `{"id":"` + scanID + `","type":"busy"}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/v1/status", r.URL.Path)
				require.Equal(t, scanID, r.URL.Query().Get("ID"))
				_, _ = w.Write([]byte(tc.response))
			}))
			defer scanner.Close()
			previousClient := KubescapeHttpClient
			KubescapeHttpClient = scanner.Client()
			t.Cleanup(func() { KubescapeHttpClient = previousClient })
			cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{},
				utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
				nil, config.Config{Namespace: "kubescape"})
			require.NoError(t, err)
			dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
			var patches []v1alpha1.OperatorCommandStatus
			dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
				var body struct {
					Status v1alpha1.OperatorCommandStatus `json:"status"`
				}
				if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
					return true, nil, err
				}
				patches = append(patches, body.Status)
				return true, &unstructured.Unstructured{}, nil
			})
			session := &utils.SessionObj{ParentCommandDetails: &utils.OperatorCommandDetails{
				Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
				StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
			}}
			retry, delay := HandleKubescapeResponse(context.Background(), cfg, &kubescapeResponseData{scanID: scanID, sessionObj: session})
			require.Equal(t, tc.wantRetry, retry)
			if tc.wantRetry {
				require.NotNil(t, delay)
				require.Empty(t, patches)
				return
			}
			require.Nil(t, delay)
			require.Len(t, patches, 1)
			require.True(t, patches[0].Completed)
			require.Equal(t, []byte(scanID), patches[0].Payload)
			if tc.wantError == "" {
				require.Nil(t, patches[0].Error)
			} else {
				require.NotNil(t, patches[0].Error)
				require.Contains(t, patches[0].Error.Message, tc.wantError)
			}
		})
	}
}

func TestTransientScannerStatusFailureDoesNotCompleteRunningCommand(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	var gets int
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets++
		if gets == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + scanID + `","type":"notBusy","outcome":"succeeded"}`))
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
		nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	var patches []v1alpha1.OperatorCommandStatus
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patches = append(patches, body.Status)
		return true, &unstructured.Unstructured{}, nil
	})
	session := &utils.SessionObj{ParentCommandDetails: &utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
		StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
	}}
	data := &kubescapeResponseData{scanID: scanID, sessionObj: session}
	retry, delay := HandleKubescapeResponse(context.Background(), cfg, data)
	require.True(t, retry)
	require.NotNil(t, delay)
	require.Empty(t, patches, "a temporary scanner outage must not end an accepted scan")
	retry, delay = HandleKubescapeResponse(context.Background(), cfg, data)
	require.False(t, retry)
	require.Nil(t, delay)
	require.Equal(t, 2, gets)
	require.Len(t, patches, 1)
	require.True(t, patches[0].Completed)
	require.Nil(t, patches[0].Error)
}

func TestRepeatedScannerStatusFailureCompletesWithError(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	var gets int
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gets++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
		nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	var patches []v1alpha1.OperatorCommandStatus
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patches = append(patches, body.Status)
		return true, &unstructured.Unstructured{}, nil
	})
	session := &utils.SessionObj{ParentCommandDetails: &utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
		StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
	}}
	data := &kubescapeResponseData{scanID: scanID, sessionObj: session}
	for i := 1; i <= maxKubescapeStatusFailures; i++ {
		retry, delay := HandleKubescapeResponse(context.Background(), cfg, data)
		require.Equal(t, i < maxKubescapeStatusFailures, retry)
		if retry {
			require.NotNil(t, delay)
			require.Empty(t, patches)
		} else {
			require.Nil(t, delay)
		}
	}
	require.Equal(t, maxKubescapeStatusFailures, gets)
	require.Len(t, patches, 1)
	require.True(t, patches[0].Completed)
	require.NotNil(t, patches[0].Error)
	require.Contains(t, patches[0].Error.Message, "status unavailable")
	require.Equal(t, []byte(scanID), patches[0].Payload)
}

func TestPendingScanIDWriteIsRetriedDuringStatusPoll(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"` + scanID + `","type":"busy"}`))
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
		nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	var patches []v1alpha1.OperatorCommandStatus
	var attempts int
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		attempts++
		if attempts == 1 {
			return true, nil, errors.New("temporary Kubernetes status failure")
		}
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patches = append(patches, body.Status)
		return true, &unstructured.Unstructured{}, nil
	})
	session := &utils.SessionObj{ParentCommandDetails: &utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
		StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
	}}
	data := &kubescapeResponseData{scanID: scanID, sessionObj: session, pendingWriteNeeded: true}
	retry, delay := HandleKubescapeResponse(context.Background(), cfg, data)
	require.True(t, retry)
	require.NotNil(t, delay)
	require.True(t, data.pendingWriteNeeded)
	require.Empty(t, patches)
	retry, delay = HandleKubescapeResponse(context.Background(), cfg, data)
	require.True(t, retry)
	require.NotNil(t, delay)
	require.False(t, data.pendingWriteNeeded)
	require.Equal(t, 2, attempts)
	require.Len(t, patches, 1)
	require.False(t, patches[0].Completed)
	require.Equal(t, []byte(scanID), patches[0].Payload)
}

func TestTerminalStatusPatchFailureRetriesWithoutRequeryingScanner(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	for _, tc := range []struct {
		name, response string
		wantError      bool
	}{
		{"success", `{"id":"` + scanID + `","type":"notBusy","outcome":"succeeded"}`, false},
		{"failure", `{"id":"` + scanID + `","type":"notBusy","outcome":"failed","error":"scan failed"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gets int
			scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				gets++
				_, _ = w.Write([]byte(tc.response))
			}))
			defer scanner.Close()
			previousClient := KubescapeHttpClient
			KubescapeHttpClient = scanner.Client()
			t.Cleanup(func() { KubescapeHttpClient = previousClient })
			cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{},
				utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
				nil, config.Config{Namespace: "kubescape"})
			require.NoError(t, err)
			dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
			var attempts int
			var patched v1alpha1.OperatorCommandStatus
			dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
				attempts++
				if attempts == 1 {
					return true, nil, errors.New("temporary Kubernetes status failure")
				}
				var body struct {
					Status v1alpha1.OperatorCommandStatus `json:"status"`
				}
				if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
					return true, nil, err
				}
				patched = body.Status
				return true, &unstructured.Unstructured{}, nil
			})
			session := &utils.SessionObj{ParentCommandDetails: &utils.OperatorCommandDetails{
				Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
				StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
			}}
			data := &kubescapeResponseData{scanID: scanID, sessionObj: session}
			retry, delay := HandleKubescapeResponse(context.Background(), cfg, data)
			require.True(t, retry, "a failed terminal status patch must not end polling")
			require.NotNil(t, delay)
			retry, delay = HandleKubescapeResponse(context.Background(), cfg, data)
			require.False(t, retry)
			require.Nil(t, delay)
			require.Equal(t, 1, gets, "terminal outcome must be cached across patch retry")
			require.Equal(t, 2, attempts)
			require.True(t, patched.Completed)
			require.Equal(t, []byte(scanID), patched.Payload)
			require.Equal(t, tc.wantError, patched.Error != nil)
		})
	}
}

func TestTerminalRetryStillPersistsMissingPendingScanID(t *testing.T) {
	const scanID = "99a48a8c-0795-42f3-b009-75f7eab1df75"
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"` + scanID + `","type":"notBusy","outcome":"failed"}`))
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://")},
		nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	dynamic := fake.NewSimpleDynamicClient(runtime.NewScheme())
	var attempts int
	var patches []v1alpha1.OperatorCommandStatus
	dynamic.PrependReactor("patch", v1alpha1.SchemaGroupVersionResource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		attempts++
		if attempts <= 3 {
			return true, nil, errors.New("temporary Kubernetes status failure")
		}
		var body struct {
			Status v1alpha1.OperatorCommandStatus `json:"status"`
		}
		if err := json.Unmarshal(action.(ktesting.PatchAction).GetPatch(), &body); err != nil {
			return true, nil, err
		}
		patches = append(patches, body.Status)
		return true, &unstructured.Unstructured{}, nil
	})
	session := &utils.SessionObj{ParentCommandDetails: &utils.OperatorCommandDetails{
		Command:   &v1alpha1.OperatorCommand{ObjectMeta: metav1.ObjectMeta{Namespace: "kubescape", Name: "scan-request"}},
		StartedAt: time.Now(), Client: &k8sinterface.KubernetesApi{DynamicClient: dynamic},
	}}
	data := &kubescapeResponseData{scanID: scanID, sessionObj: session, pendingWriteNeeded: true}
	retry, _ := HandleKubescapeResponse(context.Background(), cfg, data)
	require.True(t, retry)
	require.True(t, data.pendingWriteNeeded, "failed pending and terminal patches must retain recovery work")
	retry, _ = HandleKubescapeResponse(context.Background(), cfg, data)
	require.False(t, retry)
	require.False(t, data.pendingWriteNeeded)
	require.Len(t, patches, 2)
	require.False(t, patches[0].Completed)
	require.Equal(t, []byte(scanID), patches[0].Payload)
	require.True(t, patches[1].Completed)
	require.NotNil(t, patches[1].Error)
}
