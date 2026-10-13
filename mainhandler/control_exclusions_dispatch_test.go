package mainhandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/require"
)

func TestControlExclusionsScheduledReplayAndInvalidRequestsAtDispatch(t *testing.T) {
	var dispatched atomic.Int32
	received := make(chan utilsmetav1.PostScanRequest, 8)
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dispatched.Add(1)
		var request utilsmetav1.PostScanRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode scan: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- request
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"independent-scan","type":"success"}`))
	}))
	defer scanner.Close()
	previousClient := KubescapeHttpClient
	KubescapeHttpClient = scanner.Client()
	t.Cleanup(func() { KubescapeHttpClient = previousClient })
	handler := func(args map[string]interface{}, globals []string) *ActionHandler {
		t.Helper()
		cfg, err := config.NewOperatorConfig(
			config.CapabilitiesConfig{Components: config.Components{Kubescape: config.Component{Enabled: true}}},
			utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(scanner.URL, "http://"), InstallationData: armotypes.InstallationData{DefaultFrameworks: []string{"nsa"}}},
			&beUtils.Credentials{}, config.Config{Namespace: "kubescape", ExcludeControls: globals},
		)
		require.NoError(t, err)
		return &ActionHandler{config: cfg, sessionObj: &utils.SessionObj{Command: &apis.Command{Args: args}}}
	}

	// Use the same serialization path as scheduled jobs, then replay its stored command.
	args := map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{"excludeControls": []string{"C-0070"}, "hostScanner": false}}
	scheduled, err := getKubescapeRequest(args, []string{"nsa"})
	require.NoError(t, err)
	stored, err := wrapRequestWithCommand(scheduled)
	require.NoError(t, err)
	var commands apis.Commands
	require.NoError(t, json.Unmarshal(stored, &commands))
	require.Len(t, commands.Commands, 1)
	for _, tt := range []struct {
		name          string
		globals, want []string
	}{
		{"original installation", []string{"C-0069"}, []string{"C-0069", "C-0070"}},
		{"changed installation", []string{"C-0071"}, []string{"C-0071", "C-0070"}},
		{"removed installation exclusions", nil, []string{"C-0070"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := dispatched.Load()
			require.NoError(t, handler(commands.Commands[0].Args, tt.globals).kubescapeScan(context.Background()))
			require.Equal(t, before+1, dispatched.Load())
			select {
			case sent := <-received:
				require.Equal(t, tt.want, sent.ExcludeControls, "stored schedule must use current installation settings at actual dispatch")
				require.Equal(t, []string{"nsa"}, sent.TargetNames)
				require.NotNil(t, sent.HostScanner)
				require.False(t, *sent.HostScanner)
			default:
				t.Fatal("successful dispatch did not reach the scanner")
			}
		})
	}
	for _, value := range []interface{}{"C-0069", []interface{}{42}, []interface{}{nil}, []string{""}, []string{" "}} {
		data, err := json.Marshal(value)
		require.NoError(t, err)
		t.Run("invalid "+string(data), func(t *testing.T) {
			before := dispatched.Load()
			args := map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{"excludeControls": value}}
			require.Error(t, handler(args, []string{"C-0069"}).kubescapeScan(context.Background()))
			require.Equal(t, before, dispatched.Load(), "bad exclusions must not trigger an HTTP scan")
		})
	}
}
