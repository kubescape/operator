package mainhandler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/armosec/utils-k8s-go/probes"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type trackingBody struct {
	io.ReadCloser
	closed  atomic.Bool
	onClose func()
}

func (b *trackingBody) Close() error {
	if b.closed.CompareAndSwap(false, true) && b.onClose != nil {
		b.onClose()
	}
	return b.ReadCloser.Close()
}

type trackingRoundTripper struct {
	base        http.RoundTripper
	openBodies  atomic.Int32
	maxOpenSeen atomic.Int32
}

func (rt *trackingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	cur := rt.openBodies.Add(1)
	for {
		prev := rt.maxOpenSeen.Load()
		if cur <= prev || rt.maxOpenSeen.CompareAndSwap(prev, cur) {
			break
		}
	}
	resp.Body = &trackingBody{
		ReadCloser: resp.Body,
		onClose: func() {
			rt.openBodies.Add(-1)
		},
	}
	return resp, nil
}

func TestIsActionNeedToWait(t *testing.T) {
	fn := isActionNeedToWait(apis.Command{CommandName: apis.TypeScanImages})
	assert.Equal(t, reflect.ValueOf(waitForVulnScanReady).Pointer(), reflect.ValueOf(fn).Pointer())

	fn = isActionNeedToWait(apis.Command{CommandName: apis.TypeRunKubescape})
	assert.Equal(t, reflect.ValueOf(waitForKubescapeReady).Pointer(), reflect.ValueOf(fn).Pointer())

	fn = isActionNeedToWait(apis.Command{CommandName: "unknown-command"})
	assert.Equal(t, reflect.ValueOf(notWaitAtAll).Pointer(), reflect.ValueOf(fn).Pointer())
}

func TestWaitForVulnScanReady_ClosesResponseBodyOnRetries(t *testing.T) {
	prevInterval := readinessPollInterval
	readinessPollInterval = time.Millisecond
	t.Cleanup(func() { readinessPollInterval = prevInterval })

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, fmt.Sprintf("/v1/%s", probes.ReadinessPath), r.URL.Path)
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rt := &trackingRoundTripper{base: srv.Client().Transport}
	prevClient := VulnScanHttpClient
	VulnScanHttpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { VulnScanHttpClient = prevClient })

	clusterCfg := utilsmetadata.ClusterConfig{KubevulnURL: strings.TrimPrefix(srv.URL, "http://")}
	opCfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterCfg, &beUtils.Credentials{}, config.Config{})
	require.NoError(t, err)

	waitForVulnScanReady(opCfg)

	assert.Equal(t, int32(3), attempts.Load())
	assert.Equal(t, int32(0), rt.openBodies.Load(), "all response bodies should be closed")
	assert.Equal(t, int32(1), rt.maxOpenSeen.Load(), "each retry should close its body before the next attempt")
}

func TestWaitForKubescapeReady_ClosesResponseBodyOnRetries(t *testing.T) {
	prevInterval := readinessPollInterval
	readinessPollInterval = time.Millisecond
	t.Cleanup(func() { readinessPollInterval = prevInterval })

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		assert.Equal(t, "/readyz", r.URL.Path)
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := &trackingRoundTripper{base: srv.Client().Transport}
	prevClient := KubescapeHttpClient
	KubescapeHttpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { KubescapeHttpClient = prevClient })

	clusterCfg := utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(srv.URL, "http://")}
	opCfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, clusterCfg, &beUtils.Credentials{}, config.Config{})
	require.NoError(t, err)

	waitForKubescapeReady(opCfg)

	assert.Equal(t, int32(3), attempts.Load())
	assert.Equal(t, int32(0), rt.openBodies.Load(), "all response bodies should be closed")
	assert.Equal(t, int32(1), rt.maxOpenSeen.Load(), "each retry should close its body before the next attempt")
}
