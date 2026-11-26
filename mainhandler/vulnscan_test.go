package mainhandler

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	dockerregistry "github.com/moby/moby/api/types/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func fileToPod(filePath string) *corev1.Pod {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	var pod *corev1.Pod
	err = json.Unmarshal(b, &pod)
	if err != nil {
		return nil
	}
	return pod
}

func fileToSecret(filePath string) *corev1.Secret {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	var secret *corev1.Secret
	err = json.Unmarshal(b, &secret)
	if err != nil {
		return nil
	}
	return secret
}

func Test_ActionHandler_getImageScanConfig(t *testing.T) {
	type args struct {
		namespace string
		pod       *corev1.Pod
		imageTag  string
	}
	tests := []struct {
		name    string
		args    args
		objects []runtime.Object
		want    *ImageScanConfig
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "no registry treated as docker.io",
			args: args{
				imageTag: "nginx:latest",
			},
			objects: []runtime.Object{fileToSecret("testdata/vulnscan/registry-secret.json")},
			want: &ImageScanConfig{
				insecure: ptr.To(true),
				authConfigs: []dockerregistry.AuthConfig{
					{Username: "test-user", Password: "test-pass", ServerAddress: "docker.io"},
					{Username: "test-user-quay", Password: "test-pass-quay", ServerAddress: "quay.io"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "quay.IO",
			args: args{
				imageTag: "quay.IO/kubescape/nginx:latest",
			},
			objects: []runtime.Object{fileToSecret("testdata/vulnscan/registry-secret.json")},
			want: &ImageScanConfig{
				skipTLSVerify: ptr.To(true),
				authConfigs: []dockerregistry.AuthConfig{
					{Username: "test-user", Password: "test-pass", ServerAddress: "docker.io"},
					{Username: "test-user-quay", Password: "test-pass-quay", ServerAddress: "quay.io"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "pod with registry secret",
			args: args{
				pod: fileToPod("testdata/vulnscan/pod.json"),
			},
			objects: []runtime.Object{fileToSecret("testdata/vulnscan/regcreds.json")},
			want: &ImageScanConfig{
				authConfigs: []dockerregistry.AuthConfig{
					{Username: "matthyx", Password: "toto", Auth: "bWF0dGh5eDp0b3Rv", ServerAddress: "https://index.docker.io/v1/"},
					{Username: "YWRtaW4=", Password: "SGFyYm9yMTIzNDU=", Auth: "YWRtaW46SGFyYm9yMTIzNDU=", ServerAddress: "private.docker.io"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "pod with registry secret with httpheaders",
			args: args{
				pod: fileToPod("testdata/vulnscan/pod.json"),
			},
			objects: []runtime.Object{fileToSecret("testdata/vulnscan/regcreds-with-httpheaders.json")},
			want: &ImageScanConfig{
				authConfigs: []dockerregistry.AuthConfig{
					{Username: "", Password: "", Auth: "<REDACTED>", ServerAddress: "https://index.docker.io/v1/"},
					{Username: "", Password: "", Auth: "<REDACTED>", ServerAddress: "registry.horizons.sh"},
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sApiMock := &k8sinterface.KubernetesApi{
				Context:          context.TODO(),
				KubernetesClient: k8sfake.NewClientset(tt.objects...),
			}
			got, err := getImageScanConfig(k8sApiMock, tt.args.namespace, tt.args.pod, tt.args.imageTag)
			if !tt.wantErr(t, err, fmt.Sprintf("getImageScanConfig(%v, %v, %v, %v)", k8sApiMock, tt.args.namespace, tt.args.pod, tt.args.imageTag)) {
				return
			}
			// sort for stable comparison
			sort.Slice(got.authConfigs, func(i, j int) bool {
				return got.authConfigs[i].ServerAddress < got.authConfigs[j].ServerAddress
			})
			assert.Equalf(t, tt.want, got, "getImageScanConfig(%v, %v, %v, %v)", k8sApiMock, tt.args.namespace, tt.args.pod, tt.args.imageTag)
		})
	}
}

// The skipTLSVerify and http settings of a registry scan secret entry belong to the
// registry that entry names. An entry for a different registry, whose name only contains
// the image's registry, must not hand them to the image's scan.
func Test_getImageScanConfig_tlsSettingsFollowTheExactRegistry(t *testing.T) {
	tests := []struct {
		name         string
		registry     string
		imageTag     string
		wantSkipTLS  *bool
		wantInsecure *bool
	}{
		{
			name:     "another registry whose name contains the image's registry",
			registry: "harbor.example.com",
			imageTag: "example.com/team/app:1.0",
		},
		{
			name:     "a Docker Hub mirror named after Docker Hub",
			registry: "mirror.docker.io.internal",
			imageTag: "nginx:latest",
		},
		{
			name:     "the same host on another port",
			registry: "registry.local:5000",
			imageTag: "registry.local/app:1.0",
		},
		{
			name:         "the image's own registry",
			registry:     "harbor.example.com",
			imageTag:     "harbor.example.com/team/app:1.0",
			wantSkipTLS:  ptr.To(true),
			wantInsecure: ptr.To(true),
		},
		{
			name:         "the image's own registry written with a scheme and a path",
			registry:     "https://harbor.example.com/team",
			imageTag:     "harbor.example.com/team/app:1.0",
			wantSkipTLS:  ptr.To(true),
			wantInsecure: ptr.To(true),
		},
		{
			name:         "Docker Hub under its index address",
			registry:     "https://index.docker.io/v1/",
			imageTag:     "nginx:latest",
			wantSkipTLS:  ptr.To(true),
			wantInsecure: ptr.To(true),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := json.Marshal([]registryAuth{{
				Registry:      tt.registry,
				AuthMethod:    "credentials",
				Username:      "user",
				Password:      "pass",
				SkipTLSVerify: ptr.To(true),
				Insecure:      ptr.To(true),
			}})
			assert.NoError(t, err)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "kubescape-registry-scan-test", Namespace: "kubescape"},
				Data:       map[string][]byte{registriesAuthFieldInSecret: auth},
			}
			k8sApiMock := &k8sinterface.KubernetesApi{
				Context:          context.TODO(),
				KubernetesClient: k8sfake.NewClientset(secret),
			}

			got, err := getImageScanConfig(k8sApiMock, "", nil, tt.imageTag)

			assert.NoError(t, err)
			assert.Equal(t, tt.wantSkipTLS, got.skipTLSVerify, "skipTLSVerify")
			assert.Equal(t, tt.wantInsecure, got.insecure, "http")
		})
	}
}

func newTestRegistryScanCommands(count int) []*apis.RegistryScanCommand {
	cmds := make([]*apis.RegistryScanCommand, 0, count)
	for i := range count {
		cmds = append(cmds, &apis.RegistryScanCommand{
			ImageScanParams: apis.ImageScanParams{
				ImageTag: fmt.Sprintf("registry.example.com/repo/img-%d:v1", i),
				JobID:    fmt.Sprintf("job-%d", i),
			},
		})
	}
	return cmds
}

func TestSendAllImagesToRegistryScan_BoundedConcurrency(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	var totalCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		cur := inFlight.Add(1)
		for {
			prev := maxInFlight.Load()
			if cur <= prev || maxInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}
		totalCalls.Add(1)
		time.Sleep(80 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldClient := VulnScanHttpClient
	t.Cleanup(func() { VulnScanHttpClient = oldClient })
	VulnScanHttpClient = server.Client()

	host := strings.TrimPrefix(server.URL, "http://")
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{},
		armometadata.ClusterConfig{KubevulnURL: host},
		nil,
		config.Config{Namespace: "kubescape", ConcurrencyWorkers: 3},
	)
	require.NoError(t, err)

	err = sendAllImagesToRegistryScan(context.Background(), cfg, newTestRegistryScanCommands(6))
	require.NoError(t, err)

	assert.Equal(t, int32(6), totalCalls.Load())
	assert.GreaterOrEqual(t, maxInFlight.Load(), int32(2), "expected concurrent dispatch")
	assert.LessOrEqual(t, maxInFlight.Load(), int32(3), "expected concurrency bounded by ConcurrencyWorkers")
}

func TestSendAllImagesToRegistryScan_AggregatesAllErrors(t *testing.T) {
	var totalCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		totalCalls.Add(1)
		s := string(body)
		if strings.Contains(s, "img-1:v1") || strings.Contains(s, "img-3:v1") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldClient := VulnScanHttpClient
	t.Cleanup(func() { VulnScanHttpClient = oldClient })
	VulnScanHttpClient = server.Client()

	host := strings.TrimPrefix(server.URL, "http://")
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{},
		armometadata.ClusterConfig{KubevulnURL: host},
		nil,
		config.Config{Namespace: "kubescape", ConcurrencyWorkers: 2},
	)
	require.NoError(t, err)

	err = sendAllImagesToRegistryScan(context.Background(), cfg, newTestRegistryScanCommands(4))
	require.Error(t, err)
	assert.Equal(t, int32(4), totalCalls.Load())
	assert.Contains(t, err.Error(), "img-1:v1")
	assert.Contains(t, err.Error(), "img-3:v1")
}

func TestSendAllImagesToRegistryScan_RespectsContextCancellation(t *testing.T) {
	var totalCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		totalCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldClient := VulnScanHttpClient
	t.Cleanup(func() { VulnScanHttpClient = oldClient })
	VulnScanHttpClient = server.Client()

	host := strings.TrimPrefix(server.URL, "http://")
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{},
		armometadata.ClusterConfig{KubevulnURL: host},
		nil,
		config.Config{Namespace: "kubescape", ConcurrencyWorkers: 2},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = sendAllImagesToRegistryScan(ctx, cfg, newTestRegistryScanCommands(3))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(0), totalCalls.Load())
}

func TestSendAllImagesToRegistryScan_EmptyAndNilCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldClient := VulnScanHttpClient
	t.Cleanup(func() { VulnScanHttpClient = oldClient })
	VulnScanHttpClient = server.Client()

	host := strings.TrimPrefix(server.URL, "http://")
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{},
		armometadata.ClusterConfig{KubevulnURL: host},
		nil,
		config.Config{Namespace: "kubescape"},
	)
	require.NoError(t, err)

	assert.NoError(t, sendAllImagesToRegistryScan(context.Background(), cfg, nil))
	assert.NoError(t, sendAllImagesToRegistryScan(context.Background(), cfg, []*apis.RegistryScanCommand{
		nil,
		{ImageScanParams: apis.ImageScanParams{ImageTag: "registry.example.com/repo/img:v1", JobID: "job-1"}},
	}))
}
