package sbomexport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestSplitRef(t *testing.T) {
	tt := []struct {
		ref        string
		repository string
		version    string
	}{
		{"docker.io/library/redis:8-alpine", "docker.io/library/redis", "8-alpine"},
		{"docker.io/library/redis@sha256:0123456789abcdef", "docker.io/library/redis", "0123456789ab"},
		{"docker.io/library/redis:8-alpine@sha256:0123456789abcdef", "docker.io/library/redis", "8-alpine"},
		{"localhost:5000/app", "localhost:5000/app", "latest"},
		{"localhost:5000/app:1.2", "localhost:5000/app", "1.2"},
		{"localhost:5000/app@sha256:abc", "localhost:5000/app", "abc"},
		{"nginx", "nginx", "latest"},
	}
	for _, tc := range tt {
		t.Run(tc.ref, func(t *testing.T) {
			repository, version := splitRef(tc.ref)
			assert.Equal(t, tc.repository, repository)
			assert.Equal(t, tc.version, version)
		})
	}
}

func TestDigestOf(t *testing.T) {
	assert.Equal(t, "sha256:abc", digestOf("docker.io/library/redis@sha256:abc"))
	assert.Equal(t, "sha256:abc", digestOf("sha256:abc"))
}

func TestRunningDigests(t *testing.T) {
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	terminated := corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
	tt := []struct {
		name string
		pod  corev1.PodStatus
		want []string
	}{
		{
			name: "containers and running init containers (sidecars) count",
			pod: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "app", ImageID: "docker.io/library/app@sha256:app"},
					{Name: "starting"}, // no image ID yet
				},
				InitContainerStatuses: []corev1.ContainerStatus{
					{Name: "sidecar", ImageID: "docker.io/library/proxy@sha256:proxy", State: running},
					{Name: "migrate", ImageID: "docker.io/library/migrate@sha256:migrate", State: terminated},
				},
			},
			want: []string{"sha256:app", "sha256:proxy"},
		},
		{
			name: "a pod that is not running runs nothing",
			pod: corev1.PodStatus{
				Phase:             corev1.PodSucceeded,
				ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ImageID: "docker.io/library/app@sha256:app"}},
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, runningDigests(&corev1.Pod{Status: tc.pod}))
		})
	}
}
