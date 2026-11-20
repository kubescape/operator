package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes/fake"
)

func newTestAttributes(kind, name, namespace, subresource string, obj runtime.Object) admission.Attributes {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: kind}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	return admission.NewAttributesRecord(obj, nil, gvk, namespace, name, gvr, subresource, admission.Create, nil, false, nil)
}

func TestGetControllerDetails(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-rs",
			Namespace: "default",
			UID:       types.UID("rs-uid"),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "web", UID: types.UID("deploy-uid")},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-pod",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-rs", UID: types.UID("rs-uid")},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-1",
		},
	}
	clientset := fake.NewClientset(rs, pod)

	t.Run("nil event returns error", func(t *testing.T) {
		_, _, _, _, _, _, err := GetControllerDetails(nil, clientset)
		assert.Error(t, err)
	})

	t.Run("missing pod name or namespace returns error", func(t *testing.T) {
		ev := newTestAttributes("Pod", "", "default", "", nil)
		_, _, _, _, _, _, err := GetControllerDetails(ev, clientset)
		assert.Error(t, err)

		ev = newTestAttributes("Pod", "web-pod", "", "", nil)
		_, _, _, _, _, _, err = GetControllerDetails(ev, clientset)
		assert.Error(t, err)
	})

	t.Run("missing pod in API server returns error", func(t *testing.T) {
		ev := newTestAttributes("Pod", "does-not-exist", "default", "", nil)
		_, _, _, _, _, _, err := GetControllerDetails(ev, clientset)
		assert.Error(t, err)
	})

	t.Run("resolves pod and deployment owner", func(t *testing.T) {
		ev := newTestAttributes("Pod", "web-pod", "default", "", nil)
		gotPod, kind, name, ns, uid, nodeName, err := GetControllerDetails(ev, clientset)
		require.NoError(t, err)
		require.NotNil(t, gotPod)
		assert.Equal(t, "web-pod", gotPod.Name)
		assert.Equal(t, "Deployment", kind)
		assert.Equal(t, "web", name)
		assert.Equal(t, "default", ns)
		assert.Equal(t, "deploy-uid", uid)
		assert.Equal(t, "worker-1", nodeName)
	})
}

func TestExtractPodOwner(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1.Pod
		objects  []runtime.Object
		wantKind string
		wantName string
		wantNS   string
		wantUID  string
	}{
		{
			name: "nil pod",
			pod:  nil,
		},
		{
			name: "orphan pod without owners",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "default"},
			},
		},
		{
			name: "statefulset owner",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-0",
					Namespace: "prod",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "StatefulSet", Name: "db", UID: types.UID("sts-uid")},
					},
				},
			},
			wantKind: "StatefulSet",
			wantName: "db",
			wantNS:   "prod",
			wantUID:  "sts-uid",
		},
		{
			name: "daemonset owner",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "agent-abc",
					Namespace: "kube-system",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "DaemonSet", Name: "agent", UID: types.UID("ds-uid")},
					},
				},
			},
			wantKind: "DaemonSet",
			wantName: "agent",
			wantNS:   "kube-system",
			wantUID:  "ds-uid",
		},
		{
			name: "replicaset owned by deployment",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-1",
					Namespace: "default",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "app-rs", UID: types.UID("rs-uid")},
					},
				},
			},
			objects: []runtime.Object{
				&appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "app-rs",
						Namespace: "default",
						UID:       types.UID("rs-uid"),
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "Deployment", Name: "app", UID: types.UID("deploy-uid")},
						},
					},
				},
			},
			wantKind: "Deployment",
			wantName: "app",
			wantNS:   "default",
			wantUID:  "deploy-uid",
		},
		{
			name: "replicaset with non-first deployment ownerRef",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-2",
					Namespace: "default",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "app-rs-multi", UID: types.UID("rs-multi-uid")},
					},
				},
			},
			objects: []runtime.Object{
				&appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "app-rs-multi",
						Namespace: "default",
						UID:       types.UID("rs-multi-uid"),
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "Application", Name: "argo-app", UID: types.UID("argo-uid")},
							{Kind: "Deployment", Name: "app", UID: types.UID("deploy-uid-2")},
						},
					},
				},
			},
			wantKind: "Deployment",
			wantName: "app",
			wantNS:   "default",
			wantUID:  "deploy-uid-2",
		},
		{
			name: "standalone replicaset fallback when get fails",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "standalone-1",
					Namespace: "default",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "missing-rs", UID: types.UID("rs-fallback-uid")},
					},
				},
			},
			wantKind: "ReplicaSet",
			wantName: "missing-rs",
			wantNS:   "default",
			wantUID:  "rs-fallback-uid",
		},
		{
			name: "job owned by cronjob",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "backup-1",
					Namespace: "ops",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "Job", Name: "backup-job", UID: types.UID("job-uid")},
					},
				},
			},
			objects: []runtime.Object{
				&batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backup-job",
						Namespace: "ops",
						UID:       types.UID("job-uid"),
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "CronJob", Name: "backup-cron", UID: types.UID("cron-uid")},
						},
					},
				},
			},
			wantKind: "CronJob",
			wantName: "backup-cron",
			wantNS:   "ops",
			wantUID:  "cron-uid",
		},
		{
			name: "job with non-first cronjob ownerRef",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "backup-2",
					Namespace: "ops",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "Job", Name: "backup-job-multi", UID: types.UID("job-multi-uid")},
					},
				},
			},
			objects: []runtime.Object{
				&batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backup-job-multi",
						Namespace: "ops",
						UID:       types.UID("job-multi-uid"),
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "CustomController", Name: "custom", UID: types.UID("custom-uid")},
							{Kind: "CronJob", Name: "backup-cron", UID: types.UID("cron-uid-2")},
						},
					},
				},
			},
			wantKind: "CronJob",
			wantName: "backup-cron",
			wantNS:   "ops",
			wantUID:  "cron-uid-2",
		},
		{
			name: "standalone job fallback when get fails",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oneshot-1",
					Namespace: "ops",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "Job", Name: "missing-job", UID: types.UID("job-fallback-uid")},
					},
				},
			},
			wantKind: "Job",
			wantName: "missing-job",
			wantNS:   "ops",
			wantUID:  "job-fallback-uid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientset := fake.NewClientset(tc.objects...)
			kind, name, ns, uid := ExtractPodOwner(tc.pod, clientset)
			assert.Equal(t, tc.wantKind, kind)
			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantNS, ns)
			assert.Equal(t, tc.wantUID, uid)
		})
	}
}

func TestPodFromAdmissionObject(t *testing.T) {
	t.Run("nil event", func(t *testing.T) {
		assert.Nil(t, PodFromAdmissionObject(nil))
	})

	t.Run("non-pod kind", func(t *testing.T) {
		ev := newTestAttributes("Deployment", "web", "default", "", &unstructured.Unstructured{Object: map[string]interface{}{}})
		assert.Nil(t, PodFromAdmissionObject(ev))
	})

	t.Run("nil object", func(t *testing.T) {
		ev := newTestAttributes("Pod", "web", "default", "", nil)
		assert.Nil(t, PodFromAdmissionObject(ev))
	})

	t.Run("non-unstructured object", func(t *testing.T) {
		ev := newTestAttributes("Pod", "web", "default", "", &corev1.Pod{})
		assert.Nil(t, PodFromAdmissionObject(ev))
	})

	t.Run("valid unstructured pod", func(t *testing.T) {
		u := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]interface{}{
					"name":      "nginx",
					"namespace": "default",
				},
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "nginx",
							"image": "nginx:1.25",
						},
					},
				},
			},
		}
		ev := newTestAttributes("Pod", "nginx", "default", "", u)
		pod := PodFromAdmissionObject(ev)
		require.NotNil(t, pod)
		assert.Equal(t, "nginx", pod.Name)
		assert.Equal(t, "default", pod.Namespace)
		require.Len(t, pod.Spec.Containers, 1)
		assert.Equal(t, "nginx:1.25", pod.Spec.Containers[0].Image)
	})
}

func TestGetContainerNameFromExecToPodEvent(t *testing.T) {
	t.Run("nil event", func(t *testing.T) {
		_, err := GetContainerNameFromExecToPodEvent(nil)
		assert.Error(t, err)
	})

	t.Run("non exec/attach subresource", func(t *testing.T) {
		ev := newTestAttributes("Pod", "p1", "default", "log", &unstructured.Unstructured{Object: map[string]interface{}{}})
		_, err := GetContainerNameFromExecToPodEvent(ev)
		assert.Error(t, err)
	})

	t.Run("nil object", func(t *testing.T) {
		ev := newTestAttributes("PodExecOptions", "p1", "default", "exec", nil)
		_, err := GetContainerNameFromExecToPodEvent(ev)
		assert.Error(t, err)
	})

	t.Run("non-unstructured object", func(t *testing.T) {
		ev := newTestAttributes("PodExecOptions", "p1", "default", "exec", &corev1.PodExecOptions{Container: "app"})
		_, err := GetContainerNameFromExecToPodEvent(ev)
		assert.Error(t, err)
	})

	t.Run("exec subresource returns container name", func(t *testing.T) {
		u := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"container": "app",
			},
		}
		ev := newTestAttributes("PodExecOptions", "p1", "default", "exec", u)
		name, err := GetContainerNameFromExecToPodEvent(ev)
		require.NoError(t, err)
		assert.Equal(t, "app", name)
	})

	t.Run("attach subresource returns container name", func(t *testing.T) {
		u := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"container": "sidecar",
			},
		}
		ev := newTestAttributes("PodAttachOptions", "p1", "default", "attach", u)
		name, err := GetContainerNameFromExecToPodEvent(ev)
		require.NoError(t, err)
		assert.Equal(t, "sidecar", name)
	})
}

func TestContainerLookupHelpers(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "nginx:1.25"},
				{Name: "sidecar", Image: "envoy:v1"},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Image: "busybox:1.36"},
			},
			EphemeralContainers: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "alpine:3.19"}},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://app-id", ImageID: "docker-pullable://nginx@sha256:aaa"},
				{Name: "sidecar", ContainerID: "containerd://sidecar-id", ImageID: "envoy@sha256:bbb"},
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "init", ContainerID: "containerd://init-id", ImageID: "docker-pullable://busybox@sha256:ccc"},
			},
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				{Name: "debug", ContainerID: "containerd://debug-id", ImageID: "docker-pullable://alpine@sha256:ddd"},
			},
		},
	}

	t.Run("GetContainerID", func(t *testing.T) {
		assert.Equal(t, "", GetContainerID(nil, "app"))
		assert.Equal(t, "containerd://app-id", GetContainerID(pod, ""))
		assert.Equal(t, "containerd://sidecar-id", GetContainerID(pod, "sidecar"))
		assert.Equal(t, "containerd://init-id", GetContainerID(pod, "init"))
		assert.Equal(t, "containerd://debug-id", GetContainerID(pod, "debug"))
		assert.Equal(t, "", GetContainerID(pod, "missing"))
		assert.Equal(t, "", GetContainerID(&corev1.Pod{}, ""))
	})

	t.Run("GetContainerImage", func(t *testing.T) {
		assert.Equal(t, "", GetContainerImage(nil, "app"))
		assert.Equal(t, "nginx:1.25", GetContainerImage(pod, ""))
		assert.Equal(t, "envoy:v1", GetContainerImage(pod, "sidecar"))
		assert.Equal(t, "busybox:1.36", GetContainerImage(pod, "init"))
		assert.Equal(t, "alpine:3.19", GetContainerImage(pod, "debug"))
		assert.Equal(t, "", GetContainerImage(pod, "missing"))
		assert.Equal(t, "", GetContainerImage(&corev1.Pod{}, ""))
	})

	t.Run("GetContainerImageDigest", func(t *testing.T) {
		assert.Equal(t, "", GetContainerImageDigest(nil, "app"))
		assert.Equal(t, "nginx@sha256:aaa", GetContainerImageDigest(pod, ""))
		assert.Equal(t, "envoy@sha256:bbb", GetContainerImageDigest(pod, "sidecar"))
		assert.Equal(t, "busybox@sha256:ccc", GetContainerImageDigest(pod, "init"))
		assert.Equal(t, "alpine@sha256:ddd", GetContainerImageDigest(pod, "debug"))
		assert.Equal(t, "", GetContainerImageDigest(pod, "missing"))
		assert.Equal(t, "", GetContainerImageDigest(&corev1.Pod{}, ""))
	})
}
