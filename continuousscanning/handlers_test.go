package continuousscanning

import (
	"context"
	"testing"

	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/operator/config"
	kssfake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
)

func TestEventToUnstructured(t *testing.T) {
	t.Run("converts unstructured object", func(t *testing.T) {
		u := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]interface{}{
					"name":      "test-pod",
					"namespace": "default",
				},
			},
		}
		res, err := eventToUnstructured(watch.Event{Type: watch.Added, Object: u})
		require.NoError(t, err)
		assert.Equal(t, "Pod", res.GetKind())
		assert.Equal(t, "test-pod", res.GetName())
		assert.Equal(t, "default", res.GetNamespace())
	})

	t.Run("converts typed runtime.Object without panic", func(t *testing.T) {
		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "typed-pod",
				Namespace: "kube-system",
			},
		}
		res, err := eventToUnstructured(watch.Event{Type: watch.Added, Object: pod})
		require.NoError(t, err)
		assert.Equal(t, "Pod", res.GetKind())
		assert.Equal(t, "typed-pod", res.GetName())
		assert.Equal(t, "kube-system", res.GetNamespace())
	})

	t.Run("returns error when event object is nil", func(t *testing.T) {
		res, err := eventToUnstructured(watch.Event{Type: watch.Added, Object: nil})
		assert.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("returns error when event object is typed-nil unstructured", func(t *testing.T) {
		var u *unstructured.Unstructured
		res, err := eventToUnstructured(watch.Event{Type: watch.Added, Object: u})
		assert.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("returns error when event object is typed-nil pod", func(t *testing.T) {
		var pod *corev1.Pod
		res, err := eventToUnstructured(watch.Event{Type: watch.Added, Object: pod})
		assert.Error(t, err)
		assert.Nil(t, res)
	})
}

func TestHandlersWithTypedAndNilObjects(t *testing.T) {
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, armometadata.ClusterConfig{ClusterName: "test-cluster"}, nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)

	wp, err := ants.NewPoolWithFunc(1, func(i interface{}) {})
	require.NoError(t, err)
	defer wp.Release()

	storageClient := kssfake.NewSimpleClientset()

	t.Run("poolInvokerHandler handles typed object without panic", func(t *testing.T) {
		h := NewTriggeringHandler(wp, cfg)
		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
		}
		err := h.Handle(context.Background(), watch.Event{Type: watch.Added, Object: pod})
		assert.NoError(t, err)
	})

	t.Run("poolInvokerHandler returns error on nil object without panic", func(t *testing.T) {
		h := NewTriggeringHandler(wp, cfg)
		err := h.Handle(context.Background(), watch.Event{Type: watch.Added, Object: nil})
		assert.Error(t, err)
	})

	t.Run("poolInvokerHandler returns error on typed-nil unstructured without panic", func(t *testing.T) {
		h := NewTriggeringHandler(wp, cfg)
		var u *unstructured.Unstructured
		err := h.Handle(context.Background(), watch.Event{Type: watch.Added, Object: u})
		assert.Error(t, err)
	})

	t.Run("deletedCleanerHandler handles typed object without panic", func(t *testing.T) {
		h := NewDeletedCleanerHandler(wp, cfg, storageClient)
		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Pod",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
		}
		err := h.Handle(context.Background(), watch.Event{Type: watch.Deleted, Object: pod})
		assert.NoError(t, err)
	})

	t.Run("deletedCleanerHandler returns error on nil object without panic", func(t *testing.T) {
		h := NewDeletedCleanerHandler(wp, cfg, storageClient)
		err := h.Handle(context.Background(), watch.Event{Type: watch.Deleted, Object: nil})
		assert.Error(t, err)
	})

	t.Run("deletedCleanerHandler returns error on typed-nil unstructured without panic", func(t *testing.T) {
		h := NewDeletedCleanerHandler(wp, cfg, storageClient)
		var u *unstructured.Unstructured
		err := h.Handle(context.Background(), watch.Event{Type: watch.Deleted, Object: u})
		assert.Error(t, err)
	})
}
