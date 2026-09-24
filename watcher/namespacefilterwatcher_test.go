package watcher

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

const allowNamespaces = `{"includeNamespaces":[],"excludeNamespaces":[]}`
const excludePayments = `{"includeNamespaces":[],"excludeNamespaces":["payments"]}`

func namespaceFilterCM(data string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "filters", Namespace: "kubescape"}, Data: map[string]string{NamespaceFiltersKey: data}}
}

func startNamespaceFilterWatcher(t *testing.T, client *fake.Clientset) (*NamespaceFilterWatcher, *config.OperatorConfig, context.Context) {
	t.Helper()
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, armometadata.ClusterConfig{}, nil, config.Config{Namespace: "kubescape"})
	require.NoError(t, err)
	w, err := NewNamespaceFilterWatcher(client, cfg, "filters")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("namespace filter watcher did not stop")
		}
	})
	return w, cfg, ctx
}

func waitForNamespaceFilters(t *testing.T, w *NamespaceFilterWatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, w.WaitForReady(ctx))
}

func TestNamespaceFilterWatcherStartup(t *testing.T) {
	for _, scenario := range []string{"missing", "invalid", "missing key"} {
		t.Run(scenario, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			if scenario != "missing" {
				cm := namespaceFilterCM(`{"includeNamespaces":[]}`)
				if scenario == "missing key" {
					cm.Data = nil
				}
				_, err := client.CoreV1().ConfigMaps("kubescape").Create(context.Background(), cm, metav1.CreateOptions{})
				require.NoError(t, err)
			}
			w, cfg, ctx := startNamespaceFilterWatcher(t, client)
			waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			require.ErrorIs(t, w.WaitForReady(waitCtx), context.DeadlineExceeded)
			cm := namespaceFilterCM(excludePayments)
			var err error
			if scenario == "missing" {
				_, err = client.CoreV1().ConfigMaps("kubescape").Create(ctx, cm, metav1.CreateOptions{})
			} else {
				_, err = client.CoreV1().ConfigMaps("kubescape").Update(ctx, cm, metav1.UpdateOptions{})
			}
			require.NoError(t, err)
			waitForNamespaceFilters(t, w)
			require.True(t, cfg.SkipNamespace("payments"))
		})
	}
}

func TestNamespaceFilterWatcherLifecycle(t *testing.T) {
	client := fake.NewSimpleClientset(namespaceFilterCM(excludePayments))
	w, cfg, ctx := startNamespaceFilterWatcher(t, client)
	waitForNamespaceFilters(t, w)
	require.True(t, cfg.SkipNamespace("payments"))
	// Invalid data and unrelated resources cannot replace a valid snapshot.
	w.apply(namespaceFilterCM(`{"includeNamespaces":[],"excludeNamespaces":[],"includeNamespacesRegex":"["}`))
	other := namespaceFilterCM(allowNamespaces)
	other.Name = "other"
	w.apply(other)
	other.Name, other.Namespace = "filters", "other"
	w.apply(other)
	require.True(t, cfg.SkipNamespace("payments"))
	require.NoError(t, client.CoreV1().ConfigMaps("kubescape").Delete(ctx, "filters", metav1.DeleteOptions{}))
	require.Eventually(t, func() bool { return len(w.informer.GetStore().List()) == 0 }, 5*time.Second, 10*time.Millisecond)
	require.True(t, cfg.SkipNamespace("payments"))
	_, err := client.CoreV1().ConfigMaps("kubescape").Create(ctx, namespaceFilterCM(allowNamespaces), metav1.CreateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return !cfg.SkipNamespace("payments") }, 5*time.Second, 10*time.Millisecond)
	_, err = client.CoreV1().ConfigMaps("kubescape").Update(ctx, namespaceFilterCM(excludePayments), metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return cfg.SkipNamespace("payments") }, 5*time.Second, 10*time.Millisecond)
	for _, action := range client.Actions() {
		switch a := action.(type) {
		case clienttesting.ListAction:
			require.Equal(t, "kubescape", a.GetNamespace())
			require.Equal(t, "metadata.name=filters", a.GetListRestrictions().Fields.String())
		case clienttesting.WatchAction:
			require.Equal(t, "kubescape", a.GetNamespace())
			require.Equal(t, "metadata.name=filters", a.GetWatchRestrictions().Fields.String())
		}
	}
}

func TestNamespaceFilterWatcherRetriesForbiddenList(t *testing.T) {
	client := fake.NewSimpleClientset(namespaceFilterCM(excludePayments))
	var permit atomic.Bool
	var denied atomic.Int32
	client.PrependReactor("list", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
		if !permit.Load() {
			denied.Add(1)
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "filters", nil)
		}
		return false, nil, nil
	})
	w, cfg, _ := startNamespaceFilterWatcher(t, client)
	require.Eventually(t, func() bool { return denied.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
	select {
	case <-w.ready:
		t.Fatal("became ready without a valid ConfigMap")
	default:
	}
	permit.Store(true)
	waitForNamespaceFilters(t, w)
	require.True(t, cfg.SkipNamespace("payments"))
}

func TestNamespaceFilterWatcherReconnects(t *testing.T) {
	client := fake.NewSimpleClientset(namespaceFilterCM(excludePayments))
	watches := make(chan *watch.RaceFreeFakeWatcher, 10)
	client.PrependWatchReactor("configmaps", func(clienttesting.Action) (bool, watch.Interface, error) {
		w := watch.NewRaceFreeFake()
		watches <- w
		return true, w, nil
	})
	w, cfg, _ := startNamespaceFilterWatcher(t, client)
	waitForNamespaceFilters(t, w)
	var first, second *watch.RaceFreeFakeWatcher
	select {
	case first = <-watches:
	case <-time.After(5 * time.Second):
		t.Fatal("watch not started")
	}
	first.Stop()
	require.True(t, cfg.SkipNamespace("payments"))
	select {
	case second = <-watches:
	case <-time.After(10 * time.Second):
		t.Fatal("watch did not reconnect")
	}
	second.Modify(namespaceFilterCM(allowNamespaces))
	require.Eventually(t, func() bool { return !cfg.SkipNamespace("payments") }, 5*time.Second, 10*time.Millisecond)
}

func TestNamespaceFilterWatcherCancellationBeforeReady(t *testing.T) {
	w, _, _ := startNamespaceFilterWatcher(t, fake.NewSimpleClientset())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, w.WaitForReady(ctx), context.Canceled)
}
