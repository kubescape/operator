package continuousscanning

import (
	"context"
	"testing"

	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/watcher"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type namespaceEventRecorder struct{ namespaces []string }

func (r *namespaceEventRecorder) Handle(_ context.Context, e watch.Event) error {
	r.namespaces = append(r.namespaces, e.Object.(metav1.Object).GetNamespace())
	return nil
}

func TestNamespaceFilterRecheckedAfterQueue(t *testing.T) {
	cfg, err := config.NewOperatorConfig(config.CapabilitiesConfig{}, armometadata.ClusterConfig{}, nil, config.Config{})
	require.NoError(t, err)
	r := &namespaceEventRecorder{}
	for _, doc := range []string{
		`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[]}`,
	} {
		events := make(chan watch.Event, 1)
		events <- watch.Event{Type: watch.Added, Object: makePod("payments", "api", "")}
		close(events)
		_, err := cfg.UpdateNamespaceFilters([]byte(doc))
		require.NoError(t, err)
		s := &ContinuousScanningService{cfg: cfg, eventQueue: &watcher.CooldownQueue{ResultChan: events}, workDone: make(chan struct{}), eventHandlers: []EventHandler{r}}
		s.work(context.Background())
	}
	require.Equal(t, []string{"payments"}, r.namespaces)
}
