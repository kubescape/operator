package watcher

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
)

type nonMetaObject struct{}

func (n *nonMetaObject) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

func (n *nonMetaObject) DeepCopyObject() runtime.Object {
	return n
}

var (
	configmap       = unstructured.Unstructured{Object: map[string]interface{}{"kind": "ConfigMap", "metadata": map[string]interface{}{"uid": "748ad4a8-e5ff-44da-ba94-309992c97820"}}}
	deployment      = unstructured.Unstructured{Object: map[string]interface{}{"kind": "Deployment", "metadata": map[string]interface{}{"uid": "6b1a0c50-277f-4aa1-a4f9-9fc278ce4fe2"}}}
	pod             = unstructured.Unstructured{Object: map[string]interface{}{"kind": "Pod", "metadata": map[string]interface{}{"uid": "aa5e3e8f-2da5-4c38-93c0-210d3280d10f"}}}
	deploymentAdded = watch.Event{Type: watch.Added, Object: &deployment}
	podAdded        = watch.Event{Type: watch.Added, Object: &pod}
	podModified     = watch.Event{Type: watch.Modified, Object: &pod}
)

func TestCooldownQueue_Enqueue(t *testing.T) {
	tests := []struct {
		name      string
		inEvents  []watch.Event
		outEvents []watch.Event
	}{
		{
			name:      "add pod",
			inEvents:  []watch.Event{deploymentAdded, podAdded, podModified, podModified, podModified},
			outEvents: []watch.Event{deploymentAdded, podModified},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := NewCooldownQueue()
			go func() {
				time.Sleep(10 * time.Second)
				q.Stop()
			}()
			for _, e := range tt.inEvents {
				time.Sleep(50 * time.Millisecond) // need to sleep to preserve order since the insertion is async
				q.Enqueue(e)
			}
			var outEvents []watch.Event
			for e := range q.ResultChan {
				outEvents = append(outEvents, e)
			}
			// sort outEvents to make the comparison easier
			sort.Slice(outEvents, func(i, j int) bool {
				uidI := outEvents[i].Object.(*unstructured.Unstructured).GetUID()
				uidJ := outEvents[j].Object.(*unstructured.Unstructured).GetUID()
				return uidI < uidJ
			})
			assert.Equal(t, tt.outEvents, outEvents)
		})
	}
}

func TestCooldownQueue_Enqueue_InvalidObject(t *testing.T) {
	q := NewCooldownQueueWithParams(100*time.Millisecond, 50*time.Millisecond)
	defer q.Stop()

	invalidEvent := watch.Event{
		Type:   watch.Added,
		Object: &nonMetaObject{},
	}

	assert.NotPanics(t, func() {
		q.Enqueue(invalidEvent)
	})

	select {
	case e := <-q.ResultChan:
		t.Fatalf("expected no events, got: %v", e)
	case <-time.After(250 * time.Millisecond):
		// Success, invalid event was dropped without panicking
	}
}

// key is only based on the UID of the object
func Test_makeEventKey(t *testing.T) {
	tests := []struct {
		name    string
		e       watch.Event
		want    string
		wantErr bool
	}{
		{
			name: "add pod",
			e: watch.Event{
				Type:   watch.Added,
				Object: &pod,
			},
			want: "//Pod//",
		},
		{
			name: "delete deployment",
			e: watch.Event{
				Type:   watch.Deleted,
				Object: &deployment,
			},
			want: "//Deployment//",
		},
		{
			name: "modify configmap",
			e: watch.Event{
				Type:   watch.Modified,
				Object: &configmap,
			},
			want: "//ConfigMap//",
		},
		{
			name: "object does not implement metav1.Object",
			e: watch.Event{
				Type:   watch.Added,
				Object: &nonMetaObject{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := makeEventKey(tt.e)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
