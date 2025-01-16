package watcher

import (
	"errors"
	"strings"
	"sync"
	"time"

	"istio.io/pkg/cache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	defaultExpiration = 5 * time.Second
	evictionInterval  = 1 * time.Second
)

// CooldownQueue is a queue that lets clients put events into it with a cooldown
//
// When a client puts an event into a queue, it waits for a cooldown period before
// the event is forwarded to the consumer. If an event for the same key is put into the queue
// again before the cooldown period is over, the event is overridden and the cooldown period is reset.
type CooldownQueue struct {
	closed     bool
	mu         sync.Mutex  // mutex for closed
	chanMu     *sync.Mutex // mutex for innerChan
	seenEvents cache.ExpiringCache
	innerChan  chan watch.Event
	ResultChan <-chan watch.Event
}

// NewCooldownQueue returns a new Cooldown Queue
func NewCooldownQueue() *CooldownQueue {
	return NewCooldownQueueWithParams(defaultExpiration, evictionInterval)
}

func NewCooldownQueueWithParams(expiration, interval time.Duration) *CooldownQueue {
	events := make(chan watch.Event)
	chanMu := sync.Mutex{}
	callback := func(key, value any) {
		chanMu.Lock()
		defer chanMu.Unlock()
		events <- value.(watch.Event)
	}
	c := cache.NewTTLWithCallback(expiration, interval, callback)
	return &CooldownQueue{
		chanMu:     &chanMu,
		seenEvents: c,
		innerChan:  events,
		ResultChan: events,
	}
}

// makeEventKey creates a unique key for an event from a watcher
func makeEventKey(e watch.Event) (string, error) {
	gvk := e.Object.GetObjectKind().GroupVersionKind()
	meta, ok := e.Object.(metav1.Object)
	if !ok {
		return "", errors.New("object does not implement metav1.Object")
	}
	return strings.Join([]string{gvk.Group, gvk.Version, gvk.Kind, meta.GetNamespace(), meta.GetName()}, "/"), nil
}

func (q *CooldownQueue) Closed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closed
}

// Enqueue enqueues an event in the Cooldown Queue
func (q *CooldownQueue) Enqueue(e watch.Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	eventKey, err := makeEventKey(e)
	if err != nil {
		return
	}
	q.seenEvents.Set(eventKey, e)
}

func (q *CooldownQueue) Stop() {
	q.chanMu.Lock()
	defer q.chanMu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	close(q.innerChan)
}
