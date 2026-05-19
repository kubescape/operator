package controllers

import (
	"sync"
	"time"
)

const defaultCooldown = 5 * time.Second

// CooldownQueue debounces keys and emits each key once after a quiet period.
type CooldownQueue struct {
	quietPeriod time.Duration
	resultCh    chan string
	wakeCh      chan struct{}
	closedCh    chan struct{}
	timer       *time.Timer

	mu      sync.Mutex
	pending map[string]time.Time
	stopped bool
	stopOnce sync.Once
}

// NewCooldownQueue creates a queue with the default quiet period.
func NewCooldownQueue() *CooldownQueue {
	return NewCooldownQueueWithParams(defaultCooldown)
}

// NewCooldownQueueWithParams creates a queue with a custom quiet period.
func NewCooldownQueueWithParams(quietPeriod time.Duration) *CooldownQueue {
	if quietPeriod <= 0 {
		quietPeriod = defaultCooldown
	}
	q := &CooldownQueue{
		quietPeriod: quietPeriod,
		resultCh:    make(chan string, 64),
		wakeCh:      make(chan struct{}, 1),
		closedCh:    make(chan struct{}),
		pending:     map[string]time.Time{},
	}
	q.timer = time.NewTimer(time.Hour)
	q.timer.Stop()
	go q.run()
	return q
}

// ResultChan returns the channel of debounced keys.
func (q *CooldownQueue) ResultChan() <-chan string {
	return q.resultCh
}

// Enqueue schedules a key to fire after the quiet period.
func (q *CooldownQueue) Enqueue(key string) {
	if key == "" {
		return
	}
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return
	}
	q.pending[key] = time.Now().Add(q.quietPeriod)
	q.mu.Unlock()

	q.signal()
}

// Stop stops the queue and closes the output channel.
func (q *CooldownQueue) Stop() {
	q.stopOnce.Do(func() {
		q.mu.Lock()
		q.stopped = true
		q.mu.Unlock()
		close(q.closedCh)
	})
}

func (q *CooldownQueue) signal() {
	select {
	case q.wakeCh <- struct{}{}:
	default:
	}
}

func (q *CooldownQueue) nextDeadline() (time.Time, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.pending) == 0 {
		return time.Time{}, false
	}

	var next time.Time
	for _, deadline := range q.pending {
		if next.IsZero() || deadline.Before(next) {
			next = deadline
		}
	}

	return next, true
}

func (q *CooldownQueue) fireDue(now time.Time) []string {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.pending) == 0 {
		return nil
	}

	keys := make([]string, 0, len(q.pending))
	for key, deadline := range q.pending {
		if !deadline.After(now) {
			keys = append(keys, key)
			delete(q.pending, key)
		}
	}

	return keys
}

func (q *CooldownQueue) run() {
	for {
		select {
		case <-q.closedCh:
			q.stopTimer()
			close(q.resultCh)
			return
		default:
		}

		next, ok := q.nextDeadline()
		if !ok {
			select {
			case <-q.wakeCh:
				continue
			case <-q.closedCh:
				q.stopTimer()
				close(q.resultCh)
				return
			}
		}

		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}

		q.resetTimer(wait)

		select {
		case <-q.timer.C:
			for _, key := range q.fireDue(time.Now()) {
				q.resultCh <- key
			}
		case <-q.wakeCh:
			continue
		case <-q.closedCh:
			q.stopTimer()
			close(q.resultCh)
			return
		}
	}
}

func (q *CooldownQueue) stopTimer() {
	if q.timer == nil {
		return
	}
	if !q.timer.Stop() {
		select {
		case <-q.timer.C:
		default:
		}
	}
}

func (q *CooldownQueue) resetTimer(d time.Duration) {
	if q.timer == nil {
		q.timer = time.NewTimer(d)
		return
	}
	q.stopTimer()
	q.timer.Reset(d)
}
