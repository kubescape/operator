package controllers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCooldownQueue(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "single enqueue fires",
			run: func(t *testing.T) {
				queue := NewCooldownQueueWithParams(20 * time.Millisecond)
				defer queue.Stop()

				queue.Enqueue("alpha")

				select {
				case key := <-queue.ResultChan():
					assert.Equal(t, "alpha", key)
				case <-time.After(200 * time.Millisecond):
					t.Fatalf("timed out waiting for key")
				}
			},
		},
		{
			name: "coalesces rapid enqueues",
			run: func(t *testing.T) {
				queue := NewCooldownQueueWithParams(30 * time.Millisecond)
				defer queue.Stop()

				queue.Enqueue("alpha")
				time.Sleep(10 * time.Millisecond)
				queue.Enqueue("alpha")
				time.Sleep(10 * time.Millisecond)
				queue.Enqueue("alpha")

				select {
				case key := <-queue.ResultChan():
					assert.Equal(t, "alpha", key)
				case <-time.After(200 * time.Millisecond):
					t.Fatalf("timed out waiting for key")
				}

				select {
				case key := <-queue.ResultChan():
					t.Fatalf("unexpected second key: %s", key)
				case <-time.After(80 * time.Millisecond):
				}
			},
		},
		{
			name: "different keys are independent",
			run: func(t *testing.T) {
				queue := NewCooldownQueueWithParams(20 * time.Millisecond)
				defer queue.Stop()

				queue.Enqueue("alpha")
				queue.Enqueue("bravo")

				received := map[string]struct{}{}
				deadline := time.After(200 * time.Millisecond)

				for len(received) < 2 {
					select {
					case key := <-queue.ResultChan():
						received[key] = struct{}{}
					case <-deadline:
						t.Fatalf("timed out waiting for keys")
					}
				}

				_, hasAlpha := received["alpha"]
				_, hasBravo := received["bravo"]
				assert.True(t, hasAlpha)
				assert.True(t, hasBravo)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
