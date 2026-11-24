package mainhandler

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCommandResponseHandler() *MainHandler {
	cmdCh := make(chan *CommandResponseData, 10)
	timerCh := make(chan *timerData, 10)
	return &MainHandler{
		commandResponseChannel: &commandResponseChannelData{
			done:                                    make(chan struct{}),
			commandResponseChannel:                  &cmdCh,
			limitedGoRoutinesCommandResponseChannel: &timerCh,
		},
	}
}

func TestInsertNewCommandResponseData_NilGuards(t *testing.T) {
	mh := newTestCommandResponseHandler()
	delay := time.Millisecond

	assert.NotPanics(t, func() {
		insertNewCommandResponseData(context.Background(), nil, createNewCommandResponseData(KubescapeResponse, nil, nil, &delay))
		insertNewCommandResponseData(context.Background(), mh.commandResponseChannel, nil)
		insertNewCommandResponseData(context.Background(), mh.commandResponseChannel, createNewCommandResponseData(KubescapeResponse, nil, nil, nil))
	})

	assert.Empty(t, *mh.commandResponseChannel.limitedGoRoutinesCommandResponseChannel)
}

func TestHandleCommandResponse_RehandlesUntilComplete(t *testing.T) {
	mh := newTestCommandResponseHandler()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		mh.HandleCommandResponse(ctx)
	}()

	var calls atomic.Int32
	finished := make(chan struct{})
	cb := func(_ context.Context, _ config.IConfig, payload interface{}) (bool, *time.Duration) {
		assert.Equal(t, "scan-123", payload)
		if calls.Add(1) < 3 {
			next := 5 * time.Millisecond
			return true, &next
		}
		close(finished)
		return false, nil
	}

	delay := time.Millisecond
	insertNewCommandResponseData(context.Background(), mh.commandResponseChannel, createNewCommandResponseData(KubescapeResponse, cb, "scan-123", &delay))

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback to finish rehandling")
	}
	assert.Equal(t, int32(3), calls.Load())

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleCommandResponse did not exit after context cancellation")
	}
}

func TestHandleCommandResponse_NilDelayDoesNotPanic(t *testing.T) {
	mh := newTestCommandResponseHandler()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		mh.HandleCommandResponse(ctx)
	}()

	firstRan := make(chan struct{})
	firstCB := func(_ context.Context, _ config.IConfig, _ interface{}) (bool, *time.Duration) {
		close(firstRan)
		return true, nil
	}

	secondRan := make(chan struct{})
	secondCB := func(_ context.Context, _ config.IConfig, _ interface{}) (bool, *time.Duration) {
		close(secondRan)
		return false, nil
	}

	*mh.commandResponseChannel.commandResponseChannel <- createNewCommandResponseData(KubescapeResponse, firstCB, nil, nil)
	*mh.commandResponseChannel.commandResponseChannel <- createNewCommandResponseData(KubescapeResponse, secondCB, nil, nil)

	select {
	case <-firstRan:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first callback")
	}
	select {
	case <-secondRan:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for second callback after nil delay")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleCommandResponse did not exit after context cancellation")
	}
}

func TestHandleCommandResponse_ExitsPromptlyOnCancelWithPendingTimer(t *testing.T) {
	mh := newTestCommandResponseHandler()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		mh.HandleCommandResponse(ctx)
	}()

	longDelay := time.Hour
	insertNewCommandResponseData(context.Background(), mh.commandResponseChannel, createNewCommandResponseData(KubescapeResponse, func(_ context.Context, _ config.IConfig, _ interface{}) (bool, *time.Duration) {
		return false, nil
	}, nil, &longDelay))

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		require.Fail(t, "HandleCommandResponse hung on context cancellation")
	}
}

func TestHandleCommandResponse_ShutdownWithFullTimerQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mh := newTestCommandResponseHandler()
		queue := *mh.commandResponseChannel.limitedGoRoutinesCommandResponseChannel
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			mh.HandleCommandResponse(ctx)
		}()

		// Fill every worker and every buffer slot with timers that cannot expire during the test.
		var timers []*time.Timer
		for i := 0; i < MaxLimitationInsertToCommandResponseChannelGoRoutine+cap(queue); i++ {
			timer := time.NewTimer(time.Hour)
			defer timer.Stop()
			timers = append(timers, timer)
			select {
			case queue <- &timerData{timer: timer}:
			case <-time.After(time.Second):
				t.Fatal("timed out filling timer queue")
			}
		}
		delay := time.Hour
		inserted := make(chan struct{})
		go func() {
			defer close(inserted)
			insertNewCommandResponseData(context.Background(), mh.commandResponseChannel, createNewCommandResponseData(KubescapeResponse, nil, nil, &delay))
		}()
		synctest.Wait()
		select {
		case <-inserted:
			t.Fatal("insertion returned while queue was full")
		default:
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("handler did not exit")
		}
		select {
		case <-inserted:
		case <-time.After(time.Second):
			t.Error("insertion stayed blocked after shutdown")
		}
		assert.Empty(t, queue)
		for _, timer := range timers {
			assert.False(t, timer.Stop(), "timer still active after shutdown")
		}
		// A producer that arrives after shutdown must also return without queueing a timer.
		insertNewCommandResponseData(context.Background(), mh.commandResponseChannel, createNewCommandResponseData(KubescapeResponse, nil, nil, &delay))
		assert.Empty(t, queue)
	})
}
