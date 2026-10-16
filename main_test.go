package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestHandleAdmissionExit(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		stop bool
	}{
		{"canceled", canceled, context.Canceled, false},
		{"http closed", context.Background(), http.ErrServerClosed, false},
		{"runtime failure", context.Background(), errors.New("listen failed"), true},
		{"unexpected nil exit", context.Background(), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopped := false
			handleAdmissionExit(tc.ctx, tc.err, func() { stopped = true })
			if stopped != tc.stop {
				t.Fatalf("stop=%v want %v", stopped, tc.stop)
			}
		})
	}
}
