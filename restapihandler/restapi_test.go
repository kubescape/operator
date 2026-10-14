package restapihandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListenAddress(t *testing.T) {
	tests := []struct {
		name        string
		bindAddress string
		port        string
		want        string
	}{
		{name: "empty address binds every interface", bindAddress: "", port: "4002", want: ":4002"},
		{name: "loopback", bindAddress: "127.0.0.1", port: "4002", want: "127.0.0.1:4002"},
		{name: "ipv6 loopback is bracketed", bindAddress: "::1", port: "4002", want: "[::1]:4002"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, listenAddress(tt.bindAddress, tt.port))
		})
	}
}
