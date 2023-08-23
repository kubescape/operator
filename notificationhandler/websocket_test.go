package notificationhandler

import (
	"reflect"
	"testing"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/panjf2000/ants/v2"
)

func TestNewTriggerHandlerNotificationHandler(t *testing.T) {
	type args struct {
		pool *ants.PoolWithFunc
	}
	tests := []struct {
		name string
		args args
		want *NotificationHandler
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewNotificationHandler(tt.args.pool, utilsmetadata.ClusterConfig{}); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTriggerHandlerNotificationHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}
