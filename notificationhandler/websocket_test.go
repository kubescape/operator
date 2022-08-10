package notificationhandler

import (
	"reflect"
	"testing"

	"github.com/kubescape/kontroller/utils"
)

func TestNewTriggerHandlerNotificationHandler(t *testing.T) {
	type args struct {
		sessionObj *chan utils.SessionObj
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
			if got := NewNotificationHandler(tt.args.sessionObj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTriggerHandlerNotificationHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}
