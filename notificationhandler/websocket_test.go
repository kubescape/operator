package notificationhandler

import (
	"k8s-ca-websocket/utils"
	"reflect"
	"testing"
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
			if got := NewTriggerHandlerNotificationHandler(tt.args.sessionObj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTriggerHandlerNotificationHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}
