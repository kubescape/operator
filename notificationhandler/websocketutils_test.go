package notificationhandler

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
)

var mockCommandRunKubescapeJob = `{"commands":[{"CommandName":"runKubescapeJob","responseID":"","jobTracking":{"jobID":"6be09aad-a376-4d6b-97ad-8d1a75fce89d","timestamp":"0001-01-01T00:00:00Z"},"args":{"kubescapeJobParams":{"clusterName":"dwertent","frameworkName":"DevOpsBest","jobID":"6be09aad-a376-4d6b-97ad-8d1a75fce89d"},"scanV1":{"targetNames":["DevOpsBest"],"targetType":"Framework"}},"designators":[{"designatorType":"","attributes":{"cluster":"dwertent"}}]}]}`

func TestParseNotificationCommand(t *testing.T) {
	cmd, err := parseNotificationCommand([]byte(mockCommandRunKubescapeJob))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(cmd.Commands))
	assert.Equal(t, apis.TypeRunKubescapeJob, cmd.Commands[0].CommandName)
}

// func Test_parseNotificationCommand(t *testing.T) {
// 	type args struct {
// 		notification interface{}
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		want    *apis.Commands
// 		wantErr bool
// 	}{
// 		// TODO: Add test cases.
// 		{
// 			name: "test",
// 			args: args{
// 				notification: []byte(mockCommandRunKubescapeJob),
// 			},
// 			want: &apis.Commands{

// 				[]apis.Command{
// 					apis.Command{
// 						CommandName: apis.TypeRunKubescapeJob,
// 						WildWlid:    "wlid://cluster-temp/namescpace-temp",
// 						JobTracking: apis.JobTracking{

// 						},
// 						Args: map[string]interface{}{
// 							apis.CommandDeprecatedArgsJobParams: map[string]interface{}{
// 							}
// 						},
// 					},
// 				},
// 			},
// 			wantErr: false,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, err := parseNotificationCommand(tt.args.notification)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("parseNotificationCommand() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("parseNotificationCommand() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }
