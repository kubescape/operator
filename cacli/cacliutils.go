package cacli

import (
	"context"
	"encoding/json"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"
	"time"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetCALoginCred -
func GetCALoginCred() (cautils.CredStruct, error) {
	credStruct := cautils.CredStruct{}
	ctx := context.Background()
	sec, err := k8sworkloads.KubernetesClient.CoreV1().Secrets(cautils.CA_NAMESPACE).Get(ctx, cautils.CA_LOGIN_SECRET_NAME, metav1.GetOptions{})
	if err != nil {
		return credStruct, err
	}

	// Read secrets
	credStruct.User = string(sec.Data["username"])
	credStruct.Password = string(sec.Data["password"])
	if customer, ok := sec.Data["customer"]; ok {
		credStruct.Customer = string(customer)
	}

	glog.Infof("user name: %s", credStruct.User)
	return credStruct, nil
}

func runCacliCommandRepeat(arg []string, display bool, timeout time.Duration) ([]byte, error) {
	rep, err := runCacliCommand(arg, display, timeout)
	if err != nil {
		if !IsLoggedin() {
			glog.Infof("logging in again and retrying %d times", 3)
			if err := LoginCacli(); err != nil {
				return nil, err
			}
		}
		i := 0
		for i < 3 { // retry
			rep, err = runCacliCommand(arg, display, timeout)
			if err == nil {
				glog.Infof("cacli executed successfully")
				return rep, nil
			}
			i++
		}
		// glog.Errorf("stdout: %v. stderr:%v. err: %v", cmd.Stdout, cmd.Stderr, err)
		return nil, err
	}
	glog.Infof("cacli executed successfully")
	return rep, nil
}
func runCacliCommand(arg []string, display bool, timeout time.Duration) ([]byte, error) {
	return cautils.RunCommand("cacli", arg, display, timeout)
}

// StatusCacli -
func StatusCacli() (*Status, error) {
	cacliObj := Cacli{}
	return cacliObj.Status()
}

// LoginCacli -
func LoginCacli() error {
	cacliObj := Cacli{}
	cred, err := GetCALoginCred()
	if err != nil {
		return err
	}
	err = cacliObj.Login(cred)
	status, _ := cacliObj.Status()
	s, _ := json.Marshal(status)
	glog.Infof("%s", string(s))
	return err
}

// IsLoggedin test if logged in using the --status command
func IsLoggedin() bool {
	cacliObj := Cacli{}
	status, err := cacliObj.Status()
	if err != nil {
		glog.Errorf("IsLoggedin, %s", err.Error())
		return false
	}
	return status.LoggedIn
}
