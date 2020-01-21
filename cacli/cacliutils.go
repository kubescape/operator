package cacli

import (
	"bytes"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"
	"os/exec"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetCALoginCred -
func GetCALoginCred() (cautils.CredStruct, error) {
	credStruct := cautils.CredStruct{}
	clientset, err := kubernetes.NewForConfig(k8sworkloads.GetK8sConfig())
	if err != nil {
		return credStruct, err
	}

	sec, err := clientset.CoreV1().Secrets(cautils.CA_NAMESPACE).Get(cautils.CA_LOGIN_SECRET_NAME, metav1.GetOptions{})
	if err != nil {
		return credStruct, err
	}

	// Read secrets
	credStruct.User = string(sec.Data["username"])
	credStruct.Password = string(sec.Data["password"])
	credStruct.Customer = string(sec.Data["customer"])

	glog.Infof("Customer: %s, user name: %s", credStruct.Customer, credStruct.User)
	return credStruct, nil
}

func runCacliCommandRepeate(arg []string, display bool) ([]byte, error) {
	cmd, err := runCacliCommand(arg, display)
	if err != nil {
		if err := LoginCacli(); err != nil {
			return nil, err
		}
		cmd, err = runCacliCommand(arg, display)
		if err != nil {
			glog.Errorf("cacli stdout: %v\ncacli stderr:%v,\nerr: %v", cmd.Stdout, cmd.Stderr, err)
			return cmd.Stderr.(*bytes.Buffer).Bytes(), err
		}
	}
	glog.Infof("cacli executed successfully")
	return cmd.Stdout.(*bytes.Buffer).Bytes(), nil
}
func runCacliCommand(arg []string, display bool) (*exec.Cmd, error) {
	return cautils.RunCommand("cacli", arg, display)
}

// LoginCacli -
func LoginCacli() error {
	cacliObj := Cacli{}
	cred, err := GetCALoginCred()
	if err != nil {
		return err
	}
	return cacliObj.Login(cred)
}
