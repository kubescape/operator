package cacli

import (
	"encoding/json"
	"k8s-ca-websocket/cautils"
	"time"

	"github.com/golang/glog"
)

// ICacli commands
type ICacli interface {
	Login(globalLoginCredentials cautils.CredStruct) error
	Get(wlid string) (cautils.WorkloadTemplate, error)
	Sign(wlid, user, password string) error
}

// Cacli commands
type Cacli struct {
}

// NewCacli -
func NewCacli() *Cacli {
	return &Cacli{}
}

// Login command
func (cacli *Cacli) Login(globalLoginCredentials cautils.CredStruct) error {
	args := []string{}
	args = append(args, "login")
	args = append(args, "-u")
	args = append(args, globalLoginCredentials.User)
	args = append(args, "-c")
	args = append(args, globalLoginCredentials.Customer)
	args = append(args, "--dashboard")
	args = append(args, cautils.CA_DASHBOARD_BACKEND)

	if cautils.CA_IGNORE_VERIFY_CACLI {
		args = append(args, "--skip-verify-certificate")
	}

	args = append(args, "-p")
	args = append(args, globalLoginCredentials.Password)

	// args = append(args, "-e")
	// args = append(args, "development")
	glog.Infof("Running: cacli %v", args[:len(args)-1])

	_, err := runCacliCommand(args, false, time.Duration(2)*time.Minute)
	return err
}

// Get command
// func (cacli *Cacli) Get(wlid string) error {
func (cacli *Cacli) Get(wlid string) (cautils.WorkloadTemplate, error) {
	wt := cautils.WorkloadTemplate{}
	args := []string{}
	args = append(args, "wt")
	args = append(args, "get")
	args = append(args, "-wlid")
	args = append(args, wlid)
	wtReceive, err := runCacliCommandRepeate(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(wtReceive, &wt)
	}
	return wt, err
}

// Sign command
func (cacli *Cacli) Sign(wlid, user, password string) error {
	args := []string{}
	display := true
	args = append(args, "sign")
	args = append(args, "-wlid")
	args = append(args, wlid)
	args = append(args, "--dockerless-service-url")
	args = append(args, cautils.CA_OCIMAGE_URL)
	args = append(args, "--bypass_accelerator")

	if user != "" && password != "" {
		display = false
		args = append(args, "--docker-registry-user")
		args = append(args, user)
		args = append(args, "--docker-registry-password")
		args = append(args, password)
	}

	_, err := runCacliCommand(args, display, time.Duration(8)*time.Minute)
	return err
}
