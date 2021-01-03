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
	GetWtTriple(wlid string) (*cautils.WorkloadTemplateTriple, error)
	GetSigningProfile(spName string) (*cautils.SigningProfile, error)
	Sign(wlid, user, password string) error
	Status() (stat *Status, err error)
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
	if globalLoginCredentials.Customer != "" {
		args = append(args, "-c")
		args = append(args, globalLoginCredentials.Customer)
	}
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

// GetSigningProfile command
// func (cacli *Cacli) GetSigningProfile(spName string) (*cautils.SigningProfile, error) {
func (cacli *Cacli) GetSigningProfile(spName string) (*cautils.SigningProfile, error) {
	sp := cautils.SigningProfile{}
	args := []string{}
	args = append(args, "sp")
	args = append(args, "get")
	args = append(args, "-n")
	args = append(args, spName)
	spReceive, err := runCacliCommandRepeate(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		err = json.Unmarshal(spReceive, &sp)
	}
	return sp, err
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

// GetWtTriple command
// func (cacli *Cacli) Get(wlid string) error {
func (cacli *Cacli) GetWtTriple(wlid string) (*cautils.WorkloadTemplateTriple, error) {
	wt := cautils.WorkloadTemplateTriple{}
	args := []string{}
	args = append(args, "wt")
	args = append(args, "triplet")
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
	args = append(args, "wt")
	args = append(args, "sign")
	args = append(args, "-wlid")
	args = append(args, wlid)

	if !cautils.CA_USE_DOCKER {
		args = append(args, "--dockerless-service-url")
		args = append(args, cautils.CA_OCIMAGE_URL)
	}

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

// Status -
func (cacli *Cacli) Status() (*Status, error) {
	status := &Status{}
	args := []string{}
	args = append(args, "--status")
	statusReceive, err := runCacliCommand(args, true, time.Duration(1)*time.Minute)
	if err == nil {
		err = json.Unmarshal(statusReceive, status)
	}
	return status, err
}
