package cacli

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"time"

	"github.com/armosec/capacketsgo/secrethandling"

	"github.com/golang/glog"
)

// ICacli commands
type ICacli interface {
	Login(globalLoginCredentials cautils.CredStruct) error
	Get(wlid string) (cautils.WorkloadTemplate, error)
	GetWtTriple(wlid string) (*cautils.WorkloadTemplateTriple, error)
	GetSigningProfile(spName string) (*cautils.SigningProfile, error)
	Sign(wlid, user, password string, debug bool) error
	Status() (stat *Status, err error)

	SecretMetadata(string) (*SecretMetadata, error)
	SecretEncrypt(message, inputFile, outputFile, keyID string, base64Enc bool) ([]byte, error)
	SecretDecrypt(message, inputFile, outputFile string, base64Enc bool) ([]byte, error)
	GetKey(string) (*cautils.Key, error)
	GetSecretAccessPolicy(sid, name, cluster, namespace string) ([]secrethandling.SecretAccessPolicy, error)
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

func (cacli *Cacli) RunPostureScan(framework, cluster string) error {
	args := []string{}
	// cacli k8s posture create --framework "MITRE" --cluster childrenofbodom

	args = append(args, "k8s")
	args = append(args, "posture")
	args = append(args, "create")
	args = append(args, "--cluster")
	args = append(args, cluster)
	args = append(args, "--framework")
	args = append(args, framework)
	res, err := runCacliCommandRepeat(args, false, time.Duration(2)*time.Minute)
	if err != nil {
		return err
	}
	glog.Infof("%v", string(res))
	return nil

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
	spReceive, err := runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		err = json.Unmarshal(spReceive, &sp)
	}
	return &sp, err
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
	wtReceive, err := runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
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
	wtReceive, err := runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(wtReceive, &wt)
	}
	return &wt, err
}

// Sign command
func (cacli *Cacli) Sign(wlid, user, password string, debug bool) error {
	args := []string{}
	display := true
	args = append(args, "--debug")
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

// SecretMetadata -
func (cacli *Cacli) SecretMetadata(message string) (*SecretMetadata, error) {
	secretMetadata := &SecretMetadata{}
	args := []string{}
	args = append(args, "secret-policy")
	args = append(args, "decrypt")
	if message != "" {
		args = append(args, "--message")
		args = append(args, message)
	}
	args = append(args, "--display-metadata")
	// args = append(args, "--base64")

	statusReceive, err := runCacliCommand(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(statusReceive, secretMetadata)
	}
	return secretMetadata, err
}

// GetKey -
func (cacli *Cacli) GetKey(keyID string) (*cautils.Key, error) {
	key := &cautils.Key{}
	args := []string{}
	args = append(args, "key")
	args = append(args, "get")
	args = append(args, "-id")
	args = append(args, keyID)
	wtReceive, err := runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(wtReceive, key)
		if key.Key == "" {
			return key, fmt.Errorf("user does not have key permissions")
		}
	}
	return key, err
}

// SecretEncrypt -
func (cacli *Cacli) SecretEncrypt(message, inputFile, outputFile, keyID string, base64Enc bool) ([]byte, error) {
	args := []string{}
	args = append(args, "secret-policy")
	args = append(args, "encrypt")
	if message != "" {
		args = append(args, "--message")
		args = append(args, message)
	}
	if inputFile != "" {
		args = append(args, "--input")
		args = append(args, inputFile)
	}
	if keyID != "" {
		args = append(args, "-kid")
		args = append(args, keyID)
	}
	if outputFile != "" {
		args = append(args, "--output")
		args = append(args, outputFile)
	}
	if base64Enc {
		args = append(args, "--base64")
	}

	messageByte, err := runCacliCommand(args, false, time.Duration(2)*time.Minute)
	return messageByte, err
}

// SecretDecrypt -
func (cacli *Cacli) SecretDecrypt(message, inputFile, outputFile string, base64Enc bool) ([]byte, error) {
	args := []string{}
	args = append(args, "secret-policy")
	args = append(args, "decrypt")
	if message != "" {
		args = append(args, "--message")
		args = append(args, message)
	}
	if inputFile != "" {
		args = append(args, "--input")
		args = append(args, inputFile)
	}
	if outputFile != "" {
		args = append(args, "--output")
		args = append(args, outputFile)
	}
	if base64Enc {
		args = append(args, "--base64")
	}

	messageByte, err := runCacliCommand(args, true, time.Duration(2)*time.Minute)

	return messageByte, err
}

// GetSecretAccessPolicy -
func (cacli *Cacli) GetSecretAccessPolicy(sid, name, cluster, namespace string) ([]secrethandling.SecretAccessPolicy, error) {
	secretAccessPolicy := []secrethandling.SecretAccessPolicy{}
	args := []string{}
	args = append(args, "secret-policy")
	args = append(args, "get")
	if sid != "" {
		args = append(args, "-sid")
		args = append(args, sid)
	} else if name != "" {
		args = append(args, "--name")
		args = append(args, name)
	} else {
		if cluster != "" {
			args = append(args, "--cluster")
			args = append(args, cluster)
			if namespace != "" {
				args = append(args, "--namespace")
				args = append(args, namespace)
			}
		}
	}
	sReceive, err := runCacliCommandRepeat(args, true, 2*time.Minute)
	if err == nil {
		if err = json.Unmarshal(sReceive, &secretAccessPolicy); err != nil {
			tmpSecretAccessPolicy := secrethandling.SecretAccessPolicy{}
			if err = json.Unmarshal(sReceive, &tmpSecretAccessPolicy); err == nil {
				secretAccessPolicy = []secrethandling.SecretAccessPolicy{tmpSecretAccessPolicy}
			}
		}
		err = nil // if received and empty list
	}
	return secretAccessPolicy, err
}
