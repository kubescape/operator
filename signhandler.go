package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// SIGNINGPROFILEPATH dir storing signing profiles
	SIGNINGPROFILEPATH = "/signing_profile"
)

var (
// globalLoginCredentials = getCALoginCred()
)

type StatusResponse struct {
	Status  bool
	Message string
}

// Filter holds the filter section of  ExecutablesList
type Filter struct {
	IncludePaths      []string `json:"includePaths"`
	IncludeExtensions []string `json:"includeExtensions"`
}

// ModulesInfo holds data of specific module in signing profile
type ModulesInfo struct {
	FullPath                string `json:"fullPath"`
	Name                    string `json:"name"`
	Mandatory               int    `json:"mandatory"`
	Version                 string `json:"version"`
	SignatureMismatchAction int    `json:"signatureMismatchAction"`
	Type                    int    `json:"type"`
}

// ExecutablesList holds the list of executables in this signing profile
type ExecutablesList struct {
	MainProcess                     string            `json:"mainProcess"`
	FullProcessCommandLine          string            `json:"fullProcessCommandLine"`
	FullProcessEnvironmentVariables map[string]string `json:"fullProcessEnvironmentVariables"`
	ModulesInfo                     []ModulesInfo     `json:"modulesInfo"`
	Filter                          Filter            `json:"filter"`
}

// Envelope is the external envelope of single signing profile
type Envelope struct {
	Component               string            `json:"component"`
	URL                     string            `json:"url"`
	Platform                int64             `json:"platform"`
	Architecture            int64             `json:"architecture"`
	ComponentType           int64             `json:"componentType"`
	SignatureMismatchAction int64             `json:"signatureMismatchAction"`
	ExecutablesList         []ExecutablesList `json:"executablesList"`
	ContainerName           string            `json:"containerName"`
	DockerImageTag          string            `json:"dockerImageTag"`
	DockerImageSHA256       string            `json:"dockerImageSHA256"`
	FullPathMap             map[string]bool   `json:"-"`
}

// CredStruct holds the various credentials needed to do login into CA BE
type CredStruct struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Customer string `json:"customer"`
}

func signImage(command Command, unstructuredObj *unstructured.Unstructured, kubeconfig *rest.Config) error {
	// Get containers info
	containersArgs, ok := command.Args["signingProfiles"]
	if !ok {
		glog.Error("Containers not found in args")
		return errors.New("containers not found in args")
	}
	successfullySigned := false
	for containerName, container := range containersArgs.(map[string]interface{}) {
		kubernetesData := kubernetesData{kubeconfig: kubeconfig, unstructuredObj: unstructuredObj}
		SetDockerClient(kubernetesData, containerName)
		for _, process := range container.(map[string]interface{}) {
			envelope := process.(map[string]interface{})

			finalProfile, err := json.Marshal(process)
			if err != nil {
				glog.Error(err)
				sr := StatusResponse{Status: false, Message: fmt.Sprintf("%v", err)}
				envelope["statusResponse"] = sr
				continue
			}
			glog.Infof("Signig container: %s\nsignig profile: %s", containerName, string(finalProfile))

			fileName, err := saveSigningProfileFile(finalProfile)
			if err != nil {
				glog.Error(err)
				sr := StatusResponse{Status: false, Message: fmt.Sprintf("%v", err)}
				envelope["statusResponse"] = sr
				continue
			}

			if err := runSigner(fileName, fmt.Sprintf("%v", envelope["dockerImageTag"])); err != nil {
				glog.Error(err)
				sr := StatusResponse{Status: false, Message: fmt.Sprintf("%v", err)}
				envelope["statusResponse"] = sr

			} else {
				sr := StatusResponse{Status: true}
				envelope["statusResponse"] = sr
				successfullySigned = true
			}

			deleteSignigProfile(fileName)
		}
	}

	if successfullySigned {
		return nil
	}

	return errors.New("did not sign any images")
}

func saveSigningProfileFile(contetnt json.RawMessage) (string, error) {
	fileName := fmt.Sprintf("%s/%s.cfg", SIGNINGPROFILEPATH, strconv.FormatInt(time.Now().Unix(), 10))
	sp := []byte(contetnt)
	err := ioutil.WriteFile(fileName, sp, 0644)
	return fileName, err
}

func runSigner(signigProfile, dockerImage string) error {
	/*
		casigner --docker_image_id <docker_image:tag>  --configuration_file <file.cfg>
	*/
	globalLoginCredentials := getCALoginCred()

	args := []string{}
	args = append(args, "--docker_image_id")
	args = append(args, dockerImage)
	args = append(args, "--configuration_file")
	args = append(args, signigProfile)

	args = append(args, "--user_name")
	args = append(args, globalLoginCredentials.User)
	args = append(args, "--password")
	glog.Infof(fmt.Sprintf("Executing casigner command: %s %v", "casigner", args))

	// Adding password after print that way the password will not be displayed
	args = append(args, globalLoginCredentials.Password)

	cmd := exec.Command("casigner", args...)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		glog.Errorf("signer stdout:\n%v\nsigner stderr:\n%v", outb.String(), errb.String())
		return err
	}
	glog.Infof("signer stdout:\n%v\nsigner stderr:\n%v", outb.String(), errb.String())

	return nil
}

func deleteSignigProfile(f string) {
	if err := os.Remove(f); err != nil {
		glog.Error(err)
	}
}

// get login credentials from kubernetes secret
func getCALoginCred() CredStruct {
	clientset, err := kubernetes.NewForConfig(cautils.LoadConfig())
	if err != nil {
		panic(err)
	}

	sec, err := clientset.CoreV1().Secrets(cautils.CA_NAMESPACE).Get(cautils.CA_LOGIN_SECRET_NAME, metav1.GetOptions{})
	if err != nil {
		glog.Errorf("Error reading secret.\nnamespace: %s,secret name: %s", cautils.CA_NAMESPACE, cautils.CA_LOGIN_SECRET_NAME)
		panic(err)
	}

	// Read secrets
	user := string(sec.Data["username"])
	psw := string(sec.Data["password"])
	customer := string(sec.Data["customer"])

	glog.Infof("Customer: %s, User: %s", customer, user)
	return CredStruct{Customer: customer, User: user, Password: psw}
}
