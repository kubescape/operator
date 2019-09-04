package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
)

const (
	// SIGNINGPROFILEPATH dir storing signing profiles
	SIGNINGPROFILEPATH = "/signing_profile"
)

type StatusResponse struct {
	Status  bool
	Message string
}
type Filter struct {
	IncludePaths      []string `json:"includePaths"`
	IncludeExtensions []string `json:"includeExtensions"`
}

type ModulesInfo struct {
	Name                    string `json:"name"`
	Mandatory               int    `json:"mandatory"`
	Version                 string `json:"version"`
	SignatureMismatchAction int    `json:"signatureMismatchAction"`
	Type                    int    `json:"type"`
}
type ExecutablesList struct {
	Filter      Filter        `json:"filter"`
	MainProcess string        `json:"mainProcess"`
	ModulesInfo []ModulesInfo `json:"modulesInfo"`
}

type Envelope struct {
	Component               string            `json:"component"`
	URL                     string            `json:"url"`
	Platform                int               `json:"platform"`
	Architecture            int               `json:"architecture"`
	ComponentType           int               `json:"componentType"`
	SignatureMismatchAction int               `json:"signatureMismatchAction"`
	ExecutablesList         []ExecutablesList `json:"executablesList"`
	ContainerName           string            `json:"containerName"`
	DockerImageTag          string            `json:"dockerImageTag"`
	DockerImageSHA256       string            `json:"dockerImageSHA256"`
	// TODO - Add to API
	StatusResponse StatusResponse `json:"statusResponse"`
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
			glog.Infof("Signig container %s, process %s", container, process)
			envelope := process.(map[string]interface{})

			finalProfile, err := json.Marshal(process)
			if err != nil {
				glog.Error(err)
				sr := StatusResponse{Status: false, Message: fmt.Sprintf("%v", err)}
				envelope["statusResponse"] = sr
				continue
			}
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
	fileName := fmt.Sprintf("%s/%s%s.cfg", SIGNINGPROFILEPATH, string(rand.Intn(100)), strconv.FormatInt(time.Now().Unix(), 10))
	sp := []byte(contetnt)
	err := ioutil.WriteFile(fileName, sp, 0644)
	return fileName, err
}

func runSigner(signigProfile, dockerImage string) error {
	/*
		casigner --docker_image_id <docker_image:tag>  --configuration_file <file.cfg>
	*/
	args := []string{}
	args = append(args, "--docker_image_id")
	args = append(args, dockerImage)
	args = append(args, "--configuration_file")
	args = append(args, signigProfile)

	// TODO use login cookie
	args = append(args, "--user_name")
	args = append(args, "system_tests@cyberarmor.io")
	args = append(args, "--password")
	args = append(args, "6hdGjPeHqgmzpjRmqXIA")

	glog.Infof(fmt.Sprintf("Executing casigner command: %s %v", "casigner", args))
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
