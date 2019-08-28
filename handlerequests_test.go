package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

var (
	sleepYamPlod   = `{"apiVersion": "v1","kind": "Pod","metadata": {"name": "sleep", "labels":{"app": "sl"}, "namespace": "default","annotations": {"caGUIDs": "{\"customerGUID\":\"1e3a88bf-92ce-44f8-914e-cbe71830d566\",\"solutionGUID\":\"6a16b37a-dd55-4b43-91fe-e87b7c296aae\",\"componentGUID\":\"17601a7e-2d28-4b6a-9193-66f06e5ad5d3\"}"}},"spec": {"containers": [{"name": "sleep","image": "tutum/curl","command": ["/bin/sleep","infinity"],"imagePullPolicy": "Always","env": [{"name": "ENV_VAR","value": "i/love/sleeping"}]}]}}`
	demoDeployment = `{"apiVersion": "apps/v1","kind":"Deployment","metadata": {"name": "demo-deployment"},"spec": {"replicas": 2,"selector":{"matchLabels": {"app": "demo"}},"template":{"metadata":{"labels":{"app": "demo"},"annotations": {"caGUIDs": "{\"customerGUID\":\"1e3a88bf-92ce-44f8-914e-cbe71830d566\",\"solutionGUID\":\"6a16b37a-dd55-4b43-91fe-e87b7c296aae\",\"componentGUID\":\"17601a7e-2d28-4b6a-9193-66f06e5ad5d3\"}"}},"spec": {"containers": [{"name":  "web","image": "nginx:1.12","ports":[{"name":"http","protocol":"TCP","containerPort": 80}]}]}}}}`
)

func EmulateCommand(c string, jsonStr string) (command Command) {
	command.CommandName = c
	command.ResponseID = "1234"
	command.Args = map[string]interface{}{"json": fmt.Sprint(jsonStr)}

	return command
}

func EmulateCommands(cs []string, jsonStr string) Commands {
	var commands []Command
	for _, c := range cs {
		commands = append(commands, EmulateCommand(c, jsonStr))
	}
	return Commands{commands}
}

func EmulateReceiveCommandFromWS(cs []string, jsonStr string) ([]byte, error) {
	return json.Marshal(EmulateCommands(cs, jsonStr))
}

func TestReceiveData(t *testing.T) {
	c := []string{"create", "update", "delete"}
	receivedCommands, _ := EmulateReceiveCommandFromWS(c, sleepYamPlod)
	commands := Commands{}
	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		t.Errorf("%v", err)
	}
	if commands.Commands[0].ResponseID != "1234" {
		t.Errorf("Wrong data")
	}
}

func TestCreatePod(t *testing.T) {
	wsh := WebSocketHandler{kubeconfig: loadConfig()}
	c := EmulateCommand("create", sleepYamPlod)

	res, unstruct, err := wsh.getWorkloadResource(c.Args["json"].(string))
	if err != nil {
		t.Errorf("%#v", err)
	}

	if err := createWorkload(res, &unstruct); err != nil {
		t.Errorf("%#v", err)
	}
}

func TestCreateDeployment(t *testing.T) {
	wsh := WebSocketHandler{kubeconfig: loadConfig()}
	c := EmulateCommand("create", demoDeployment)

	res, unstruct, err := wsh.getWorkloadResource(c.Args["json"].(string))
	if err != nil {
		t.Errorf("%#v", err)
	}

	if err := createWorkload(res, &unstruct); err != nil {
		t.Errorf("%#v", err)
	}
}
func TestUpdatePod(t *testing.T) {
	wsh := WebSocketHandler{kubeconfig: loadConfig()}
	c := EmulateCommand("update", sleepYamPlod)

	res, unstruct, err := wsh.getWorkloadResource(c.Args["json"].(string))
	if err != nil {
		t.Errorf("%#v", err)
	}

	if err := updateWorkload(res, &unstruct); err != nil {
		t.Errorf("%#v", err)
	}

}

func TestUpdateDeployment(t *testing.T) {
	wsh := WebSocketHandler{kubeconfig: loadConfig()}
	c := EmulateCommand("update", demoDeployment)

	res, unstruct, err := wsh.getWorkloadResource(c.Args["json"].(string))
	if err != nil {
		t.Errorf("%#v", err)
	}

	if err := updateWorkload(res, &unstruct); err != nil {
		t.Errorf("%#v", err)
	}

}
