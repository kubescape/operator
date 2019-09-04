package main

import (
	"encoding/json"
	"time"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/restmapper"
)

// Commands list of commands received from websocket
type Commands struct {
	Commands []Command `json:"commands"`
}

// Command structure of command received from websocket
type Command struct {
	CommandName string                 `json:"commandName"`
	ResponseID  string                 `json:"responseID"`
	Args        map[string]interface{} `json:"args"`
}

// Containers to sign
type Containers struct {
	Containers []SignigProfile `json:"containers"`
}

// SignigProfile container name and profile
type SignigProfile struct {
	Name           string `json:"name"`
	SigningProfile string `json:"signingProfile"`
}

var (
	// CREATE workload
	CREATE = "create"
	// UPDATE workload
	UPDATE = "update"
	// DELETE workload
	DELETE = "delete"
	// SIGN image
	SIGN = "sign"
)

type patchUpdate struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// HandlePostmanRequest Parse received commands and run the command
func (wsh *WebSocketHandler) HandlePostmanRequest(receivedCommands []byte) error {
	glog.Infof("\n ================== Starting CyberArmor websocket!! ================== \n")
	// log.Printf("Recveived: %v", string(receivedCommands))
	commands := Commands{}

	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
		glog.Infof("\n ================== Failed CyberArmor websocket!! ================== \n")
		return err
	}
	for _, c := range commands.Commands {
		return wsh.runCommand(c)
	}
	glog.Infof("\n ================== Done CyberArmor websocket!! ================== \n")
	return nil

}
func (wsh *WebSocketHandler) runCommand(c Command) error {
	resJSON, ok := c.Args["json"]
	if !ok {
		glog.Error("Json not found in args")
		return nil
	}
	res, unstruct, err := wsh.getWorkloadResource(resJSON.(string))
	if err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("Received %s command", c.CommandName)
	switch c.CommandName {
	case CREATE:
		createWorkload(res, &unstruct)
	case UPDATE:
		updateWorkload(res, &unstruct)
	case DELETE:
		deleteWorkload(res, &unstruct)
	case SIGN:
		if err := signImage(c, &unstruct, wsh.kubeconfig); err == nil {
			glog.Infof("Done signig, updating workload. Kind: %s, Name: %s", unstruct.GetKind(), unstruct.GetName())
			updateWorkload(res, &unstruct)
		}
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func (wsh *WebSocketHandler) getWorkloadResource(resJSON string) (resource dynamic.ResourceInterface, unstructuredObj unstructured.Unstructured, err error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode

	obj, gvk, err := decode([]byte(resJSON), nil, nil)
	if err != nil {
		return resource, unstructuredObj, err
	}
	dynClient, err := dynamic.NewForConfig(wsh.kubeconfig)
	if err != nil {
		return resource, unstructuredObj, err
	}
	clientset, err := kubernetes.NewForConfig(wsh.kubeconfig)
	if err != nil {
		return resource, unstructuredObj, err
	}
	gk := schema.GroupKind{Group: gvk.Group, Kind: gvk.Kind}
	groupResources, err := restmapper.GetAPIGroupResources(clientset.Discovery())
	if err != nil {
		return resource, unstructuredObj, err
	}
	rm := restmapper.NewDiscoveryRESTMapper(groupResources)
	mapping, err := rm.RESTMapping(gk, gvk.Version)
	if err != nil {
		return resource, unstructuredObj, err
	}

	unstructur, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	unstructuredObj = unstructured.Unstructured{Object: unstructur}
	namespace := unstructuredObj.GetNamespace()
	if namespace == "" {
		namespace = "default"
	}
	resource = dynClient.Resource(mapping.Resource).Namespace(namespace)

	return resource, unstructuredObj, nil
}

func updateWorkload(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {

	if unstructuredObj.GetKind() == "Pod" {
		return updatePod(resource, unstructuredObj)
	}
	return updateAbstract(resource, unstructuredObj)
}

func createWorkload(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {
	_, err := resource.Create(unstructuredObj, metav1.CreateOptions{})
	if err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("Workload created successfully")
	return nil
}

func updatePod(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {
	if err := deleteWorkload(resource, unstructuredObj); err != nil {
		glog.Error(err)
		return err
	}
	name := unstructuredObj.GetName()
	// Wait for pod to delete
	for {
		if _, err := resource.Get(name, metav1.GetOptions{}); err != nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err := createWorkload(resource, unstructuredObj); err != nil {
		glog.Error(err)
		return err
	}
	return nil
}

func updateAbstract(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {
	// Get current annotations
	annotations, found, err := unstructured.NestedStringMap(unstructuredObj.Object, "spec", "template", "metadata", "annotations")
	if err != nil {
		glog.Errorf("Error receiving annotations: %s", err)
	}
	if !found {
		annotations = make(map[string]string)
	}

	tm := time.Now().UTC()
	annotations["last-update"] = string(tm.Format("02-01-2006 15:04:05"))
	unstructured.SetNestedStringMap(unstructuredObj.Object, annotations, "spec", "template", "metadata", "annotations")
	ob, err := resource.Get(unstructuredObj.GetName(), metav1.GetOptions{})
	if err != nil {
		glog.Error(err)
		return err
	}

	unstructuredObj.SetResourceVersion(ob.GetResourceVersion())

	_, err = resource.Update(unstructuredObj, metav1.UpdateOptions{})
	if err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("Workload updated successfully")
	return nil
}
func deleteWorkload(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {
	d := metav1.DeletePropagationBackground
	err := resource.Delete(unstructuredObj.GetName(), &metav1.DeleteOptions{PropagationPolicy: &d})
	if err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("Workload deleted successfully")
	return nil
}
