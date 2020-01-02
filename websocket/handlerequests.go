package websocket

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"
	"k8s-ca-websocket/sign"
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

// HandlePostmanRequest Parse received commands and run the command
func (wsh *WebSocketHandler) HandlePostmanRequest(receivedCommands []byte) []error {
	// log.Printf("Recveived: %v", string(receivedCommands))
	commands := cautils.Commands{}
	errorList := []error{}

	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
		glog.Infoln("Failed CyberArmor websocket")
		return []error{err}
	}
	for _, c := range commands.Commands {
		go func(c cautils.Command) {
			glog.Infof(" ================== Starting CyberArmor websocket, command: %s ================== ", c.CommandName)
			glog.Infof("Running %s command", c.CommandName)
			if err := wsh.runCommand(c); err != nil {
				glog.Errorf("%v", err)
				glog.Infof("----------------- Failed CyberArmor websocket, command: %s  -----------------", c.CommandName)
				errorList = append(errorList, err)
			}
			glog.Infof(" ================== Done CyberArmor websocket, command: %s ================== ", c.CommandName)
		}(c)
	}
	return errorList
}
func (wsh *WebSocketHandler) runCommand(c cautils.Command) error {
	glog.Infof("Wlid: %s", c.Wlid)

	resJSON, ok := c.Args["json"]
	if !ok {
		return fmt.Errorf("Json not found in args")
	}

	message, _ := json.Marshal(resJSON)
	glog.Infof("received:\n%s", string(message))

	res, unstruct, err := wsh.getWorkloadResource(resJSON.(string))
	if err != nil {
		return err
	}

	switch c.CommandName {
	case CREATE:
		return createWorkload(res, &unstruct)
	case UPDATE:
		return updateWorkload(res, &unstruct)
	case DELETE:
		return deleteWorkload(res, &unstruct)
	case SIGN:
		return signWorkload(res, &unstruct, c.Wlid)

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
	dynClient, err := dynamic.NewForConfig(k8sworkloads.GetK8sConfig())
	if err != nil {
		return resource, unstructuredObj, err
	}
	clientset, err := kubernetes.NewForConfig(k8sworkloads.GetK8sConfig())
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
func signWorkload(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured, wlid string) error {
	s := sign.NewSigner(wlid)
	if err := s.SignImage(unstructuredObj); err != nil {
		return err
	}
	glog.Infof("Done signing, updating workload. Kind: %s, Name: %s", unstructuredObj.GetKind(), unstructuredObj.GetName())
	return updateWorkload(resource, unstructuredObj)
}

func updateWorkload(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {

	if unstructuredObj.GetKind() == "Pod" {
		// DELETE and CREATE pod
		return updatePod(resource, unstructuredObj)
	}
	// Edit annotations and UPDATE
	return updateAbstract(resource, unstructuredObj)
}

func createWorkload(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {
	glog.Infof("Running create")

	// Get current annotations
	annotations, found, errr := unstructured.NestedStringMap(unstructuredObj.Object, "metadata", "annotations")
	if errr != nil {
		glog.Errorf("Error receiving annotations: %s", errr)
	}
	if !found {
		annotations = make(map[string]string)
	}

	ann, _ := json.Marshal(annotations)
	glog.Infof("Annotations:\n%s", string(ann))

	_, err := resource.Create(unstructuredObj, metav1.CreateOptions{})
	if err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("Workload created successfully")
	return nil
}

func updatePod(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {
	glog.Infof("Running update pod")
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
	/*
		-- IMPORTANT --
		When running update, websocket IGNORES all fields (execp annotations) in the recieved workload.
	*/
	ob, err := resource.Get(unstructuredObj.GetName(), metav1.GetOptions{})
	if err != nil {
		glog.Error(err)
		return err
	}

	// Get current annotations
	annotations, found, err := unstructured.NestedStringMap(unstructuredObj.Object, "spec", "template", "metadata", "annotations")
	if err != nil {
		glog.Errorf("Error receiving annotations: %s", err)
	}
	if !found {
		annotations = make(map[string]string)
	}

	tm := time.Now().UTC()
	annotations["last-cawesocket-update"] = string(tm.Format("02-01-2006 15:04:05"))

	// Change annotations
	unstructured.SetNestedStringMap(ob.Object, annotations, "spec", "template", "metadata", "annotations")

	_, err = resource.Update(ob, metav1.UpdateOptions{})
	if err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("Workload updated successfully")
	return nil
}
func deleteWorkload(resource dynamic.ResourceInterface, unstructuredObj *unstructured.Unstructured) error {
	glog.Infof("Running delete")
	d := metav1.DeletePropagationBackground
	err := resource.Delete(unstructuredObj.GetName(), &metav1.DeleteOptions{PropagationPolicy: &d})
	if err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("Workload deleted successfully")
	return nil
}
