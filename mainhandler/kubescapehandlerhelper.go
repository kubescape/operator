package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"k8s-ca-websocket/cautils"
	"net/http"
	"net/url"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/k8s-interface/k8sinterface"
	utilsapisv1 "github.com/armosec/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"
	"github.com/armosec/utils-go/boolutils"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getKubescapeV1ScanURL() *url.URL {
	ksURL := url.URL{}
	ksURL.Scheme = "http"
	ksURL.Host = cautils.ClusterConfig.KubescapeURL
	ksURL.Path = cautils.KubescapeRequestPathV1

	q := ksURL.Query()
	q.Set("keep", "true")
	ksURL.RawQuery = q.Encode()

	return &ksURL
}

func getKubescapeV1ScanRequest(args map[string]interface{}) (*utilsmetav1.PostScanRequest, error) {

	scanV1, ok := args[cautils.KubescapeScanV1]
	if !ok {
		return nil, fmt.Errorf("request not found")
	}

	scanV1Bytes, err := json.Marshal(scanV1)
	if err != nil {
		return nil, err
	}

	// validate
	postScanRequest := &utilsmetav1.PostScanRequest{}
	if err := json.Unmarshal(scanV1Bytes, postScanRequest); err != nil {
		return nil, fmt.Errorf("failed to convert request to v1/scan object, reason: %s", err.Error())
	}

	return postScanRequest, nil
}

func readKubescapeV1ScanResponse(resp *http.Response) (*utilsmetav1.Response, error) {
	response := &utilsmetav1.Response{}
	if resp == nil {
		return response, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return response, fmt.Errorf("received status code '%d' from kubescape, body: %s", resp.StatusCode, resp.Body)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return response, err
	}

	if err := json.Unmarshal(bodyBytes, response); err != nil {
		return nil, fmt.Errorf("failed to convert response object, reason: %s", err.Error())
	}

	return response, nil
}

func getKubescapeRequest(args map[string]interface{}) (*utilsmetav1.PostScanRequest, error) {
	postScanRequest, err := getKubescapeV1ScanRequest(args)
	if err != nil {
		return postScanRequest, err
	}

	// validate request
	if err := validateKubescapeScanRequest(postScanRequest); err != nil {
		return postScanRequest, err
	}
	setDefaultsKubescapeScanRequest(postScanRequest)

	return postScanRequest, nil
}

func setCronJobTemplate(jobTemplateObj *v1.CronJob, name, schedule, jobID, targetName string, targetType utilsapisv1.NotificationPolicyKind, hostScanner *bool) {

	jobTemplateObj.Name = name
	if schedule != "" {
		jobTemplateObj.Spec.Schedule = schedule
	}

	// update volume name
	for i, v := range jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes {
		if v.Name == VolumeNamePlaceholder {
			jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap.Name = name
		}
	}

	// add annotations
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.jobid"] = jobID // deprecated
	if targetType != "" {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[strings.ToLower(fmt.Sprintf("armo.%s", targetType))] = targetName
	}
	if hostScanner != nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.host-scanner"] = boolutils.BoolPointerToString(hostScanner)
	}

	// add annotations
	if jobTemplateObj.ObjectMeta.Labels == nil {
		jobTemplateObj.ObjectMeta.Labels = make(map[string]string)
	}
	jobTemplateObj.ObjectMeta.Labels["app"] = name

}

// func convertRulesToRequest(args map[string]interface{}) error {
// 	// TODO: use "kubescapeJobParams" instead of "rules"
// 	rulesList, ok := args["rules"].([]opapolicy.PolicyIdentifier)
// 	if !ok {
// 		return fmt.Errorf("failed to convert rules list to PolicyIdentifier")
// 	}

// 	postScanRequest := &utilsmetav1.PostScanRequest{}
// 	for i := range rulesList {
// 		postScanRequest.TargetType = utilsapisv1.NotificationPolicyKind(rulesList[i].Kind)
// 		postScanRequest.TargetNames = append(postScanRequest.TargetNames, rulesList[i].Name)
// 	}
// 	args[cautils.KubescapeScanV1] = postScanRequest
// 	return nil
// }

func createTriggerRequestConfigMap(k8sAPI *k8sinterface.KubernetesApi, name string, req *utilsmetav1.PostScanRequest) error {
	// create config map
	configMap := corev1.ConfigMap{}
	configMap.Name = name
	if configMap.Labels == nil {
		configMap.Labels = make(map[string]string)
	}
	configMap.Labels["app"] = name

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	command, err := wrapRequestWithCommand(req)
	if err != nil {
		return err
	}

	configMap.Data["request-body.json"] = string(command)
	if _, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Create(context.Background(), &configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func combineKubescapeCMDArgsWithFrameworkName(frameworkName string, currentArgs []string) []string {
	kubescapeScanCMDToken := "scan"
	kubescapeFrameworkCMDToken := "framework"
	for len(currentArgs) > 0 && !strings.HasPrefix(currentArgs[0], "-") {
		currentArgs = currentArgs[1:]
	}
	firstArgs := []string{kubescapeScanCMDToken}
	if frameworkName != "" {
		firstArgs = []string{kubescapeScanCMDToken, kubescapeFrameworkCMDToken, frameworkName}
	}
	return append(firstArgs, currentArgs...)
}

func fixK8sJobNameLimit(jobName string) string {
	return fixK8sNameLimit(jobName, 63)
}

// wrapRequestWithCommand wrap kubescape post request  with command so the websocket can parse the request
func wrapRequestWithCommand(postScanRequest *utilsmetav1.PostScanRequest) ([]byte, error) {

	c := apis.Commands{
		Commands: []apis.Command{
			{
				CommandName: apis.TypeRunKubescape,
				Args: map[string]interface{}{
					cautils.KubescapeScanV1: *postScanRequest,
				},
			},
		},
	}

	return json.Marshal(c)
}

func validateKubescapeScanRequest(postScanRequest *utilsmetav1.PostScanRequest) error {
	// validate request
	if len(postScanRequest.TargetNames) > 0 {
		if string(postScanRequest.TargetType) == "" {
			return fmt.Errorf("received targetNames but not target types")
		}
	}
	return nil
}

func setDefaultsKubescapeScanRequest(postScanRequest *utilsmetav1.PostScanRequest) {
	// set default scan to all
	if len(postScanRequest.TargetNames) == 0 {
		postScanRequest.TargetNames = []string{"all"}
		postScanRequest.TargetType = utilsapisv1.KindFramework
	}
}
