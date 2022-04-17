package mainhandler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"

	utilsapisv1 "github.com/armosec/opa-utils/httpserver/apis/v1"
	opapolicy "github.com/armosec/opa-utils/reporthandling"
)

func kubescapeV1ScanURL() *url.URL {
	ksURL := url.URL{}
	ksURL.Scheme = "http"
	ksURL.Host = "kubescape:8080"
	ksURL.Path = "v1/scan"
	return &ksURL
}

func (actionHandler *ActionHandler) getKubescapeV1ScanRequest() ([]byte, error) {
	scanV1, ok := actionHandler.command.Args["v1/scan"]
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
		return nil, fmt.Errorf("failed to convert request to v1/scan object")
	}
	return scanV1Bytes, nil
}

func getKubescapeV1ScanResponse(resp *http.Response) (*utilsmetav1.Response, error) {
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
		return nil, fmt.Errorf("failed to convert request to v1/scan object")
	}

	return response, nil
}

func convertRulesToRequest(args map[string]interface{}) error {
	// TODO: use "kubescapeJobParams" instead of "rules"
	rulesList, ok := args["rules"].([]opapolicy.PolicyIdentifier)
	if !ok {
		return fmt.Errorf("failed to convert rules list to PolicyIdentifier")
	}

	postScanRequest := &utilsmetav1.PostScanRequest{}
	for i := range rulesList {
		postScanRequest.TargetType = utilsapisv1.NotificationPolicyKind(rulesList[i].Kind)
		postScanRequest.TargetNames = append(postScanRequest.TargetNames, rulesList[i].Name)
	}
	args["v1/scan"] = postScanRequest
	return nil
}
