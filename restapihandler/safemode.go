package restapihandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"net/http"
	"net/url"

	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"
	"github.com/golang/glog"
)

type SafeMode struct {
	Reporter        string `json:"reporter"`      // "Agent"
	Wlid            string `json:"wlid"`          // CAA_WLID
	PodName         string `json:"podName"`       // CAA_POD_NAME
	ContainerName   string `json:"containerName"` // CAA_CONTAINER_NAME
	ProcessName     string `json:"processName"`
	ProcessID       int    `json:"processID"`
	ProcessCMD      string `json:"processCMD"`
	ComponentGUID   string `json:"componentGUID"`   // CAA_GUID
	StatusCode      int    `json:"statusCode"`      // 0/1/2
	ProcessExitCode int    `json:"processExitCode"` // 0 +
	Timestamp       int64  `json:"timestamp"`
	Message         string `json:"message"` // any string
	JobID           string `json:"jobID"`   // any string
}

func (resthandler *HTTPHandler) SafeMode(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("recover in SafeMode: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			bErr, _ := json.Marshal(err)
			w.Write(bErr)
		}
	}()
	defer r.Body.Close()
	var err error
	returnValue := []byte("ok")

	httpStatus := http.StatusOK
	readBuffer, _ := ioutil.ReadAll(r.Body)

	switch r.Method {
	case http.MethodPost:
		err = resthandler.handlePost(r.URL.Query(), readBuffer)
	default:
		httpStatus = http.StatusMethodNotAllowed
		err = fmt.Errorf("Method %s no allowed", r.Method)
	}
	if err != nil {
		returnValue = []byte(err.Error())
		httpStatus = http.StatusBadRequest
	}

	w.WriteHeader(httpStatus)
	w.Write(returnValue)
}

func (resthandler *HTTPHandler) handlePost(urlVals url.Values, readBuffer []byte) error {
	message := fmt.Sprintf("%s", readBuffer)
	safeMode, _ := convertRequest(readBuffer)
	reporter := reporterlib.NewBaseReport(cautils.CA_CUSTOMER_GUID, "Websocket")
	reporter.SetTarget(safeMode.Wlid)
	reporter.SetActionName("SafeMode")
	if safeMode.JobID == "" {
		reporter.JobID = safeMode.JobID
	}
	reporter.SendError(fmt.Errorf(message), true, true)
	glog.Infof("SafeMode received: %s", message)
	// command := apis.Command{
	// 	CommandName: apis.REMOVE, //
	// 	Wlid:        wlid,
	// }

	// message := fmt.Sprintf("Detaching wlid '%s' since agent failed to load in container, agent log: %v", wlid, readBuffer)
	// sessionObj := cautils.NewSessionObj(&command, message, "", 1)
	// *resthandler.sessionObj <- *sessionObj
	return nil
}

func convertRequest(bytesRequest []byte) (*SafeMode, error) {
	safeMode := &SafeMode{}
	if err := json.Unmarshal(bytesRequest, safeMode); err != nil {
		glog.Error(err)
		return nil, err
	}
	return safeMode, nil

}
