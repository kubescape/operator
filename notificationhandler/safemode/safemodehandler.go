package safemode

import (
	"context"
	"fmt"
	"k8s-ca-websocket/cautils"
	"time"

	pkgcautils "github.com/armosec/capacketsgo/cautils"

	"github.com/armosec/capacketsgo/k8sinterface"
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"
	"github.com/golang/glog"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/capacketsgo/apis"
)

type SafeModeHandler struct {
	sessionObj        *chan cautils.SessionObj
	safeModeObj       *chan apis.SafeMode
	k8sApi            *k8sinterface.KubernetesApi
	wlidCompatibleMap WlidCompatibleMap
	workloadStatusMap WorkloadStatusMap
}

func NewSafeModeHandler(sessionObj *chan cautils.SessionObj, safeModeObj *chan apis.SafeMode) *SafeModeHandler {
	return &SafeModeHandler{
		sessionObj:        sessionObj,
		safeModeObj:       safeModeObj,
		k8sApi:            k8sinterface.NewKubernetesApi(),
		wlidCompatibleMap: *NewWlidCompatibleMap(),
		workloadStatusMap: *NewWorkloadStatusMap(),
	}
}

func (safeModeHandler *SafeModeHandler) HandlerSafeModeNotification() {

	for {
		safeMode := <-*safeModeHandler.safeModeObj

		if err := safeModeHandler.HandlerSafeMode(&safeMode); err != nil {
			glog.Error(err)
		}
	}
}

func (safeModeHandler *SafeModeHandler) HandlerSafeMode(safeMode *apis.SafeMode) error {

	var err error
	switch safeMode.Reporter {
	case "agnet", "agent":
		// update podMap status
		err = safeModeHandler.handleAgentReport(safeMode)
	case "webhook":
		// cawp.Reporter.SetDetails("Problem accessing container image, make sure you gave ARMO access to your container registry")
		// err = safeModeHandler.handleWebhookReport(safeMode)
	case "Init-container": // pod started
		// update podMap status
		err = safeModeHandler.handlePodStarted(safeMode)
	}

	return err
}

func (safeModeHandler *SafeModeHandler) InitSafeModeHandler() error {
	if err := safeModeHandler.wlidCompatibleMap.InitWlidMap(safeModeHandler.k8sApi); err != nil {
		return err
	}
	go safeModeHandler.snooze()
	return nil
}
func (safeModeHandler *SafeModeHandler) handlePodStarted(safeMode *apis.SafeMode) error {
	if safeMode.StatusCode != 0 {
		return nil // ignore errors in init container
	}
	if compatible, err := safeModeHandler.wlidCompatibleMap.Get(safeMode.Wlid); err == nil && compatible != nil && *compatible {
		glog.Infof("agent reported compatible, instanceID: %s, wlid: %s", safeMode.InstanceID, safeMode.Wlid)
		return nil
	}
	glog.Infof("waiting for agent to report, instanceID: %s, wlid: %s", safeMode.InstanceID, safeMode.Wlid)
	safeModeHandler.workloadStatusMap.Add(safeMode)
	safeModeHandler.reportJobSuccess(safeMode) // ?
	return nil
}

func (safeModeHandler *SafeModeHandler) handleAgentReport(safeMode *apis.SafeMode) error {
	switch safeMode.StatusCode {
	case 0:
		safeModeHandler.workloadStatusMap.Update(safeMode, true)
	default:
		if err := safeModeHandler.updateAgentIncompatible(safeMode); err != nil {
			glog.Errorf(err.Error())
		}
	}
	return nil
}

// func (safeModeHandler *SafeModeHandler) handleWebhookReport(safeMode *apis.SafeMode) error {
// 	switch safeMode.StatusCode {
// 	case 100:
// 		if err := safeModeHandler.updateAgentIncompatible(safeMode); err != nil {
// 			glog.Errorf(err.Error())
// 		}
// 	}
// 	return nil
// }
func (safeModeHandler *SafeModeHandler) agentIncompatibleUnknown(safeMode *apis.SafeMode) error {
	// remove pod from list
	safeModeHandler.workloadStatusMap.Remove(safeMode.InstanceID)

	if compatible, err := safeModeHandler.wlidCompatibleMap.Get(safeMode.Wlid); err == nil && compatible != nil {
		return nil
	}
	glog.Warningf("agent compatible unknown. instacneID: '%s', wlid: '%s'", safeMode.InstanceID, safeMode.Wlid)
	return nil
}
func (safeModeHandler *SafeModeHandler) updateAgentIncompatible(safeMode *apis.SafeMode) error {
	if compatible, err := safeModeHandler.wlidCompatibleMap.Get(safeMode.Wlid); err == nil && compatible != nil && *compatible {
		glog.Errorf("received safeMode notification but instance is reported as compatible. InstanceID: %s, wlid: %s", safeMode.InstanceID, safeMode.Wlid)
		return nil
	}

	if _, err := safeModeHandler.workloadStatusMap.Get(safeMode.InstanceID); err != nil {
		glog.Errorf("received safeMode notification but instance is not in list to watch. InstanceID: %s, wlid: %s", safeMode.InstanceID, safeMode.Wlid)
		return nil
	}
	glog.Warningf("INCOMPATIBLE. instacneID: '%s', wlid: '%s'", safeMode.InstanceID, safeMode.Wlid)

	// update wlid list
	safeModeHandler.wlidCompatibleMap.Update(safeMode.InstanceID, false)

	// update config map
	if err := safeModeHandler.updateConfigMap(safeMode, false); err != nil {
		glog.Errorf(err.Error())
	}

	message := "ARMO guard failed to initialize correctly, please report to ARMO team"
	safeModeHandler.reportSafeModeIncompatible(safeMode, message)

	// trigger detach
	safeModeHandler.triggerIncompatibleCommand(safeMode)

	// remove pod from list
	safeModeHandler.workloadStatusMap.Remove(safeMode.InstanceID)
	return nil
}
func (safeModeHandler *SafeModeHandler) updateAgentCompatible(safeMode *apis.SafeMode) error {
	safeModeHandler.workloadStatusMap.Remove(safeMode.InstanceID)
	if compatible, err := safeModeHandler.wlidCompatibleMap.Get(safeMode.Wlid); err == nil && compatible != nil {
		return nil
	}

	glog.Infof("agent compatible. instacneID: '%s', wlid: '%s'", safeMode.InstanceID, safeMode.Wlid)

	// update config map
	if err := safeModeHandler.updateConfigMap(safeMode, true); err != nil {
		glog.Errorf(err.Error())
	}
	safeModeHandler.wlidCompatibleMap.Update(safeMode.Wlid, true)

	return nil
}

func (safeModeHandler *SafeModeHandler) reportSafeModeIncompatible(safeMode *apis.SafeMode, message string) {
	reporter := reporterlib.NewBaseReport(cautils.CA_CUSTOMER_GUID, "Websocket")
	reporter.SetTarget(safeMode.Wlid)
	reporter.SetJobID(safeMode.JobID)
	reporter.SetActionName("Agent incompatible - detaching")
	reporter.SetDetails(message)
	reporter.SetStatus(reporterlib.JobFailed)
	reporter.SendError(fmt.Errorf(safeMode.Message), true, true)
}

func (safeModeHandler *SafeModeHandler) reportJobSuccess(safeMode *apis.SafeMode) {
	reporter := reporterlib.NewBaseReport(cautils.CA_CUSTOMER_GUID, safeMode.Reporter)
	reporter.SetTarget(safeMode.Wlid)
	reporter.SetJobID(safeMode.JobID)
	reporter.SetActionName("Attach armo agent")
	reporter.SetStatus(reporterlib.JobDone)
	reporter.SendStatus(reporterlib.JobDone, true)
}

func (safeModeHandler *SafeModeHandler) triggerIncompatibleCommand(safeMode *apis.SafeMode) {
	command := apis.Command{
		CommandName: apis.INCOMPATIBLE,
		Wlid:        safeMode.Wlid,
	}

	// message := fmt.Sprintf("agent incompatible, detaching wlid '%s'. agent log: %v", safeMode.Wlid, safeMode.Message)
	sessionObj := cautils.NewSessionObj(&command, "Websocket", "", safeMode.JobID, 1)
	*safeModeHandler.sessionObj <- *sessionObj
}

func (safeModeHandler *SafeModeHandler) updateConfigMap(safeMode *apis.SafeMode, status bool) error {
	confName := pkgcautils.GenarateConfigMapName(safeMode.Wlid)
	configMap, err := safeModeHandler.k8sApi.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Get(context.Background(), confName, v1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get configMap '%s', reason: %s", confName, safeMode.Wlid)
		return err
	}
	k8sinterface.SetAgentCompatibleLabel(configMap.ObjectMeta.Labels, status)
	_, err = safeModeHandler.k8sApi.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Update(context.Background(), configMap, v1.UpdateOptions{})
	if err != nil {
		err = fmt.Errorf("failed to update configMap '%s', reason: %s", confName, safeMode.Wlid)
		return err
	}
	return nil
}

// func (safeModeHandler *SafeModeHandler) createConfigMap(safeMode *apis.SafeMode, status bool) error {
// 	confName := pkgcautils.GenarateConfigMapName(safeMode.Wlid)
// 	configMap := corev1.ConfigMap{}
// 	configMap.SetName(confName)
// 	configMap.SetLabels(map[string]string{pkgcautils.ArmoCompatibleLabel: "false"})
// 	configMap.SetAnnotations(map[string]string{pkgcautils.ArmoWlid: safeMode.Wlid})
// 	_, err := safeModeHandler.k8sApi.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Create(context.Background(), &configMap, v1.CreateOptions{})
// 	if err != nil {
// 		err = fmt.Errorf("failed to create configMap '%s', reason: %s", confName, safeMode.Wlid)
// 		return err
// 	}
// 	return nil
// }

func (safeModeHandler *SafeModeHandler) snooze() error {
	sleepTime := 2 * time.Minute     // TODO get from env ?
	agentLoadTime := 5 * time.Minute // TODO get from env
	for {
		time.Sleep(sleepTime)

		workloadStatusMap := safeModeHandler.workloadStatusMap.GetKeys()
		for _, k := range workloadStatusMap {
			ws, err := safeModeHandler.workloadStatusMap.Get(k)
			if err != nil {
				continue
			}
			if time.Now().UTC().Sub(ws.GetTime()) < agentLoadTime { /// if lees 5 minutes
				continue // ignore
			}
			if status, err := safeModeHandler.wlidCompatibleMap.Get(ws.GetSafeMode().InstanceID); err == nil && status != nil {
				continue
			}
			status := ws.GetStatus()
			if status == nil {
				// unknown
				safeModeHandler.agentIncompatibleUnknown(ws.GetSafeMode())
				// safeModeHandler.updateAgentIncompatible(ws.GetSafeMode())
			} else if *status {
				safeModeHandler.updateAgentCompatible(ws.GetSafeMode())
			} else if !*status {
				// we should not have such a case
				safeModeHandler.updateAgentIncompatible(ws.GetSafeMode())
			}
		}
	}
}
