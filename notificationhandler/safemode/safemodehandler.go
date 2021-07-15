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
	case "agent":
		// update podMap status
		err = safeModeHandler.handleAgentReport(safeMode)
	case "webhook":
		// update compatibleMap
	case "init-container": // pod started
		// update podMap status
		err = safeModeHandler.handlePodStarted(safeMode)
	}

	return err
}

func (safeModeHandler *SafeModeHandler) InitSafeModeHandler() error {
	if err := safeModeHandler.wlidCompatibleMap.InitWlidMap(); err != nil {
		return err
	}
	go safeModeHandler.snooze()
	return nil
}
func (safeModeHandler *SafeModeHandler) handlePodStarted(safeMode *apis.SafeMode) error {
	glog.Infof("dwertent, handlePodStarted, safeMode.InstanceID, %s", safeMode.InstanceID)
	if compatible, err := safeModeHandler.wlidCompatibleMap.Get(safeMode.Wlid); err == nil && compatible != nil && *compatible {
		glog.Infof("dwertent, handlePodStarted, compatible!!, safeMode.InstanceID, %s", safeMode.InstanceID)
		return nil
	}
	glog.Infof("dwertent, handlePodStarted, adding to list!!, safeMode.InstanceID, %s", safeMode.InstanceID)
	safeModeHandler.workloadStatusMap.Add(safeMode)
	safeModeHandler.reportJobSuccess(safeMode)
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
func (safeModeHandler *SafeModeHandler) updateAgentIncompatible(safeMode *apis.SafeMode) error {
	if _, err := safeModeHandler.workloadStatusMap.Get(safeMode.InstanceID); err == nil {
		glog.Errorf("received safeMode notification but instance is not in list to watch. InstanceID: %s, wlid: %s", safeMode.InstanceID, safeMode.Wlid)
		return nil
	}
	if compatible, err := safeModeHandler.wlidCompatibleMap.Get(safeMode.Wlid); err == nil && compatible != nil && *compatible {
		glog.Errorf("received safeMode notification but instance is reported as compatible. InstanceID: %s, wlid: %s", safeMode.InstanceID, safeMode.Wlid)
		return nil
	}

	// update wlid list
	safeModeHandler.wlidCompatibleMap.Update(safeMode.InstanceID, false)

	// update config map
	if err := safeModeHandler.updateConfigMap(safeMode, false); err != nil {
		glog.Errorf(err.Error())
	}

	// trigger detach
	safeModeHandler.triggerDetachCommand(safeMode)

	// remove pod from list
	safeModeHandler.workloadStatusMap.Remove(safeMode.InstanceID)

	return nil
}
func (safeModeHandler *SafeModeHandler) updateAgentCompatible(safeMode *apis.SafeMode) error {
	safeModeHandler.wlidCompatibleMap.Update(safeMode.Wlid, true)

	// update config map
	if err := safeModeHandler.updateConfigMap(safeMode, true); err != nil {
		glog.Errorf(err.Error())
	}
	return nil
}

func (safeModeHandler *SafeModeHandler) reportSafeModeIncompatible(safeMode *apis.SafeMode) {
	reporter := reporterlib.NewBaseReport(cautils.CA_CUSTOMER_GUID, safeMode.Reporter)
	reporter.SetTarget(safeMode.Wlid)
	reporter.SetJobID(safeMode.JobID)
	reporter.SetActionName("agent incompatible")
	reporter.SendError(fmt.Errorf(safeMode.Message), true, true)
}

func (safeModeHandler *SafeModeHandler) reportJobSuccess(safeMode *apis.SafeMode) {
	reporter := reporterlib.NewBaseReport(cautils.CA_CUSTOMER_GUID, safeMode.Reporter)
	reporter.SetTarget(safeMode.Wlid)
	reporter.SetJobID(safeMode.JobID)
	reporter.SetActionName(safeMode.Action)
	reporter.SetStatus(reporterlib.JobDone)
	reporter.SendStatus(reporterlib.JobDone, true)
}

func (safeModeHandler *SafeModeHandler) triggerDetachCommand(safeMode *apis.SafeMode) {
	command := apis.Command{
		CommandName: apis.REMOVE,
		Wlid:        safeMode.Wlid,
	}

	// message := fmt.Sprintf("agent incompatible, detaching wlid '%s'. agent log: %v", safeMode.Wlid, safeMode.Message)
	sessionObj := cautils.NewSessionObj(&command, "agent incompatible", "", safeMode.JobID, 1)
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

func (safeModeHandler *SafeModeHandler) snooze() error {
	sleepTime := 2 * time.Minute
	agentLoadTime := 5 * time.Minute
	for {
		time.Sleep(sleepTime)

		workloadStatusMap := safeModeHandler.workloadStatusMap.Copy()
		for _, v := range workloadStatusMap {
			if time.Now().UTC().Sub(v.GetTime()) < agentLoadTime { /// if lees 5 minutes
				continue // ignore
			}
			status := v.GetStatus()
			if status == nil {
				safeModeHandler.updateAgentIncompatible(v.GetSafeMode())
			}
			if *status {
				safeModeHandler.updateAgentCompatible(v.GetSafeMode())
			}
			if !*status {
				// we should not have such a case
				safeModeHandler.updateAgentIncompatible(v.GetSafeMode())
			}
		}
	}
}
