package safemode

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"sync"
	"time"

	"github.com/armosec/capacketsgo/apis"
	pkgcautils "github.com/armosec/capacketsgo/cautils"

	"github.com/armosec/capacketsgo/k8sinterface"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// ================================================================================
// ================================================================================
// ================================================================================

type WorkloadStatus struct {
	safeModeReport *apis.SafeMode
	status         *bool
	updateTime     time.Time
}

func (ws *WorkloadStatus) GetStatus() *bool            { return ws.status }
func (ws *WorkloadStatus) GetTime() time.Time          { return ws.updateTime }
func (ws *WorkloadStatus) GetSafeMode() *apis.SafeMode { return ws.safeModeReport }

func (ws *WorkloadStatus) SetStatus(s *bool)             { ws.status = s }
func (ws *WorkloadStatus) SetTime(t time.Time)           { ws.updateTime = t }
func (ws *WorkloadStatus) SetSafeMode(sm *apis.SafeMode) { ws.safeModeReport = sm }

// ================================================================================
// ================================================================================
// ================================================================================

type WlidCompatibleMap struct {
	compatibleMap map[string]*bool // map[wlid]*compatible
	mutex         sync.RWMutex
}

func NewWlidCompatibleMap() *WlidCompatibleMap {
	return &WlidCompatibleMap{
		compatibleMap: make(map[string]*bool),
		mutex:         sync.RWMutex{},
	}
}

func (wm *WlidCompatibleMap) Add(name string) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.compatibleMap[name] = nil
}

func (wm *WlidCompatibleMap) Remove(name string) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	delete(wm.compatibleMap, name)
}

func (wm *WlidCompatibleMap) Update(wlid string, status bool) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.compatibleMap[wlid] = &status
}

func (wm *WlidCompatibleMap) Get(wlid string) (*bool, error) {
	if wlid == "" {
		return nil, fmt.Errorf("empty wlid")
	}
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()
	if s, ok := wm.compatibleMap[wlid]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("not found")
}

func (wm *WlidCompatibleMap) InitWlidMap(k8sApi *k8sinterface.KubernetesApi) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	r, _ := labels.NewRequirement(pkgcautils.ArmoCompatibleLabel, selection.In, []string{"true", "false"})
	configMaps, err := k8sApi.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).List(k8sApi.Context, v1.ListOptions{
		LabelSelector: r.String(),
	})
	if err != nil {
		return err
	}

	for i := range configMaps.Items {
		wlid := ""
		if ann := configMaps.Items[i].GetAnnotations(); ann != nil {
			wlid = ann[pkgcautils.ArmoWlid] // todo - remove deprecated
			if wlid == "" {
				wlid = ann[pkgcautils.CAWlid] // Deprecated
			}
		}
		if wlid == "" {
			continue
		}
		if labels := configMaps.Items[i].GetLabels(); labels != nil {
			if v, ok := labels[pkgcautils.ArmoCompatibleLabel]; ok { // todo
				var compatible bool
				if v == "true" {
					compatible = true
				} else if v == "false" {
					compatible = false
				} else {
					continue
				}
				wm.compatibleMap[wlid] = &compatible
			}
		}
	}
	return nil
}

// ================================================================================
// ================================================================================
// ================================================================================

type WorkloadStatusMap struct {
	workloadStatusMap map[string]WorkloadStatus
	mutex             sync.RWMutex
}

func NewWorkloadStatusMap() *WorkloadStatusMap {
	return &WorkloadStatusMap{
		workloadStatusMap: make(map[string]WorkloadStatus),
		mutex:             sync.RWMutex{},
	}
}

func (wsm *WorkloadStatusMap) Add(safeModeReport *apis.SafeMode) {
	if safeModeReport == nil || safeModeReport.InstanceID == "" {
		return
	}
	ws := WorkloadStatus{
		updateTime:     time.Now().UTC(),
		safeModeReport: safeModeReport,
	}
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()
	wsm.workloadStatusMap[safeModeReport.InstanceID] = ws
}

func (wsm *WorkloadStatusMap) Remove(name string) {
	if name == "" {
		return
	}
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()
	delete(wsm.workloadStatusMap, name)
}

func (wsm *WorkloadStatusMap) Update(safeModeReport *apis.SafeMode, status bool) {
	if safeModeReport == nil || safeModeReport.InstanceID == "" {
		return
	}

	wsm.mutex.RLock()
	if _, ok := wsm.workloadStatusMap[safeModeReport.InstanceID]; !ok {
		wsm.mutex.RUnlock()
		return
	}
	wsm.mutex.RUnlock()

	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()
	if ws, ok := wsm.workloadStatusMap[safeModeReport.InstanceID]; ok {
		ws.SetStatus(&status)
		ws.SetSafeMode(safeModeReport)
		wsm.workloadStatusMap[safeModeReport.InstanceID] = ws
	}
}

func (wsm *WorkloadStatusMap) Get(name string) (*WorkloadStatus, error) {
	if name == "" {
		return nil, fmt.Errorf("empty name")
	}
	wsm.mutex.RLock()
	defer wsm.mutex.RUnlock()
	if ws, ok := wsm.workloadStatusMap[name]; ok {
		return &ws, nil
	}
	return nil, fmt.Errorf("not found")
}

func (wsm *WorkloadStatusMap) Copy() map[string]WorkloadStatus {
	wsm.mutex.RLock()
	defer wsm.mutex.RUnlock()

	workloadStatusMap := make(map[string]WorkloadStatus, len(wsm.workloadStatusMap))
	for k, v := range wsm.workloadStatusMap {
		ws := WorkloadStatus{
			updateTime: v.GetTime(),
		}
		if ws.GetStatus() != nil {
			ws.SetStatus(&(*v.GetStatus()))
		}
		if ws.GetSafeMode() != nil {
			ws.SetSafeMode(&(*v.GetSafeMode()))
		}

		workloadStatusMap[k] = ws
	}
	return workloadStatusMap
}

func (wsm *WorkloadStatusMap) GetKeys() []string {
	wsm.mutex.RLock()
	defer wsm.mutex.RUnlock()
	keys := []string{}
	for k, _ := range wsm.workloadStatusMap {
		keys = append(keys, k)
	}
	return keys
}

// ================================================================================
// ================================================================================
// ================================================================================
