package mainhandler

import (
	"context"
	"fmt"
	"io"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/armometadata"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/yaml"

	// pkgcautils "github.com/armosec/utils-k8s-go/wlid"
	cacli "github.com/armosec/cacli-wrapper-go/cacli"
	"github.com/armosec/k8s-interface/k8sinterface"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	opapolicy "github.com/armosec/opa-utils/reporthandling"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/golang/glog"
	"golang.org/x/sync/semaphore"
)

type MainHandler struct {
	sessionObj      *chan cautils.SessionObj
	cacli           cacli.ICacli
	k8sAPI          *k8sinterface.KubernetesApi
	signerSemaphore *semaphore.Weighted
}

type ActionHandler struct {
	cacli           cacli.ICacli
	k8sAPI          *k8sinterface.KubernetesApi
	reporter        reporterlib.IReporter
	wlid            string
	sid             string
	command         apis.Command
	signerSemaphore *semaphore.Weighted
}

var k8sNamesRegex *regexp.Regexp

func init() {
	var err error
	k8sNamesRegex, err = regexp.Compile("[^A-Za-z0-9-]+")
	if err != nil {
		glog.Fatal(err)
	}
}

// CreateWebSocketHandler Create ws-handler obj
func NewMainHandler(sessionObj *chan cautils.SessionObj, cacliRef cacli.ICacli, k8sAPI *k8sinterface.KubernetesApi) *MainHandler {
	armometadata.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &MainHandler{
		sessionObj:      sessionObj,
		cacli:           cacliRef,
		k8sAPI:          k8sAPI,
		signerSemaphore: semaphore.NewWeighted(cautils.SignerSemaphore),
	}
}

// CreateWebSocketHandler Create ws-handler obj
func NewActionHandler(cacliObj cacli.ICacli, k8sAPI *k8sinterface.KubernetesApi, signerSemaphore *semaphore.Weighted, sessionObj *cautils.SessionObj) *ActionHandler {
	armometadata.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &ActionHandler{
		reporter:        sessionObj.Reporter,
		command:         sessionObj.Command,
		cacli:           cacliObj,
		k8sAPI:          k8sAPI,
		signerSemaphore: signerSemaphore,
	}
}

// HandlePostmanRequest Parse received commands and run the command
func (mainHandler *MainHandler) HandleRequest() []error {
	// recover
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("RECOVER in HandleRequest, reason: %v", err)
		}
	}()
	for {
		sessionObj := <-*mainHandler.sessionObj

		if ignoreNamespace(sessionObj.Command.CommandName, getCommandNamespace(&sessionObj.Command)) {
			glog.Infof("namespace '%s' out of scope. Ignoring wlid: %s, command: %s", getCommandNamespace(&sessionObj.Command), getCommandID(&sessionObj.Command), sessionObj.Command.CommandName)
			continue
		}

		// if scan disabled
		if cautils.ScanDisabled && sessionObj.Command.CommandName == apis.SCAN {
			err := fmt.Errorf("scan is disabled in cluster")
			glog.Warningf(err.Error())
			sessionObj.Reporter.SetActionName(apis.SCAN)
			sessionObj.Reporter.SendError(err, true, true)
			continue
		}
		isToItemizeScopeCommand := sessionObj.Command.WildWlid != "" || sessionObj.Command.WildSid != "" || len(sessionObj.Command.Designators) > 0
		switch sessionObj.Command.CommandName {
		case string(opapolicy.TypeRunKubescapeJob), string(opapolicy.TypeSetKubescapeCronJob), string(opapolicy.TypeDeleteKubescapeCronJob), string(opapolicy.TypeUpdateKubescapeCronJob):
			isToItemizeScopeCommand = false
		}
		if isToItemizeScopeCommand {
			mainHandler.HandleScopedRequest(&sessionObj) // this might be a heavy action, do not send to a goroutine
			// } else if sessionObj.Command.Sid != "" {
			// 	go mainHandler.HandleSingleRequest(&sessionObj)
		} else {
			go mainHandler.HandleSingleRequest(&sessionObj)
		}
	}
}

func (mainHandler *MainHandler) HandleSingleRequest(sessionObj *cautils.SessionObj) {
	// FALLBACK
	sidFallback(sessionObj)

	if sessionObj.Command.CommandName != apis.SCAN_REGISTRY && sessionObj.Command.GetID() == "" {
		glog.Errorf("Received empty id")
		return
	}

	status := "SUCCESS"

	actionHandler := NewActionHandler(mainHandler.cacli, mainHandler.k8sAPI, mainHandler.signerSemaphore, sessionObj)
	glog.Infof("NewActionHandler: %v/%v", actionHandler.reporter.GetParentAction(), actionHandler.reporter.GetJobID())
	actionHandler.reporter.SendAction(sessionObj.Command.CommandName, true)
	err := actionHandler.runCommand(sessionObj)
	if err != nil {
		actionHandler.reporter.SendError(err, true, true)
		status = "FAIL"
		// cautils.SendSafeModeReport(sessionObj, err.Error(), 1)
	} else {
		actionHandler.reporter.SendStatus(jobStatus(sessionObj.Command.CommandName), true)
	}
	donePrint := fmt.Sprintf("Done command %s, wlid: %s, status: %s", sessionObj.Command.CommandName, sessionObj.Command.GetID(), status)
	if err != nil {
		donePrint += fmt.Sprintf(", reason: %s", err.Error())
	}
	glog.Infof(donePrint)
}

func (actionHandler *ActionHandler) runCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command
	if pkgwlid.IsWlid(c.GetID()) {
		actionHandler.wlid = c.GetID()
	} else {
		actionHandler.sid = c.GetID()
	}

	logCommandInfo := fmt.Sprintf("Running %s command, id: '%s'", c.CommandName, c.GetID())

	glog.Infof(logCommandInfo)
	switch c.CommandName {
	case apis.UPDATE, apis.INJECT, apis.ATTACH:
		return actionHandler.update(c.CommandName)
	case apis.REMOVE, apis.DETACH:
		actionHandler.deleteConfigMaps(c)
		err := actionHandler.update(c.CommandName)
		go actionHandler.workloadCleanupDiscovery()
		return err
	case apis.RESTART, apis.INCOMPATIBLE, apis.IMAGE_UNREACHABLE, apis.REPLACE_HEADERS:
		return actionHandler.update(c.CommandName)
	case apis.UNREGISTERED:
		err := actionHandler.update(c.CommandName)
		go actionHandler.workloadCleanupAll()
		return err
	case apis.SIGN:
		actionHandler.signerSemaphore.Acquire(context.Background(), 1)
		defer actionHandler.signerSemaphore.Release(1)
		return actionHandler.signWorkload()
	case apis.ENCRYPT, apis.DECRYPT:
		return actionHandler.runSecretCommand(sessionObj)
	case apis.SCAN:
		// return nil
		return actionHandler.scanWorkload(sessionObj)
	case apis.SCAN_REGISTRY:
		// return nil
		return actionHandler.scanRegistry(sessionObj)
	case string(opapolicy.TypeRunKubescapeJob):
		return actionHandler.runKubescapeJob()
	case string(opapolicy.TypeSetKubescapeCronJob):
		return actionHandler.setKubescapeCronJob()
	case string(opapolicy.TypeUpdateKubescapeCronJob):
		return actionHandler.updateKubescapeCronJob()
	case string(opapolicy.TypeDeleteKubescapeCronJob):
		return actionHandler.deleteKubescapeCronJob()
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func (actionHandler *ActionHandler) deleteKubescapeCronJob() error {
	kubescapeJobParams, ok := actionHandler.command.Args["kubescapeJobParams"].(opapolicy.KubescapeJobParams)
	if !ok {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}
	namespaceName := os.Getenv("CA_NAMESPACE")
	err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(namespaceName).Delete(context.Background(), kubescapeJobParams.Name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) updateKubescapeCronJob() error {
	kubescapeJobParams, ok := actionHandler.command.Args["kubescapeJobParams"].(opapolicy.KubescapeJobParams)
	if !ok {
		return fmt.Errorf("failed to convert kubescapeJobParams list to KubescapeJobParams")
	}
	namespaceName := os.Getenv("CA_NAMESPACE")
	jobTemplateObj, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(namespaceName).Get(context.Background(), kubescapeJobParams.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	jobName := kubescapeJobParams.Name
	jobName = fixK8sCronJobNameLimit(jobName)
	jobTemplateObj.Name = jobName
	jobTemplateObj.Spec.Schedule = kubescapeJobParams.CronTabSchedule
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}
	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.updatejobid"] = actionHandler.command.JobTracking.JobID
	_, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(namespaceName).Update(context.Background(), jobTemplateObj, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) setKubescapeCronJob() error {
	// TODO: use "kubescapeJobParams" instead of "rules"
	rulesList, ok := actionHandler.command.Args["rules"].([]opapolicy.PolicyIdentifier)
	if !ok {
		return fmt.Errorf("failed to convert rules list to PolicyIdentifier")
	}
	namespaceName := os.Getenv("CA_NAMESPACE")
	configMap, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(namespaceName).Get(context.Background(), "kubescape-cronjob-template", metav1.GetOptions{})
	if err != nil {
		return err

	}
	jobTemplateStr := configMap.Data["cronjobTemplate"]
	for ruleIdx := range rulesList {
		jobTemplateObj := &v1.CronJob{}
		if err := yaml.Unmarshal([]byte(jobTemplateStr), jobTemplateObj); err != nil {
			return err
		}
		ruleName := rulesList[ruleIdx].Name

		jobName := fmt.Sprintf("%s-%s", jobTemplateObj.Name, ruleName)
		jobName = fixK8sCronJobNameLimit(jobName)
		if !strings.Contains(jobName, ruleName) {
			rndInt := rand.NewSource(time.Now().UnixNano()).Int63()
			jobName = fmt.Sprintf("%s-%d-%s", jobTemplateObj.Name, rndInt, ruleName)
			jobName = fixK8sCronJobNameLimit(jobName)
		}
		jobTemplateObj.Name = jobName
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Args = combineKubescapeCMDArgsWithFrameworkName(ruleName, jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Args)
		jobTemplateObj.Spec.Schedule = actionHandler.command.Designators[0].Attributes["cronTabSchedule"]
		if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
			jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
		}
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.jobid"] = actionHandler.command.JobTracking.JobID
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.framework"] = ruleName
		_, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().CronJobs(namespaceName).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{})
		if err != nil {
			return err
		}
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

func fixK8sCronJobNameLimit(jobName string) string {
	return fixK8sNameLimit(jobName, 52)
}

func fixK8sJobNameLimit(jobName string) string {
	return fixK8sNameLimit(jobName, 63)
}

// convert to K8s valid name, lower-case, don't end with '-', maximum X characters
// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
func fixK8sNameLimit(jobName string, nameLimit int) string {
	if len(jobName) > nameLimit {
		jobName = jobName[:nameLimit]
	}
	lastIdx := len(jobName) - 1
	for lastIdx >= 0 && jobName[lastIdx] == '-' {
		jobName = jobName[:lastIdx]
		lastIdx = len(jobName) - 1
	}
	if lastIdx == -1 {
		jobName = "invalid name was given"
	}
	jobName = k8sNamesRegex.ReplaceAllString(jobName, "-")
	return strings.ToLower(jobName)
}

func (actionHandler *ActionHandler) runKubescapeJob() error {
	// TODO: use "kubescapeJobParams" instead of "rules"
	rulesList, ok := actionHandler.command.Args["rules"].([]opapolicy.PolicyIdentifier)
	if !ok {
		return fmt.Errorf("failed to convert rules list to PolicyIdentifier")
	}
	namespaceName := os.Getenv("CA_NAMESPACE")
	configMap, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().ConfigMaps(namespaceName).Get(context.Background(), "kubescape-job-template", metav1.GetOptions{})
	if err != nil {
		return err

	}
	jobTemplateStr := configMap.Data["jobTemplate"]
	for ruleIdx := range rulesList {
		jobTemplateObj := &v1.Job{}
		if err := yaml.Unmarshal([]byte(jobTemplateStr), jobTemplateObj); err != nil {
			return err
		}
		// inject kubescape CLI parameters into pod spec
		ruleName := rulesList[ruleIdx].Name
		jobName := fmt.Sprintf("%s-%s-%s", jobTemplateObj.Name, ruleName, actionHandler.command.JobTracking.JobID)
		jobName = fixK8sJobNameLimit(jobName)
		if !strings.Contains(jobName, ruleName) {
			rndInt := rand.NewSource(time.Now().UnixNano()).Int63()
			jobName = fmt.Sprintf("%s-%d-%s", jobTemplateObj.Name, rndInt, ruleName)
			jobName = fixK8sJobNameLimit(jobName)
		}
		jobTemplateObj.Name = jobName

		jobTemplateObj.Spec.Template.Spec.Containers[0].Args = combineKubescapeCMDArgsWithFrameworkName(ruleName, jobTemplateObj.Spec.Template.Spec.Containers[0].Args)
		if jobTemplateObj.Spec.Template.Annotations == nil {
			jobTemplateObj.Spec.Template.Annotations = make(map[string]string)
		}
		jobTemplateObj.Spec.Template.Annotations["armo.jobid"] = actionHandler.command.JobTracking.JobID
		jobTemplateObj.Spec.Template.Annotations["armo.framework"] = ruleName
		_, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		// watch job status
		watchHand, err := actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Watch(
			context.Background(), metav1.ListOptions{FieldSelector: fmt.Sprintf("metadata.name=%s", jobTemplateObj.Name)})
		if err != nil {
			return err
		}
		timerForError := time.NewTimer(4 * time.Minute)
		defer func() {
			if !timerForError.Stop() {
				<-timerForError.C
			}
		}()
		watchChan := watchHand.ResultChan()
		eventCount := int32(0) // ugly workaround for not reported failures
		backoffL := int32(6)
		if jobTemplateObj.Spec.BackoffLimit == nil {
			jobTemplateObj.Spec.BackoffLimit = &backoffL
		} else {
			backoffL = *jobTemplateObj.Spec.BackoffLimit
		}
		for {
			var event watch.Event
			select {
			case event = <-watchChan:
			case <-timerForError.C:
				glog.Errorf("New job watch - timer signal")
				logs, shouldReturn, returnValue := actionHandler.getJobPodLogs(namespaceName, jobTemplateObj)
				if shouldReturn {
					return fmt.Errorf("timer out signal, no pod logs: %v", returnValue)
				}
				return fmt.Errorf("timer out signal, pod logs: %s", logs)
			}
			if event.Type == watch.Error {
				glog.Errorf("New job watch chan loop error: %v", event.Object)
				watchHand.Stop()
				return fmt.Errorf("new job watch chan loop error: %v", event.Object)
			}

			jobTemplateObjReal, ok := event.Object.(*v1.Job)
			if !ok {
				glog.Errorf("New job watch - failed to convert job: %v", event)
				continue
			}
			eventCount++
			if jobTemplateObjReal.Status.Succeeded == 0 && jobTemplateObj.Status.Failed == 0 && jobTemplateObjReal.Status.Active == 0 {
				jobTemplateObjReal, err = actionHandler.k8sAPI.KubernetesClient.BatchV1().Jobs(namespaceName).Get(context.Background(), jobTemplateObjReal.Name, metav1.GetOptions{})
				if err != nil {
					glog.Errorf("New job watch - failed to get job: %s", jobTemplateObj.Name)
					continue
				}
			}
			if jobTemplateObjReal.Status.Succeeded > 0 {
				glog.Infof("job %s succeeded", jobTemplateObj.Name)
				break
			} else if jobTemplateObjReal.Status.Failed > backoffL || eventCount > backoffL+1 {
				glog.Errorf("job %s failed", jobTemplateObj.Name)
				// reading logs of pod
				logs, shouldReturn, returnValue := actionHandler.getJobPodLogs(namespaceName, jobTemplateObjReal)
				if shouldReturn {
					return returnValue
				}
				glog.Errorf("job %s failed, error logs: %s", jobTemplateObjReal.Name, string(logs))

				return fmt.Errorf("job %s failed, error logs: %s", jobTemplateObjReal.Name, string(logs))
			} else {
				glog.Errorf("job %s status unknown: %+v", jobTemplateObjReal.Name, jobTemplateObjReal.Status)
			}
		}
	}
	return nil
}

func (actionHandler *ActionHandler) getJobPodLogs(namespaceName string, jobTemplateObjReal *v1.Job) ([]byte, bool, error) {
	podList, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(namespaceName).List(
		context.Background(), metav1.ListOptions{LabelSelector: fmt.Sprintf("job-name=%s", jobTemplateObjReal.Name)})
	if err != nil {
		return nil, true, fmt.Errorf("new job watch -failed to get pods: %v", err)
	}
	if len(podList.Items) < 1 {
		return nil, true, fmt.Errorf("new job watch - wrong number of pods: %v", len(podList.Items))
	}
	podLogOpts := corev1.PodLogOptions{Timestamps: true, Container: jobTemplateObjReal.Spec.Template.Spec.Containers[0].Name}
	logsObj := actionHandler.k8sAPI.KubernetesClient.CoreV1().Pods(namespaceName).GetLogs(podList.Items[0].Name, &podLogOpts)
	readerObj, err := logsObj.Stream(actionHandler.k8sAPI.Context)
	if err != nil {
		return nil, true, fmt.Errorf("failed to get pod logs stream: %v", err)
	}
	logs, err := io.ReadAll(readerObj)
	if err != nil {
		return nil, true, fmt.Errorf("failed to read pod logs stream: %v", err)
	}
	return logs, false, nil
}

func (actionHandler *ActionHandler) signWorkload() error {
	var err error
	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
	if err != nil {
		return err
	}

	s := sign.NewSigner(actionHandler.cacli, actionHandler.k8sAPI, actionHandler.reporter, actionHandler.wlid)
	if cautils.CA_USE_DOCKER {
		err = s.SignImageDocker(workload)
	} else {
		err = s.SignImageOcimage(workload)
	}
	if err != nil {
		return err
	}

	glog.Infof("Done signing, updating workload, wlid: %s", actionHandler.wlid)

	return actionHandler.update(apis.RESTART)
}

// HandleScopedRequest handle a request of a scope e.g. all workloads in a namespace
func (mainHandler *MainHandler) HandleScopedRequest(sessionObj *cautils.SessionObj) {
	if sessionObj.Command.GetID() == "" {
		glog.Errorf("Received empty id")
		return
	}
	fmt.Printf("HandleScopedRequest: %v\n", sessionObj.Command.JobTracking)

	namespaces := make([]string, 0, 1)
	namespaces = append(namespaces, pkgwlid.GetNamespaceFromWlid(sessionObj.Command.GetID()))
	labels := sessionObj.Command.GetLabels()
	fields := sessionObj.Command.GetFieldSelector()
	resources := resourceList(sessionObj.Command.CommandName)
	if len(sessionObj.Command.Designators) > 0 {
		namespaces = make([]string, 0, 3)
		for desiIdx := range sessionObj.Command.Designators {
			if ns, ok := sessionObj.Command.Designators[desiIdx].Attributes[armotypes.AttributeNamespace]; ok {
				namespaces = append(namespaces, ns)
			}
		}
	}
	if len(namespaces) == 0 {
		namespaces = append(namespaces, "")
	}
	info := fmt.Sprintf("%s: id: '%s', namespaces: '%v', labels: '%v', fieldSelector: '%v'", sessionObj.Command.CommandName, sessionObj.Command.GetID(), namespaces, labels, fields)
	glog.Infof(info)
	sessionObj.Reporter.SendAction(info, true)
	ids, errs := mainHandler.GetIDs(namespaces, labels, fields, resources)
	for i := range errs {
		glog.Warningf(errs[i].Error())
		sessionObj.Reporter.SendError(errs[i], true, true)
	}

	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)

	glog.Infof("ids found: '%v'", ids)
	go func() { // send to goroutine so the channel will be released release the channel
		for i := range ids {
			cmd := sessionObj.Command.DeepCopy()

			var err error
			if pkgwlid.IsWlid(ids[i]) {
				cmd.Wlid = ids[i]
				err = pkgwlid.IsWlidValid(cmd.Wlid)
			} else if pkgwlid.IsSid(ids[i]) {
				cmd.Sid = ids[i]
				// TODO - validate sid
			} else {
				err = fmt.Errorf("unknown id")
			}

			// clean all scope request parameters
			cmd.WildWlid = ""
			cmd.WildSid = ""
			cmd.Designators = make([]armotypes.PortalDesignator, 0)
			// send specific command to ourselve
			newSessionObj := cautils.NewSessionObj(cmd, "Websocket", sessionObj.Reporter.GetJobID(), "", 1)

			if err != nil {
				err := fmt.Errorf("invalid: %s, id: '%s'", err.Error(), newSessionObj.Command.GetID())
				glog.Error(err)
				sessionObj.Reporter.SendError(err, true, true)
				continue
			}

			glog.Infof("triggering id: '%s'", newSessionObj.Command.GetID())
			// sessionObj.Reporter.SendAction(fmt.Sprintf("triggering id: '%s'", newSessionObj.Command.GetID()), true)
			*mainHandler.sessionObj <- *newSessionObj
			// sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)
		}
	}()
}

func (mainHandler *MainHandler) GetIDs(namespaces []string, labels, fields map[string]string, resources []string) ([]string, []error) {
	ids := []string{}
	errs := []error{}
	for _, resource := range resources {
		workloads, err := mainHandler.listWorkloads(namespaces, resource, labels, fields)
		if err != nil {
			errs = append(errs, err)
		}
		if len(workloads) == 0 {
			// err := fmt.Errorf("Resource: '%s', no workloads found. namespace: '%s', labels: '%v'", resource, namespace, labels)
			// errs = append(errs, err)
			continue
		}
		w, e := mainHandler.GetResourcesIDs(workloads)
		if len(e) != 0 {
			errs = append(errs, e...)
		}
		if len(w) == 0 {
			err := fmt.Errorf("resource: '%s', failed to calculate workloadIDs. namespaces: '%v', labels: '%v'", resource, namespaces, labels)
			errs = append(errs, err)
		}
		ids = append(ids, w...)
	}

	return ids, errs
}

// HandlePostmanRequest Parse received commands and run the command
func (mainHandler *MainHandler) StartupTriggerActions(actions []apis.Command) {

	time.Sleep(2 * time.Second) // wait for master to start listenning to the channel

	for i := range actions {
		sessionObj := cautils.NewSessionObj(&actions[i], "Websocket", "", "", 1)
		*mainHandler.sessionObj <- *sessionObj
	}
}
