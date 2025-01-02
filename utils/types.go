package utils

import (
	"context"
	"encoding/json"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/backend/pkg/command/types/v1alpha1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Commands list of commands received from websocket
type SessionObj struct {
	CustomerGUID string
	JobID        string
	Timestamp    time.Time
	Command      *apis.Command `json:"command"`
	ParentJobID  string
	// optional - if command was created by an OperatorCommand CRD
	ParentCommandDetails *OperatorCommandDetails `json:"parentCommandDetails,omitempty"`
}

type OperatorCommandDetails struct {
	Command   *v1alpha1.OperatorCommand
	StartedAt time.Time
	Client    *k8sinterface.KubernetesApi
}

type patchStatus struct {
	errors  []error
	success bool
	payload []byte
}

func WithPayload(payload []byte) func(*patchStatus) {
	return func(s *patchStatus) {
		s.payload = payload
	}
}

func WithMultipleErrors(errors []error) func(*patchStatus) {
	return func(s *patchStatus) {
		s.errors = errors
	}
}

func WithError(err error) func(*patchStatus) {
	return func(s *patchStatus) {
		s.errors = []error{err}
	}
}

func WithSuccess() func(*patchStatus) {
	return func(s *patchStatus) {
		s.success = true
	}
}

func (s *SessionObj) SetOperatorCommandStatus(ctx context.Context, options ...func(*patchStatus)) {
	// if the command was not created by an OperatorCommand CRD, do nothing
	if s.ParentCommandDetails == nil {
		return
	}

	ps := &patchStatus{}
	for _, o := range options {
		o(ps)
	}

	status := v1alpha1.OperatorCommandStatus{
		Executer:    "operator",
		Started:     true,
		StartedAt:   &metav1.Time{Time: s.ParentCommandDetails.StartedAt},
		Completed:   true,
		CompletedAt: &metav1.Time{Time: time.Now()},
		Payload:     ps.payload,
	}

	if len(ps.errors) == 1 {
		status.Error = &v1alpha1.OperatorCommandStatusError{Message: ps.errors[0].Error()}
	} else if len(ps.errors) > 1 {
		status.Error = &v1alpha1.OperatorCommandStatusError{Message: "Failed with multiple errors"}

		// convert all errors to strings and store them in the payload
		errorMessages := make([]string, len(ps.errors))
		for i, err := range ps.errors {
			errorMessages[i] = err.Error()
		}

		// Marshal []string to JSON
		payload, err := json.Marshal(errorMessages)
		if err != nil {
			return
		}
		status.Payload = payload
	}

	patchBytes, err := json.Marshal(map[string]v1alpha1.OperatorCommandStatus{"status": status})
	if err != nil {
		logger.L().Error("patchCommandStatus - failed to marshal status patch", helpers.Error(err))
		return
	}

	_, err = s.ParentCommandDetails.Client.GetDynamicClient().Resource(v1alpha1.SchemaGroupVersionResource).Namespace(s.ParentCommandDetails.Command.Namespace).Patch(
		ctx,
		s.ParentCommandDetails.Command.Name,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
		"status",
	)
	if err != nil {
		logger.L().Error("patchCommandStatus - failed to patch command status", helpers.Error(err))
		return
	}
	logger.L().Info("patchCommandStatus: command status patched successfully")
}

type ContainerData struct {
	ImageTag      string // imageTag (from container.Image)
	ImageID       string // imageID (from containerStatus.ImageID)
	InstanceID    string // instanceID.GetStringFormatted()
	ContainerName string // containerName
	ContainerType string // containerType (init or regular)
	Slug          string // represent the unique identifier of the container
	Wlid          string // workloadID
}

// CredStruct holds the various credentials needed to do login into CA BE
type CredStruct struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Customer string `json:"customer"`
}

type Job struct {
	ctx        context.Context
	sessionObj SessionObj
}

func (j *Job) Context() context.Context {
	return j.ctx
}

func (j *Job) Obj() SessionObj {
	return j.sessionObj
}

func (j *Job) SetContext(ctx context.Context) {
	j.ctx = ctx
}

func (j *Job) SetObj(sessionObj SessionObj) {
	j.sessionObj = sessionObj
}
