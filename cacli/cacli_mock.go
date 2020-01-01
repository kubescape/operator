package cacli

import (
	"k8s-ca-websocket/cautils"
)

// CacliMock commands
type CacliMock struct {
}

// NewCacliMock -
func NewCacliMock() *CacliMock {
	return &CacliMock{}
}

// Login -
func (caclim *CacliMock) Login(globalLoginCredentials cautils.CredStruct) error {
	return nil
}

// Get wordpress wlid
func (caclim *CacliMock) Get(wlid string) (cautils.WorkloadTemplate, error) {
	return *cautils.WrokloadTemplateWordpressMock(), nil
}

// Sign wordpress wlid
func (caclim *CacliMock) Sign(wlid string) error {
	return nil
}
