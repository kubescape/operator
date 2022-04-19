package mainhandler

import (
	"strings"
	"testing"
)

func TestCombineKubescapeCMDArgsWithFrameworkName(t *testing.T) {
	fullCMD := combineKubescapeCMDArgsWithFrameworkName("mitre", []string{"scan", "framework"})
	if strings.Join(fullCMD, " ") != "scan framework mitre" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{"scan", "framework"})
	if strings.Join(fullCMD, " ") != "scan" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{"scan", "framework", "--environment"})
	if strings.Join(fullCMD, " ") != "scan --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("mitre", []string{"scan", "framework", "--environment"})
	if strings.Join(fullCMD, " ") != "scan framework mitre --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("mitre", []string{"--environment"})
	if strings.Join(fullCMD, " ") != "scan framework mitre --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{"--environment"})
	if strings.Join(fullCMD, " ") != "scan --environment" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("", []string{})
	if strings.Join(fullCMD, " ") != "scan" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
	fullCMD = combineKubescapeCMDArgsWithFrameworkName("mitre", []string{})
	if strings.Join(fullCMD, " ") != "scan framework mitre" {
		t.Errorf("invalid kubescape args str: %v", fullCMD)
	}
}
