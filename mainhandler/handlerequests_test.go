package mainhandler

import (
	"strings"
	"testing"
)

func TestFixK8sNameLimit(t *testing.T) {
	if res := fixK8sNameLimit("AA-bb-"); res != "aa-bb" {
		t.Errorf("invalid k8s:%s", res)
	}
	if res := fixK8sNameLimit("aa-bb-fddddddddddddDDDDDdfdsfsdfdsfdsere122347985-046mntwensd8yf98"); res != "aa-bb-fddddddddddddddddddfdsfsdfdsfdsere122347985-046mntwensd8y" {
		t.Errorf("invalid k8s:%s", res)
	}
	if res := fixK8sNameLimit("aa-bb-fddddddddddddDDDDDdfdsfsdfdsfdsere122347985-046mntwensd--f98"); res != "aa-bb-fddddddddddddddddddfdsfsdfdsfdsere122347985-046mntwensd" {
		t.Errorf("invalid k8s:%s", res)
	}

}

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
