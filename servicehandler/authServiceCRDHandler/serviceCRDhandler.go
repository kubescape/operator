package authservicecrdhandler

import (
	"fmt"

	"github.com/kubescape/operator/servicehandler"
)

type AuthServiceCRD struct {
	Name string
}

func CRDHandler(serviceScanResult servicehandler.AuthServicre) {
	fmt.Println("AuthCRDHandler")
}

func createCRD() {
	fmt.Println("createCRD")
}

func uppdateCRD() {
	fmt.Println("uppdateCRD")
}

func deleteCRD() {
	fmt.Println("deleteCRD")
}

func getCRD() {
	fmt.Println("getCRD")
}

func getCurerntCRDState() map[string]string {
	fmt.Println("getCurerntCRDState")
	return map[string]string{}
}

func AuthServicesCRDHandler(serviceScanResult map[string][]servicehandler.AuthServicre) {
	fmt.Println("AuthServicesCRDHandler")
}
