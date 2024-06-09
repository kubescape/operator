package authservicecrdhandler

import (
	"fmt"

	"github.com/kubescape/operator/servicehandler/scanner"
)

func AuthCRDHandler(scanResult scanner.ServiceResult) {
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
