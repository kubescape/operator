package extractor

import (
	"os"

	//Q: metav1 is just a name?

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func GetClient(in_cluster bool) *kubernetes.Clientset {
	kubeconfig := ""
	if in_cluster {
		kubeconfig = ""
	} else {
		kubeconfig = os.Getenv("HOME") + "/.kube/config"
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic("couldnt find the insreted configurtion")

	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic("couldnt connect to the cluster and create a client")

	}

	return clientset
}
