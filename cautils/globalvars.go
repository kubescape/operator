package cautils

import (
	"fmt"
	"os"
)

var (
	CA_NAMESPACE         = ""
	CA_SERVICE_NAME      = ""
	CA_SERVICE_PORT      = ""
	CA_PORATL_BACKEND    = ""
	CA_CLUSTER_NAME      = ""
	CA_POSTMAN           = ""
	CA_CUSTOMER_GUID     = ""
	CA_LOGIN_SECRET_NAME = ""
)

func ReadEnvironmentVaribles() {
	CA_NAMESPACE = testEnvironmentVarible("CA_NAMESPACE")
	CA_SERVICE_NAME = testEnvironmentVarible("CA_SERVICE_NAME")
	CA_SERVICE_PORT = testEnvironmentVarible("CA_SERVICE_PORT")
	CA_PORATL_BACKEND = testEnvironmentVarible("CA_PORATL_BACKEND")
	CA_CLUSTER_NAME = testEnvironmentVarible("CA_CLUSTER_NAME")
	CA_POSTMAN = testEnvironmentVarible("CA_POSTMAN")
	CA_CUSTOMER_GUID = testEnvironmentVarible("CA_CUSTOMER_GUID")
	// CA_LOGIN_SECRET_NAME = testEnvironmentVarible("CA_LOGIN_SECRET_NAME")

	//TODO
	CA_LOGIN_SECRET_NAME, _ = os.LookupEnv("CA_LOGIN_SECRET_NAME")
}
func testEnvironmentVarible(key string) string {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		panic(fmt.Sprintf("Missing/empty environment variable %s", key))
	}
	return v
}
