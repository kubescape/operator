module k8s-ca-websocket

go 1.13

replace github.com/armosec/capacketsgo => ./vendor/github.com/armosec/capacketsgo

require (
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/armosec/capacketsgo v0.0.30
	github.com/containerd/containerd v1.5.5 // indirect
	github.com/docker/docker v20.10.8+incompatible
	github.com/golang/glog v0.0.0-20210429001901-424d2337a529
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/robfig/cron v1.2.0
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	k8s.io/api v0.22.0
	k8s.io/apimachinery v0.22.0
	k8s.io/client-go v0.22.0
)
