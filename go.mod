module k8s-ca-websocket

go 1.13

replace github.com/armosec/capacketsgo => ./vendor/github.com/armosec/capacketsgo

require (
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/armosec/capacketsgo v0.0.6
	github.com/containerd/containerd v1.4.4 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.6+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/robfig/cron v1.2.0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	k8s.io/api v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4

)
