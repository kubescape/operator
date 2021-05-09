package cronjobs

// import (
// 	"k8s-ca-websocket/cautils"
// 	"testing"
// 	"time"

// 	icacli "github.com/armosec/capacketsgo/cacli"
// 	"github.com/golang/glog"
// 	"github.com/robfig/cron"
// )

// func mock() {
// 	client := icacli.NewCacli("https://dashbe.eudev3.cyberarmorsoft.com", false)
// 	if err := client.Login(); err != nil {
// 		glog.Errorf("unable to login to cacli in order to perform cluster posture scans")
// 	}
// 	glog.Infof("starting to run posture scans")
// 	frameworks := loadFrameworks()
// 	for _, framework := range frameworks {
// 		go func(framework string) {
// 			glog.Infof("running %v framework posture scan on cluster", framework)
// 			if err := client.RunPostureScan(framework, cautils.CA_CLUSTER_NAME); err != nil {
// 				glog.Errorf("running posture framework %s failed due to: %v", framework, err.Error())
// 			}
// 		}(framework)

// 	}
// }
// func TestGetWLID(t *testing.T) {
// 	c := cron.New()
// 	c.AddFunc("@every 1m", mock)
// 	c.Start()
// 	time.Sleep(time.Minute * 6)
// }
