package websocket

import (
	"cacli"
	"log"
)

func sendWorkloadToVulnerabilityScanner(vulnScanURL string, wlid string) {
	caCliClient := cacli.NewCacli()
	workload, err := caCliClient.Get(wlid)
	if err != nil {
		log.Printf("failed retrieving workload from cacli %s", err)
		return
	}
	if len(workload.Containers) == 0 || workload.Containers[0].SigningProfileName == "" {
		log.Printf("no container to scan %s", wlid)
		return
	}
	spName := workload.Containers[0].SigningProfileName
	sp, err := cacli.GetSigningProfile(spName)
	if err != nil {
		log.Printf("failed retrieving signing profile from cacli %s", wlid)
		return
	}
	wtTriplet, err := caCliClient.GetWtTriple(wlid)
	if err != nil {
		log.Printf("failed retrieving workload triple from cacli %s", err)
		return
	}

	jsonSP, err := json.Marshal(sp)
	if err != nil {
		log.Printf("problem converting signing profile %s", err)
		return
	}
	req, err := http.NewRequest("POST", vulnScanURL+"/scanImage", bytes.NewBuffer(jsonSP))
	req.Header.Set("Content-Type", "application/json")
	q := req.URL.Query()
	q.Add("customerGuid", wtTriplet.CustomerGUID)
	q.Add("solutionGuid", wtTriplet.SolutionGUID)
	q.Add("wlid", wlid)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed posting to vulnerabilty scanner %s", err)
		return
	}
	defer resp.Body.Close()
}
