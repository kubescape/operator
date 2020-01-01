package cautils

import "testing"

func TestGetWLID(t *testing.T) {

	wlid := GetWLID("city", "home", "street", "number")
	if wlid != "wlid://cluster-city/namespace-home/street-number" {
		t.Errorf("wrong wlid")
	}
}
