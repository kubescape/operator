package cacli

// Status cacli status
type Status struct {
	CacliVersion     string `json:"cacli-version"`
	CacsignerVersion string `json:"casigner-version"`
	Server           string `json:"server"`
	Customer         string `json:"customer"`
	UserName         string `json:"user-name"`
	LoggedIn         bool   `json:"logged-in"`
}
