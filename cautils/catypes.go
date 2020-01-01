package cautils

// Commands list of commands received from websocket
type Commands struct {
	Commands []Command `json:"commands"`
}

// Command structure of command received from websocket
type Command struct {
	CommandName string                 `json:"commandName"`
	ResponseID  string                 `json:"responseID"`
	Wlid        string                 `json:"wlid"`
	Args        map[string]interface{} `json:"args"`
}

//WorkloadTemplate sent
type WorkloadTemplate struct {
	Kind                       string                   `json:"kind"`
	Name                       string                   `json:"name"`
	Cluster                    string                   `json:"cluster,omitempty"`
	Datacenter                 string                   `json:"datacenter,omitempty"`
	Namespace                  string                   `json:"namespace,omitempty"`
	Project                    string                   `json:"project,omitempty"`
	GroupingLevel0             string                   `json:"groupingLevel0"`
	GroupingLevel1             string                   `json:"groupingLevel1"`
	Wlid                       string                   `json:"wlid"`
	MetaInfo                   WorkloadTemplateMetaInfo `json:"metainfo,omitempty"`
	AutoAccessTokenUpdate      bool                     `json:"autoAccessTokenUpdate"`
	Containers                 []DockerContainers       `json:"containers"`
	WorkloadTemplateAttributes map[string]string        `json:"attributes,omitempty"`
}

// WorkloadTemplateMetaInfo attributes in workload
type WorkloadTemplateMetaInfo struct {
	CreationDate string                    `json:"creationDate"`
	LastEdited   string                    `json:"lastEdited"`
	WorkloadKind string                    `json:"workloadKind"`
	Instances    WorkloadTemplateInstances `json:"instances"`
	Categories   []string                  `json:"categories"`
}

//WorkloadTemplateInstances list of active and inactive
type WorkloadTemplateInstances struct {
	Active   []string `json:"active"`
	Inactive []string `json:"inactive"`
}

// DockerContainers -
type DockerContainers struct {
	Name               string            `json:"name"`
	Os                 string            `json:"os,omitempty"`
	Architecture       string            `json:"architecture,omitempty"`
	ImageHash          string            `json:"imageHash,omitempty"`
	ImageTag           string            `json:"imageTag,omitempty"`
	EnableVisiblity    []map[string]bool `json:"enableVisiblity,omitempty"`
	SigningProfileName string            `json:"signingProfileName,omitempty"`
}

// ModulesInformation holds data of specific module in signing profile
type ModulesInformation struct {
	FullPath                string `json:"fullPath"`
	Name                    string `json:"name"`
	Mandatory               int    `json:"mandatory"`
	Version                 string `json:"version,omitempty"`
	SignatureMismatchAction int    `json:"signatureMismatchAction,omitempty"`
	Type                    int    `json:"type,omitempty"`
}

// CredStruct holds the various credentials needed to do login into CA BE
type CredStruct struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Customer string `json:"customer"`
}
