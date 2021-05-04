package cautils

import reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"

// Commands list of commands received from websocket
type Commands struct {
	Commands []Command `json:"commands"`
}

// Commands list of commands received from websocket
type SessionObj struct {
	Command  Command               `json:"command"`
	Reporter reporterlib.IReporter `json:"reporter"`
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
type WorkloadTemplateTriple struct {
	CustomerGUID  string `json:"customerGUID"`
	SolutionGUID  string `json:"solutionGUID"`
	ComponentGUID string `json:"componentGUID,omitempty"`
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

// CredStruct holds the various credentials needed to do login into CA BE
type CredStruct struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Customer string `json:"customer"`
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

// ExecutablesList holds the list of executables in this signing profile
type ExecutablesList struct {
	MainProcess                     string               `json:"mainProcess"`
	FullProcessCommandLine          string               `json:"fullProcessCommandLine,omitempty"`
	FullProcessEnvironmentVariables map[string]string    `json:"fullProcessEnvironmentVariables,omitempty"`
	ModulesInfo                     []ModulesInformation `json:"modulesInfo"`
	Filters                         FiltersSection       `json:"filter,omitempty"`
}

// FiltersSection holds the filter section of  ExecutablesList
type FiltersSection struct {
	IncludePaths      []string `json:"includePaths,omitempty"`
	IncludeExtensions []string `json:"includeExtensions,omitempty"`
}

// SigningProfile signingProfile configuration
type SigningProfile struct {
	Name           string                  `json:"name"`
	GUID           string                  `json:"guid"`
	Platform       int64                   `json:"platform"`
	Architecture   int64                   `json:"architecture"`
	CreationTime   string                  `json:"creation_time"`
	LastEditTime   string                  `json:"last_edit_time"`
	Attributes     SignigProfileAttributes `json:"attributes"`
	ExecutableList []ExecutablesList       `json:"executablesList"` // Use structs from catypes
	FullPathMap    map[string]bool         `json:"-"`
}

// SignigProfileAttributes -
type SignigProfileAttributes struct {
	IsStockProfile    bool   `json:"isStockProfile,omitempty"`
	ContainerName     string `json:"containerName,omitempty"`
	DockerImageTag    string `json:"dockerImageTag,omitempty"`
	DockerImageSHA256 string `json:"dockerImageSHA256,omitempty"`
	GeneratedFor      string `json:"generatedFor,omitempty"`
	GeneratedFrom     string `json:"generatedFrom,omitempty"`
}

// Key portal key structure
type Key struct {
	GUID                string            `json:"guid"`
	Name                string            `json:"name"`
	CustomID            string            `json:"custom_id"`
	Key                 string            `json:"key"`
	Algorithm           string            `json:"algorithm"`
	Description         string            `json:"description"`
	DliveryFlags        string            `json:"delivery_flags"`
	BackupInDB          bool              `json:"backup_in_ca_db"`
	BusinessRulePackage interface{}       `json:"business_rule_package"`
	Attributes          map[string]string `json:"attributes"`
}

// SecretPolicy portal SecretPolicy structure
type SecretPolicy struct {
	AccessPolicy     string                `json:"guid"`
	Name             string                `json:"name"`
	EncryptionStatus string                `json:"custom_id"`
	KeyID            string                `json:"key"`
	Type             string                `json:"algorithm"`
	AccessSet        SecretAccessSetPolicy `json:"secretAccessSetPolicy"`
}

// SecretAccessSetPolicy portal SecretPolicy structure
type SecretAccessSetPolicy struct {
	Wlids      []string          `json:"wlids"`
	Attributes map[string]string `json:"attributes"`
}
