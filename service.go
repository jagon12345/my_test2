package shipyard

type ServiceInfo struct {
	ID          string `json:"id,omitempty" gorethink:"id,omitempty"`
	Name        string `json:"name,omitempty" gorethink:"name,omitempty"`
	Description string `json:"description,omitempty" gorethink:"description,omitempty"`

	// 服务注册类型，地图数据处理服务，存储服务，可视化服务等等
	ServiceType string `json:"servicetype,omitempty" gorethink:"servicetype,omitempty"`

	// 服务配置
	YmlConfig []*YmlConfig `json:"ymlconfig,omitempty" gorethink:"ymlconfig,omitempty"`

	// 服务的api, 以及可转到服务页面的地址
	Apis []string `json:"apis,omitempty" gorethink:"apis,omitempty"`
	Addr string   `json:"addr,omitempty" gorethink:"addr,omitempty"`

	// 容器数量，对应使用compose-file进行的replicas数量，或总的数量
	Containers []*Container	`json:"containers,omitempty" gorethink:"containers,omitempty"`
	// 节点加ID

	// 主机(服务容器所在的主机列表)，服务状态，?
	Hosts			[]string	`json:"hosts,omitempty" gorethink:"hosts,omitempty"`
	Status string `json:"status,omitempty" gorethink:"status,omitempty"`
	//Manager			string		`json:"manager,omitempty" gorethink:"manager,omitempty"`
}

type ServiceTypeInfo struct {
	ID          string `json:"id,omitempty" gorethink:"id,omitempty"`
	Name        string `json:"name,omitempty" gorethink:"name,omitempty"`
	Description string `json:"description,omitempty" gorethink:"description,omitempty"`
}

type ThirdpartyServiceInfo struct {
	ID          string   `json:"id,omitempty" gorethink:"id,omitempty"`
	Name        string   `json:"name,omitempty" gorethink:"name,omitempty"`
	Description string   `json:"description,omitempty" gorethink:"description,omitempty"`
	ServiceType string   `json:"serviceType,omitempty" gorethink:"serviceType,omitempty"`
	YmlConfig   string   `json:"ymlConfig,omitempty" gorethink:"ymlConfig,omitempty"`
	Apis        []string `json:"apis,omitempty" gorethink:"apis,omitempty"`
	ServiceAddr string   `json:"serveAddr,omitempty" gorethink:"serveAddr,omitempty"`
}

type YmlConfig struct {
	Id string `json:"id,omitempty" gorethink:"id,omitempty"`
	Path string `json:"path,omitempty" gorethink:"path,omitempty"`
	// node name
	Node string `json:"node,omitempty" gorethink:"node,omitempty"`
	ContainerName string `json:"containername,omitempty" gorethink:"containername,omitempty"`
}

type Container struct {
	Node string `json:"node,omitempty" gorethink:"node,omitempty"`
	ContainerName string `json:"containername,omitempty" gorethink:"containername,omitempty"`
	ContainerId string `json:"containerid,omitempty" gorethink:"containerid,omitempty"`
}

type RespServiceList struct {
	ID          string `json:"id,omitempty" gorethink:"id,omitempty"`
	Name        string `json:"name,omitempty" gorethink:"name,omitempty"`
	Description string `json:"description,omitempty" gorethink:"description,omitempty"`

	// 服务注册类型，地图数据处理服务，存储服务，可视化服务等等
	ServiceType string `json:"servicetype,omitempty" gorethink:"servicetype,omitempty"`
	Status string `json:"status,omitempty" gorethink:"status,omitempty"`
	Hosts			[]string	`json:"hosts,omitempty" gorethink:"hosts,omitempty"`
}
