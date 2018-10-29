package shipyard

import (
	"time"
	"github.com/samalba/dockerclient"
)

type Node struct {
	ID             string   `json:"id" gorethink:"id"`
	Name           string   `json:"name" gorethink:"name"`
	Addr           string   `json:"addr" gorethink:"addr"`
	Containers     string   `json:"containers"`
	ReservedCPUs   string   `json:"reserved_cpus"`
	ReservedMemory string   `json:"reserved_memory"`
	Labels         []string `json:"labels"`
	ResponseTime   float64  `json:"response_time" gorethink:"response_time"`
}

type RethinkNodeGeneralInfo struct {
	Info []*NodeGeneralInfo	`json:"info" gorethink:"info"`
	ReqTime time.Time		`json:"-" gorethink:"reqtime"`
}
type NodeGeneralInfo struct {
	Name      string              `json:"name" gorethink:"name"`
	Addr      string              `json:"addr" gorethink:"addr"`
	Status    string              `json:"status" gorethink:"status"`
	Alert     bool                `json:"alert" gorethink:"alert"`
	AlertInfo map[string]string              `json:"alertinfo" gorethink:"alertinfo"`
	Info      *NodeGeneralSysinfo `json:"info" gorethink:"info"`
}

type NodeGeneralSysinfo struct {
	Uptime     string `json:"uptime" gorethink:"uptime"`
	CpuPercent string `json:"cpupercent" gorethink:"cpupercent"`
	Disk       string `json:"disk" gorethink:"disk"`
	VmPercent  string `json:"vmpercent" gorethink:"vmpercent"`
	Network    string `json:"network" gorethink:"network"`
	Load       string `json:"load" gorethink:"load"`
	LastUser   string `json:"lastuser" gorethink:"lastuser"`
}

type AlertInfo struct {
	Node       string   `json:"node" gorethink:"node"`
	CpuPercent string   `json:"cpupercent" gorethink:"cpupercent"`
	Disk       string   `json:"disk" gorethink:"disk"`
	VmPercent  string   `json:"vmpercent" gorethink:"vmpercent"`
	Load       string `json:"load" gorethink:"load"`
}

type ImageInfo struct {
	Image     *dockerclient.Image  `json:"images" gorethink:"image"`
	Node       []string   `json:"node" gorethink:"node"`
}

type RethinkImageInfo struct {
	Info []*ImageInfo  `json:"info" gorethink:"info"`
	ReqTime time.Time   `json:"-" gorethink:"reqtime"`
}
