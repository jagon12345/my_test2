package shipyard

import (
	"time"
)

type (
	RespHostInfo struct {
		Info *HostInfo `json:"hostinfo, omitempty" gorethink:"hostinfo,omitempty"`
		// 请求时间，服务端每隔5秒从其他节点获取系统信息
		// 前端获取的信息为数据库中最新的一条
		ReqTime time.Time `json:"-" gorethink:"reqtime,omitempty"`
		Node    string    `json:"-" gorethink:"node,omitempty"`
	}

	HostInfo struct {
		HostName      string    `json:"hostname" gorethink:"hostname,omitempty"`
		BootTime      time.Time `json:"boottime" gorethink:"boottime,omitempty"`
		Uptime        string    `json:"uptime" gorethink:"uptime,omitempty"`
		KernelVersion string    `json:"kernelversion" gorethink:"kernelversion,omitempty"`
		Platform      string    `json:"platform" gorethink:"platform,omitempty"`
		OS            string    `json:"os" gorethink:"os,omitempty"`
		Procs         uint64    `json:"procs" gorethink:"procs,omitempty"`
	}

	RespMemInfo struct {
		Info    *MemInfo  `json:"meminfo, omitempty" gorethink:"meminfo,omitempty"`
		ReqTime time.Time `json:"-" gorethink:"reqtime,omitempty"`
		Node    string    `json:"-" gorethink:"node,omitempty"`
	}

	MemInfo struct {
		SwapMemory    map[string]string `json:"swapmemory" gorethink:"swapmemory,omitempty"`
		VirtualMemory map[string]string `json:"virtualmemory" gorethink:"virtualmemory,omitempty"`
	}

	RespNetInfo struct {
		Info    *NetInfo  `json:"netinfo, omitempty" gorethink:"netinfo,omitempty"`
		ReqTime time.Time `json:"-" gorethink:"reqtime,omitempty"`
		Node    string    `json:"-" gorethink:"node,omitempty"`
	}

	NetInfo struct {
		Interfaces []ModifiedInterfaceStat     `json:"interfaces" gorethink:"interfaces,omitempty"`
		//IOCounters []map[string]string `json:"iocounters" gorethink:"iocounters,omitempty"`
		Traffic    map[string]string   `json:"traffic" gorethink:"traffic,omitempty"`
	}

	InterfaceAddr struct {
		Addr string `json:"addr" gorethink:"addr,omitempty"`
	}

	InterfaceStat struct {
		MTU          int             `json:"mtu" gorethink:"mtu,omitempty"`
		Name         string          `json:"name" gorethink:"name,omitempty"`
		HardwareAddr string          `json:"hardwareaddr" gorethink:"hardwareaddr,omitempty"`
		Flags        []string        `json:"flags" gorethink:"flags,omitempty"`
		Addrs        []InterfaceAddr `json:"addrs" gorethink:"addrs,omitempty"`
	}

	ModifiedInterfaceStat struct {
		InterfaceStat
		BytesSent   string      `json:"bytesSent" gorethink:"bytesSent"`
		BytesRecv   string      `json:"bytesRecv" gorethink:"bytesRecv"`
		PacketsSent string      `json:"packetsSent" gorethink:"packetsSent"`
		PacketsRecv string      `json:"packetsRecv" gorethink:"packetsRecv"`
		BytesSentSpeed  string  `json:"bytesSentSpeed" gorethink:"bytesSentSpeed"`
		BytesRecvSpeed  string  `json:"bytesRecvSpeed" gorethink:"bytesRecvSpeed"`
	}

	RespCpuInfo struct {
		Info    *CpuInfo  `json:"cpuinfo, omitempty" gorethink:"cpuinfo,omitempty"`
		ReqTime time.Time `json:"-" gorethink:"reqtime,omitempty"`
		Node    string    `json:"-" gorethink:"node,omitempty"`
	}

	CpuInfo struct {
		CpuCounts  int               `json:"cpucounts" gorethink:"cpucounts,omitempty"`
		CpuTimes   map[string]string `json:"cputimes" gorethink:"cputimes,omitempty"`
		CpuPercent string            `json:"cpupercent" gorethink:"cpupercent,omitempty"`
	}

	RespDiskInfo struct {
		Info    []*DiskInfo `json:"diskinfo, omitempty" gorethink:"diskinfo,omitempty"`
		ReqTime time.Time   `json:"-" gorethink:"reqtime,omitempty"`
		Node    string      `json:"-" gorethink:"node,omitempty"`
	}

	DiskInfo struct {
		Device      string `json:"device" gorethink:"device,omitempty"`
		Mountpoint  string `json:"mountpoint" gorethink:"mountpoint,omitempty"`
		Total       string `json:"total" gorethink:"total,omitempty"`
		Used        string `json:"used" gorethink:"used,omitempty"`
		Free        string `json:"free" gorethink:"free,omitempty"`
		UsedPercent string `json:"usedpercent" gorethink:"usedpercent,omitempty"`
	}

	RespUserInfo struct {
		Info    []*UserInfo `json:"userinfo, omitempty" gorethink:"userinfo,omitempty"`
		ReqTime time.Time   `json:"-" gorethink:"reqtime,omitempty"`
		Node    string      `json:"-" gorethink:"node,omitempty"`
	}

	UserInfo struct {
		Username   string `json:"username" gorethink:"username,omitempty"`
		LoginIP    string `json:"loginip" gorethink:"loginip,omitempty"`
		LoginTime  string `json:"logintime" gorethink:"logintime,omitempty"`
		LogoutTime string `json:"logouttime" gorethink:"logouttime,omitempty"`
		Duration   string `json:"duration" gorethink:"duration,omitempty"`
		Status     string `json:"status" gorethink:"status,omitempty"`
		IsLast     bool   `json:"islast" gorethink:"islast,omitempty"`
	}

	RespLoadInfo struct {
		Info    *LoadInfo `json:"loadinfo, omitempty" gorethink:"loadinfo,omitempty"`
		ReqTime time.Time `json:"-" gorethink:"reqtime,omitempty"`
		Node    string    `json:"-" gorethink:"node,omitempty"`
	}

	LoadInfo struct {
		Load1  float64 `json:"load1" gorethink:"load1,omitempty"`
		Load5  float64 `json:"load5" gorethink:"load5,omitempty"`
		Load15 float64 `json:"load15" gorethink:"load15,omitempty"`
	}
)
