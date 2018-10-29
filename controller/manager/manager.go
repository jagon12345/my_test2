package manager

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"archive/tar"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"os"
	"io/ioutil"
	"io"
	"bufio"
	"math/rand"
	"mime/multipart"
	"strconv"

	"crypto/tls"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/sessions"
	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
	"github.com/shipyard/shipyard/auth"
	"github.com/shipyard/shipyard/dockerhub"
	"github.com/shipyard/shipyard/version"
	r "gopkg.in/dancannon/gorethink.v2"
)

const (
	tblNameConfig           = "config"
	tblNameEvents           = "events"
	tblNameAccounts         = "accounts"
	tblNameRoles            = "roles"
	tblNameServices         = "services"     //===new
	tblNameNodesGeneralInfo = "generalinfo"  //===new
	tblNameAlert            = "alert"        //===new
	tblNameHostInfo         = "hostinfo"     //===new
	tblNameMemInfo          = "meminfo"      //===new
	tblNameNetInfo          = "netinfo"      //===new
	tblNameDiskInfo         = "diskinfo"     //===new
	tblNameLoadInfo         = "loadinfo"     //===new
	tblNameCpuInfo          = "cpuinfo"      //===new
	tblNameUserInfo         = "userinfo"     //===new
	tblNameServiceType     = "servicetype" //===new
	tblNameThirdpartyServices   = "thirdparty"	//===new
	tblNameYmlConfig	= "ymlconfig"	//===new
	tblNameImageInfo	= "imageinfo"	//===new
	tblNameServiceKeys = "service_keys"
	tblNameExtensions  = "extensions"
	tblNameWebhookKeys = "webhook_keys"
	tblNameRegistries  = "registries"
	tblNameConsole     = "console"
	storeKey           = "shipyard"
	trackerHost        = "http://tracker.shipyard-project.com"
	NodeHealthUp       = "up"
	NodeHealthDown     = "down"
	ContainerDir		= "/data/shipyard/ymlconfig/Container"	//===new
)

var (
	ErrCannotPingRegistry         = errors.New("不能ping仓库（Registry）")
	ErrLoginFailure               = errors.New("无效的用户或密码")
	ErrAccountExists              = errors.New("账户已存在")
	ErrAccountDoesNotExist        = errors.New("账户不存在")
	ErrRoleDoesNotExist           = errors.New("角色不存在")
	ErrNodeDoesNotExist           = errors.New("节点不存在")
	ErrServiceDoesNotExist        = errors.New("服务不存在")   //===new
	ErrServiceExists              = errors.New("服务已存在")   //===new
	ErrThirdpartyServiceDoesNotExist        = errors.New("第三方服务不存在")   //===new
	ErrThirdpartyServiceExists              = errors.New("第三方服务已存在")   //===new
	ErrServiceTypeDoesNotExist    = errors.New("服务类型不存在") //===new
	ErrServiceTypeExists          = errors.New("服务类型已存在") //===new
	ErrAlertDoesNotExist          = errors.New("报警节点不存在") //===new
	ErrAlertExist          = errors.New("报警节点已设置") //===new
	ErrHostInfoDoesNotExist          = errors.New("未获取到主机信息") //===new
	ErrMemInfoDoesNotExist          = errors.New("未获取到内存信息") //===new
	ErrNetInfoDoesNotExist          = errors.New("未获取到网络信息") //===new
	ErrLoadInfoDoesNotExist          = errors.New("未获取到负载信息") //===new
	ErrCpuInfoDoesNotExist          = errors.New("未获取到Cpu信息") //===new
	ErrDiskInfoDoesNotExist          = errors.New("未获取到磁盘信息") //===new
	ErrUserInfoDoesNotExist          = errors.New("未获取到用户信息") //===new
	ErrServiceKeyDoesNotExist     = errors.New("服务密钥不存在")
	ErrInvalidAuthToken           = errors.New("无效的认证令牌")
	ErrExtensionDoesNotExist      = errors.New("extension 不存在")
	ErrWebhookKeyDoesNotExist     = errors.New("webhook key 不存在")
	ErrRegistryDoesNotExist       = errors.New("仓库（Registry） 不存在")
	ErrConsoleSessionDoesNotExist = errors.New("控制台会话不存在")
	store                         = sessions.NewCookieStore([]byte(storeKey))
)

type (
	DefaultManager struct {
		storeKey         string
		database         string
		authKey          string
		session          *r.Session
		authenticator    auth.Authenticator
		store            *sessions.CookieStore
		client           *dockerclient.DockerClient
		disableUsageInfo bool
	}

	ScaleResult struct {
		Scaled []string
		Errors []string
	}

	Manager interface {
		Accounts() ([]*auth.Account, error)
		Account(username string) (*auth.Account, error)
		Authenticate(username, password string) (bool, error)
		GetAuthenticator() auth.Authenticator
		SaveAccount(account *auth.Account) error
		DeleteAccount(account *auth.Account) error
		Roles() ([]*auth.ACL, error)
		Role(name string) (*auth.ACL, error)
		Store() *sessions.CookieStore
		StoreKey() string
		Container(id string) (*dockerclient.ContainerInfo, error)

		//UploadYmlConfig(multi *multipart.Form) (*shipyard.YmlConfig, error)                           //===new
		//DeployFromYmlConfig(*shipyard.YmlConfig) (string, error)                                    //===new
		SaveYmlConfigFile(r io.Reader, boundary string, path string, node string) (string, error) //===new
		ListNodeContainer(addr string) ([]string, error) //===new
		Services() ([]*shipyard.RespServiceList, error)                                                 //===new
		GetService(serviceId string) (*shipyard.ServiceInfo, error)                                 //===new
		//QueryServices(host string, serviceType string, status string) ([]*shipyard.ServiceInfo, error) //===new
		AddService(s *shipyard.ServiceInfo) (string, error)                                         //===new
		UpdateService(s *shipyard.ServiceInfo, serviceId string) (string, error)                    //===new
		DeleteService(serviceId string) (string, error)                                             //===new
		AutoGetYmlConfig(ci []*shipyard.Container) ([]*shipyard.YmlConfig, error)                          //===new
		GetServiceYmlConfig(serviceId string) ([]*shipyard.YmlConfig, error)                          //===new
		GetServiceContainers(serviceId string) ([]*shipyard.Container, error)                                      //===new TODO
		GetServiceApis(serviceId string) ([]string,  error)                                          //===new
		GetServiceAddr(serviceId string) (string, error)                                            //===new
		ExportServiceYmlConfig(serviceId string) (string, *bytes.Buffer, error)                                    //===new TODO
		//ExportMultiServiceYmlConfig(idList []int) (*[]ymlConfig, error)//===new

		ThirdpartyServices() ([]*shipyard.ThirdpartyServiceInfo, error)                 //===new
		GetThirdpartyService(serviceId string) (*shipyard.ThirdpartyServiceInfo, error) //===new
		//QueryThirdpartyServices(queries string) ([]*shipyard.ThirdpartyServiceInfo, error)//===new
		AddThirdpartyService(s *shipyard.ThirdpartyServiceInfo) (string, error)                      //===new
		UpdateThirdpartyService(s *shipyard.ThirdpartyServiceInfo, serviceId string) (string, error) //===new
		DeleteThirdpartyService(serviceId string) (string, error)                                    //===new

		ServicesType() ([]*shipyard.ServiceTypeInfo, error)         //===new
		AddServiceType(s *shipyard.ServiceTypeInfo) (*shipyard.ServiceTypeInfo, error) //===new
		DeleteServiceType(serviceId string) (map[string]string, error)         //===new

		//ScaleNode(name string) (string, error)  //===new
		DeleteNode(name string) (string, error) //===new

		Images() ([]*shipyard.ImageInfo, error)                   //===new TODO
		PullImage(name string, tag string) (string, error) //===new TODO
		ImageBatchDownload(imageName string) (string, error) //===new TODO
		//ImageDelete(name string) (string, error) //===new TODO
		//ImageBatchDelete(name []string) (string, error) //===new TODO

		NodesInfo() ([]*shipyard.Node, error)                    //===new TODO
		NodesGeneralInfo() (*shipyard.RethinkNodeGeneralInfo, error)  //===new TODO
		NodesGetAlert(node string) (*shipyard.AlertInfo, error) //===new TODO
		NodesSetAlert(alert *shipyard.AlertInfo) (*shipyard.AlertInfo, error) //===new TODO
		NodesModifyAlert(alert *shipyard.AlertInfo) (*shipyard.AlertInfo, error) //===new TODO
		GetHostInfo(name string) (*shipyard.RespHostInfo, error) //===new
		GetMemInfo(name string) (*shipyard.RespMemInfo, error)   //===new
		GetNetInfo(name string) (*shipyard.RespNetInfo, error)   //===new
		GetLoadInfo(name string) (*shipyard.RespLoadInfo, error) //===new
		GetDiskInfo(name string) (*shipyard.RespDiskInfo, error) //===new
		GetCpuInfo(name string) (*shipyard.RespCpuInfo, error)   //===new
		GetUserInfo(name string) (*shipyard.RespUserInfo, error) //===new

		ScaleContainer(id string, numInstances int) ScaleResult
		SaveServiceKey(key *auth.ServiceKey) error
		RemoveServiceKey(key string) error
		SaveEvent(event *shipyard.Event) error
		Events(limit int) ([]*shipyard.Event, error)
		PurgeEvents() error
		ServiceKey(key string) (*auth.ServiceKey, error)
		ServiceKeys() ([]*auth.ServiceKey, error)
		NewAuthToken(username string, userAgent string) (*auth.AuthToken, error)
		VerifyAuthToken(username, token string) error
		VerifyServiceKey(key string) error
		NewServiceKey(description string) (*auth.ServiceKey, error)
		ChangePassword(username, password string) error
		WebhookKey(key string) (*dockerhub.WebhookKey, error)
		WebhookKeys() ([]*dockerhub.WebhookKey, error)
		NewWebhookKey(image string) (*dockerhub.WebhookKey, error)
		SaveWebhookKey(key *dockerhub.WebhookKey) error
		DeleteWebhookKey(id string) error
		DockerClient() *dockerclient.DockerClient

		Nodes() ([]*shipyard.Node, error)
		Node(name string) (*shipyard.Node, error)

		AddRegistry(registry *shipyard.Registry) error
		RemoveRegistry(registry *shipyard.Registry) error
		Registries() ([]*shipyard.Registry, error)
		Registry(name string) (*shipyard.Registry, error)
		RegistryByAddress(addr string) (*shipyard.Registry, error)

		CreateConsoleSession(c *shipyard.ConsoleSession) error
		RemoveConsoleSession(c *shipyard.ConsoleSession) error
		ConsoleSession(token string) (*shipyard.ConsoleSession, error)
		ValidateConsoleSessionToken(containerId, token string) bool
	}
)

// Connecting to rethinkdb.
func NewManager(addr string, database string, authKey string, client *dockerclient.DockerClient, disableUsageInfo bool, authenticator auth.Authenticator) (Manager, error) {
	log.Debug("setting up rethinkdb session")
	session, err := r.Connect(r.ConnectOpts{
		Address:  addr,
		Database: database,
		AuthKey:  authKey,
	})
	if err != nil {
		return nil, err
	}
	log.Info("checking database")

	r.DBCreate(database).Run(session)
	m := &DefaultManager{
		database:         database,
		authKey:          authKey,
		session:          session,
		authenticator:    authenticator,
		store:            store,
		client:           client,
		storeKey:         storeKey,
		disableUsageInfo: disableUsageInfo,
	}
	m.initdb()
	m.init()
	return m, nil
}

func (m DefaultManager) Store() *sessions.CookieStore {
	return m.store
}

func (m DefaultManager) DockerClient() *dockerclient.DockerClient {
	return m.client
}

func (m DefaultManager) StoreKey() string {
	return m.storeKey
}

func (m DefaultManager) initdb() {
	// create tables if needed
	tables := []string{tblNameConfig, tblNameEvents, tblNameAccounts, tblNameRoles, tblNameConsole, tblNameServiceKeys, tblNameRegistries, tblNameExtensions, tblNameWebhookKeys, tblNameThirdpartyServices, tblNameServices, tblNameServiceType, tblNameHostInfo, tblNameDiskInfo, tblNameMemInfo, tblNameNetInfo, tblNameLoadInfo, tblNameCpuInfo, tblNameUserInfo, tblNameNodesGeneralInfo, tblNameAlert, tblNameYmlConfig, tblNameImageInfo} //===new
	for _, tbl := range tables {
		_, err := r.Table(tbl).Run(m.session)
		if err != nil {
			if _, err := r.DB(m.database).TableCreate(tbl).Run(m.session); err != nil {
				log.Fatalf("error creating table: %s", err)
			}
		}
	}
}

func (m DefaultManager) init() error {
	// get sysinfo from swarm node and save it ro rethinkdb
	go m.reqAndSaveSysInfo()
	// anonymous usage info
	go m.usageReport()
	// create dirs to store ymlconfig.
	// 创建目录存储编排文件
	err := os.MkdirAll(ContainerDir, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) reqAndSaveSysInfo() {
	// 每隔5s请求一次数据
	fmt.Println("Start ticking for sysinfo request.")
	t := time.NewTicker(5 * time.Second).C
	for {
		select {
		case <-t:
			nodes, err := m.Nodes()
			if err != nil {
				log.Errorf("error get node info: %s", err)
				return
			}
			addrs := []string{}
			for i := range nodes {
				addrs = append(addrs, nodes[i].Addr)
				tags := []string{"host", "mem", "net", "load", "cpu", "disk", "user"}
				for j := range(tags) {
					// 保存主机、网络等信息
					go m.saveSysInfo(nodes[i].Addr, tags[j])
				}
			}
			// 保存节点概要信息
			go m.saveNodeGeneralInfo(nodes)
			// 保存镜像信息
			go m.saveImageInfo(addrs)
		}
	}
}


func (m DefaultManager) saveNodeGeneralInfo(nodes []*shipyard.Node) {
	//存储节点的简要信息
	ngis := new(shipyard.RethinkNodeGeneralInfo)
	for i := range(nodes) {
		nodeStatus := "healthy"
		sysInfo, err := m.getNodeGeneralSysInfo(nodes[i].Addr)
		//fmt.Println(sysInfo)
		if err != nil {
			log.Warnf("err get node general info (%s) : %s", "", err)
			nodeStatus = "SysinfoUnreachable"
		}
		alert, alertInfo := m.checkAlert(nodes[i].Addr, sysInfo)
		if alert == true {
			nodeStatus = "unhealthy"
		}
		ngi := &shipyard.NodeGeneralInfo{
			Name:      nodes[i].Name,
			Addr:      nodes[i].Addr,
			Status:    nodeStatus,
			Alert:     alert,
			AlertInfo: alertInfo,
			Info:      sysInfo,
		}
		ngis.Info = append(ngis.Info, ngi)
	}
	fmt.Println("delete............1")
	res, err := r.Table(tblNameNodesGeneralInfo).Count().Run(m.session)
	var kk float64 = 0
	err = res.One(&kk)
	fmt.Println(kk)
	if err != nil {
		fmt.Println(err)
	}
	ngis.ReqTime = time.Now()
	t := ngis.ReqTime.Add(-10 * time.Minute)
	//fmt.Println(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	_, err = r.Table(tblNameNodesGeneralInfo).Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
	fmt.Println("delete............2")
	if err != nil {
		log.Warnf("err delete node general info: %s",  err)
		return
	}
	_, err = r.Table(tblNameNodesGeneralInfo).Insert(ngis).RunWrite(m.session)
	if err != nil {
		log.Warnf("err insert node general info: %s",  err)
		return
	}
	//fmt.Println(ngis)
}

func (m DefaultManager) saveImageInfo(addrs []string) {
	// 存储节点镜像信息
	imageList, err := m.client.ListImages(false)
	if err != nil {
		log.Warnf("err get image list: %s", err)
		return
	}
	nodes, err := m.Nodes()
	if err != nil {
		log.Warnf("err get node list: %s", err)
		return
	}
	imageInfo := []*shipyard.ImageInfo{}
	//imageInfo := new(shipyard.RethinkImageInfo)
	for i := range(imageList) {
		tmp := &shipyard.ImageInfo {
			Image: imageList[i],
			Node: []string{},
		}
		imageInfo = append(imageInfo, tmp)
	}
	for i := range(nodes) {
		info, err := m.sendRequestToNodes(nodes[i].Addr, "imageinfo")
		if err != nil {
			log.Warnf("err get imageinfo from node %s: %s", nodes[i].Addr, err)
			return
		}
		// LOL, it's \\n.
		l := strings.Split(info, "\\n")
		for k := range l{
			for j := range(imageList) {
				if imageList[j].Id == l[k] {
					imageInfo[j].Node = append(imageInfo[j].Node, nodes[i].Addr)
					break
				}
			}
		}
	}
	rethinkImageInfo := &shipyard.RethinkImageInfo{
		Info: imageInfo,
		ReqTime: time.Now(),
	}
	t := rethinkImageInfo.ReqTime.Add(-10 * time.Minute)
	_, err = r.Table(tblNameImageInfo).Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
	if err != nil {
		log.Warnf("error delete image info: %s", err)
		return
	}
	_, err = r.Table(tblNameImageInfo).Insert(rethinkImageInfo).RunWrite(m.session)
	if err != nil {
		log.Warnf("err insert image info: %s", err)
		return
	}

}

func (m DefaultManager) getNodeGeneralSysInfo(addr string) (*shipyard.NodeGeneralSysinfo, error) {
	info := &shipyard.NodeGeneralSysinfo{}
	hostInfo := &shipyard.RespHostInfo{}
	if res, err := r.Table(tblNameHostInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session); err != nil {
		return nil, err
	} else {
		err := res.One(&hostInfo)
		if err != nil {
			return nil, err
		}
		info.Uptime = hostInfo.Info.Uptime
	}
	memInfo := &shipyard.RespMemInfo{}
	if res, err := r.Table(tblNameMemInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session); err != nil {
		return nil, err
	} else {
		err := res.One(&memInfo)
		if err != nil {
			return nil, err
		}
		info.VmPercent = memInfo.Info.VirtualMemory["UsedPercent"]
	}
	netInfo := &shipyard.RespNetInfo{}
	if res, err := r.Table(tblNameNetInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session); err != nil {
		return nil, err
	} else {
		err := res.One(&netInfo)
		if err != nil {
			return nil, err
		}
		info.Network = netInfo.Info.Traffic["bytesRecvSpeed"] + "," + netInfo.Info.Traffic["bytesSentSpeed"]
	}
	cpuInfo := &shipyard.RespCpuInfo{}
	if res, err := r.Table(tblNameCpuInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session); err != nil {
		return nil, err
	} else {
		err := res.One(&cpuInfo)
		if err != nil {
			return nil, err
		}
		info.CpuPercent = cpuInfo.Info.CpuPercent
	}
	diskInfo := &shipyard.RespDiskInfo{}
	if res, err := r.Table(tblNameDiskInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session); err != nil {
		return nil, err
	} else {
		err := res.One(&diskInfo)
		if err != nil {
			return nil, err
		}
		info.Disk = diskInfo.Info[0].Mountpoint +  " " + diskInfo.Info[0].Used + "/" + diskInfo.Info[0].Total
	}
	loadInfo := &shipyard.RespLoadInfo{}
	if res, err := r.Table(tblNameLoadInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session); err != nil {
		return nil, err
	} else {
		err := res.One(&loadInfo)
		if err != nil {
			return nil, err
		}
		info.Load = strconv.FormatFloat(loadInfo.Info.Load1, 'f', -1, 64) + " " + strconv.FormatFloat(loadInfo.Info.Load5, 'f', -1, 64) + " " + strconv.FormatFloat(loadInfo.Info.Load15, 'f', -1, 64)
	}
	userInfo := &shipyard.RespUserInfo{}
	if res, err := r.Table(tblNameUserInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session); err != nil {
		return nil, err
	} else {
		err := res.One(&userInfo)
		if err != nil {
			return nil, err
		}
		info.LastUser = userInfo.Info[0].Username
	}
	return info, nil
}
func (m DefaultManager) saveSysInfo(addr string, tag string) {
	// 保存数据到rethinkdb，前端请求时获取最新数据(order by reqtime)
	//v := new(shipyard.RespHostInfo)

	str := strings.TrimSuffix(addr, ":2375")
	// TODO encode url
	url := "http://" + str + ":7373/" + tag + "info"
	resp, err := http.Get(url)
	if err != nil {
		// 不添加日志，不然日志文件会很大
		//log.Warnf("error req node (%s) sysinfo: %s", str, err)
		return
	}
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		//log.Warnf("error read node (%s) sysinfo: %s", str, err)
		return
	}

	// This is really stupid, cannot find another way to pass different
	// struct and deal with an efficent operation.
	// 重复这么多次好二...
	switch tag {
	case "host":
		v := new(shipyard.RespHostInfo)
		if err := json.Unmarshal(result, &v.Info); err != nil {
			log.Warnf("error trans node (%s) sysinfo: %s", str, err)
			return
		}
		v.Node = addr
		v.ReqTime = time.Now()
		// tblName... = key+ "info"
		t := v.ReqTime.Add(-10 * time.Minute)
		_, err := r.Table(tag + "info").Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
		if err != nil {
			log.Warnf("error delete node (%s) sysinfo: %s", str, err)
			return
		}

		if _, err := r.Table(tag + "info").Insert(v).RunWrite(m.session); err != nil {
			log.Warnf("error insert node (%s) sysinfo: %s", str, err)
			return
		}
	case "mem":
		v := new(shipyard.RespMemInfo)
		if err := json.Unmarshal(result, &v.Info); err != nil {
			log.Warnf("error trans node (%s) sysinfo: %s", str, err)
			return
		}
		v.Node = addr
		v.ReqTime = time.Now()
		fmt.Println(v.ReqTime, "========", str)
		// tblName... = key+ "info"
		t := v.ReqTime.Add(-10 * time.Minute)
		_, err := r.Table(tag + "info").Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
		if err != nil {
			log.Warnf("error delete node (%s) sysinfo: %s", str, err)
			return
		}

		if _, err := r.Table(tag + "info").Insert(v).RunWrite(m.session); err != nil {
			log.Warnf("error insert node (%s) sysinfo: %s", str, err)
			return
		}
	case "net":
		v := new(shipyard.RespNetInfo)
		if err := json.Unmarshal(result, &v.Info); err != nil {
			log.Warnf("error trans node (%s) sysinfo: %s", str, err)
			return
		}
		v.Node = addr
		v.ReqTime = time.Now()
		// tblName... = key+ "info"

		t := v.ReqTime.Add(-10 * time.Minute)
		_, err := r.Table(tag + "info").Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
		if err != nil {
			log.Warnf("error delete node (%s) sysinfo: %s", str, err)
			return
		}
		if _, err := r.Table(tag + "info").Insert(v).RunWrite(m.session); err != nil {
			log.Warnf("error insert node (%s) sysinfo: %s", str, err)
			return
		}
	case "load":
		v := new(shipyard.RespLoadInfo)
		if err := json.Unmarshal(result, &v.Info); err != nil {
			log.Warnf("error trans node (%s) sysinfo: %s", str, err)
			return
		}
		v.Node = addr
		v.ReqTime = time.Now()
		// tblName... = key+ "info"
		
		t := v.ReqTime.Add(-10 * time.Minute)
		_, err := r.Table(tag + "info").Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
		if err != nil {
			log.Warnf("error delete node (%s) sysinfo: %s", str, err)
			return
		}
		if _, err := r.Table(tag + "info").Insert(v).RunWrite(m.session); err != nil {
			log.Warnf("error insert node (%s) sysinfo: %s", str, err)
			return
		}
	case "cpu":
		v := new(shipyard.RespCpuInfo)
		if err := json.Unmarshal(result, &v.Info); err != nil {
			log.Warnf("error trans node (%s) sysinfo: %s", str, err)
			return
		}
		v.Node = addr
		v.ReqTime = time.Now()
		// tblName... = key+ "info"

		t := v.ReqTime.Add(-10 * time.Minute)
		_, err := r.Table(tag + "info").Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
		if err != nil {
			log.Warnf("error delete node (%s) sysinfo: %s", str, err)
			return
		}
		if _, err := r.Table(tag + "info").Insert(v).RunWrite(m.session); err != nil {
			log.Warnf("error insert node (%s) sysinfo: %s", str, err)
			return
		}
	case "disk":
		v := new(shipyard.RespDiskInfo)
		if err := json.Unmarshal(result, &v.Info); err != nil {
			log.Warnf("error trans node (%s) sysinfo: %s", str, err)
			return
		}
		v.Node = addr
		v.ReqTime = time.Now()

		t := v.ReqTime.Add(-10 * time.Minute)
		_, err := r.Table(tag + "info").Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
		if err != nil {
			log.Warnf("error delete node (%s) sysinfo: %s", str, err)
			return
		}
		// tblName... = key+ "info"
		if _, err := r.Table(tag + "info").Insert(v).RunWrite(m.session); err != nil {
			log.Warnf("error insert node (%s) sysinfo: %s", str, err)
			return
		}
	case "user":
		v := new(shipyard.RespUserInfo)
		if err := json.Unmarshal(result, &v.Info); err != nil {
			log.Warnf("error trans node (%s) sysinfo: %s", str, err)
			return
		}
		v.Node = addr
		v.ReqTime = time.Now()
		t := v.ReqTime.Add(-10 * time.Minute)
		_, err := r.Table(tag + "info").Filter(r.Row.Field("reqtime").Lt(r.Time(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), "Z"))).Delete().Run(m.session)
		if err != nil {
			log.Warnf("error delete node (%s) sysinfo: %s", str, err)
			return
		}
		// tblName... = key+ "info"
		if _, err := r.Table(tag + "info").Insert(v).RunWrite(m.session); err != nil {
			log.Warnf("error insert node (%s) sysinfo: %s", str, err)
			return
		}
	}
}

func (m DefaultManager) logEvent(eventType, message string, tags []string) {
	evt := &shipyard.Event{
		Type:    eventType,
		Time:    time.Now(),
		Message: message,
		Tags:    tags,
	}

	if err := m.SaveEvent(evt); err != nil {
		log.Errorf("error logging event: %s", err)
	}
}

func (m DefaultManager) usageReport() {
	if m.disableUsageInfo {
		return
	}
	m.uploadUsage()
	t := time.NewTicker(1 * time.Hour).C
	for {
		select {
		case <-t:
			go m.uploadUsage()
		}
	}
}

func (m DefaultManager) uploadUsage() {
	id := "anon"
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Name != "lo" {
				hw := iface.HardwareAddr.String()
				id = strings.Replace(hw, ":", "", -1)
				break
			}
		}
	}
	usage := &shipyard.Usage{
		ID:      id,
		Version: version.Version,
	}
	b, err := json.Marshal(usage)
	if err != nil {
		log.Warnf("error serializing usage info: %s", err)
	}
	buf := bytes.NewBuffer(b)
	if _, err := http.Post(fmt.Sprintf("%s/update", trackerHost), "application/json", buf); err != nil {
		log.Warnf("error sending usage info: %s", err)
	}
}

func (m DefaultManager) Container(id string) (*dockerclient.ContainerInfo, error) {
	return m.client.InspectContainer(id)
}

func (m DefaultManager) ScaleContainer(id string, numInstances int) ScaleResult {
	var (
		errChan = make(chan (error))
		resChan = make(chan (string))
		result  = ScaleResult{Scaled: make([]string, 0), Errors: make([]string, 0)}
		lock    sync.Mutex // when set container affinities to swarm cluster, must use mutex
	)

	containerInfo, err := m.Container(id)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	for i := 0; i < numInstances; i++ {
		go func(instance int) {
			log.Debugf("scaling: id=%s #=%d", containerInfo.Id, instance)
			config := containerInfo.Config
			// clear hostname to get a newly generated
			config.Hostname = ""
			hostConfig := containerInfo.HostConfig
			config.HostConfig = *hostConfig // sending hostconfig via the Start-endpoint is deprecated starting with docker-engine 1.12

			lock.Lock()
			defer lock.Unlock()
			id, err := m.client.CreateContainer(config, "", nil)
			if err != nil {
				errChan <- err
				return
			}
			if err := m.client.StartContainer(id, hostConfig); err != nil {
				errChan <- err
				return
			}
			resChan <- id
		}(i)
	}

	for i := 0; i < numInstances; i++ {
		select {
		case id := <-resChan:
			result.Scaled = append(result.Scaled, id)
		case err := <-errChan:
			log.Errorf("error scaling container: err=%s", strings.TrimSpace(err.Error()))
			result.Errors = append(result.Errors, strings.TrimSpace(err.Error()))
		}
	}

	return result
}

//func (m DefaultManager) UploadYmlConfig(multi *multipart.Form) (*shipyard.YmlConfig, error) {
//	// check path
//
//	path := multi.Value["path"]
//	node := multi.Value["node"]
//	err := os.MkdirAll(path[0], os.ModePerm)
//	if err != nil {
//		return nil, err
//	}
//	// file
//	filename := path[0] + multi.File["file"][0].Filename
//	f, err := os.Create(filename)
//	if err != nil {
//		return nil, err
//	}
//	uFile, err:= multi.File["file"][0].Open()
//	if err != nil {
//		return nil, err
//	}
//	_, err = io.Copy(f, uFile)
//	if err != nil {
//		return nil, err
//	}
//	_, err = f.Seek(0, 0)
//	stat, err := f.Stat()
//	bytesize := stat.Size()
//	b := make([]byte, bytesize)
//	_, err = f.Read(b)
//	yml := new(shipyard.YmlConfig)
//	yml.Path = path[0]
//	yml.Node = node[0]
//	//fmt.Println(yml.File)
//	return yml, nil
//}

//func (m DefaultManager) DeployFromYmlConfig(yml *shipyard.YmlConfig) (string, error) {
//	m.sendRequestToNodes(yml.Node, yml.Path)
//	return "", nil
//}

func (m DefaultManager) SaveYmlConfigFile(rd io.Reader, boundary string, path string, node string) (string, error) {
	mr := multipart.NewReader(rd, boundary)
    p, err := mr.NextPart()
    if err == io.EOF {
        return "", err
    }
    if err != nil {
		return "", err
    }
    slurp, err := ioutil.ReadAll(p)
    if err != nil {
		return "", err
    }

	buf := new(bytes.Buffer)
	buf.Write(slurp)

	bufCopy := new(bytes.Buffer)
	var lines []string
	scanner := bufio.NewScanner(io.TeeReader(buf, bufCopy))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	var containerName []string
	for i := range lines {
		if strings.Contains(lines[i], "container_name") {
			containerName = append(containerName, strings.TrimSpace(strings.Split(lines[i], ":")[1]))
		}
	}
	for i := range containerName {
		ymlConfig := &shipyard.YmlConfig{
			Id: generateId(16),
			Node: node,
			Path: path,
			ContainerName: containerName[i],
		}
		res, err := r.Table(tblNameYmlConfig).Filter(map[string]string{"node":node, "path":path, "containername":containerName[i]}).Pluck("id").Run(m.session)
		if err != nil {
			log.Warnf("error retrive ymlconfig: %s", err)
			return "", err
		} else if !res.IsNil() && err == nil {
			if err := res.One(ymlConfig); err != nil {
				log.Warnf("error retrive ymlconfig: %s", err)
				return "", err
			}
		} else if _, err := r.Table(tblNameYmlConfig).Insert(ymlConfig).RunWrite(m.session); err != nil {
			log.Warnf("error insert ymlconfig: %s", err)
			return "", err
		}
		
		path := strings.TrimRight(path, "/")
		p := strings.Split(path, "/")
		ymlPath := fmt.Sprintf("%s/%s/%s", ContainerDir, ymlConfig.Id, p[len(p)-1])
		// 先创建目录，不然没法直接创建文件
		// 一定注意文件创建过多时的处理, 好在这些配置文件都不大
		os.MkdirAll(ymlPath, os.ModePerm)
		fLocal, err := os.Create(fmt.Sprintf("%s/docker-compose.yml", ymlPath))
		if err != nil {
			return "failed", err
		}
		defer fLocal.Close()
		newBuf := new(bytes.Buffer)
		io.Copy(fLocal, io.TeeReader(bufCopy, newBuf))
		io.Copy(bufCopy, newBuf)
	}
	return "success", nil
}

func (m DefaultManager) Services() ([]*shipyard.RespServiceList, error) {
	res, err := r.Table(tblNameServices).Run(m.session)
	if err != nil {
		return nil, err
	}

	if res.IsNil() {
		return nil, nil
	}
	var s []*shipyard.ServiceInfo
	if err := res.All(&s); err != nil {
		return nil, err
	}

	var respServiceList []*shipyard.RespServiceList

	for i := range s {
		status, err := m.checkServiceStatus(s[i].Containers)
		if err != nil {
			return nil, err
		}
		if status {
			s[i].Status = "1"
		}
		t := &shipyard.RespServiceList {
			ID: s[i].ID,
			Name: s[i].Name,
			Description: s[i].Description,
			ServiceType: s[i].ServiceType,
			Status: s[i].Status,
			Hosts: s[i].Hosts,
		}
		respServiceList = append(respServiceList, t)
	}


	return respServiceList, nil
}

func (m DefaultManager) GetService(serviceId string) (*shipyard.ServiceInfo, error) {

	res, err := r.Table(tblNameServices).Filter(map[string]string{"id": serviceId}).Run(m.session)
	defer res.Close()
	if err != nil {
		return nil, err
	}

	if res.IsNil() {
		return nil, ErrServiceDoesNotExist
	}

	var s *shipyard.ServiceInfo
	if err := res.One(&s); err != nil {
		return nil, err
	}
	status, err := m.checkServiceStatus(s.Containers)
	if err != nil {
		return nil, err
	}
	if status {
		s.Status = "1"
	}
	return s, nil
}
//func (m DefaultManager) QueryServices(host string, serviceType string, status string) ([]*shipyard.ServiceInfo, error) {
//
//	// queries
//	res, err := r.Table(tblNameServices).Filter(map[string]string{"host": host, "serviceType": serviceType, "status": status}).Run(m.session)
//	defer res.Close()
//	if err != nil {
//		return nil, err
//	}
//
//	if res.IsNil() {
//		return nil, nil
//	}
//
//	return nil, nil
//}

func (m DefaultManager) ListNodeContainer(addr string) ([]string, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(b))
	addr = strings.TrimSuffix(string(b), ":2375")

	info, err := m.sendRequestToNodes(addr, "/containerinfo")
	if err != nil {
		return nil, err
	}
	l := strings.Split(info, "\\n")
	return l[:len(l)-1], nil
}

func (m DefaultManager) checkServiceStatus(ci []*shipyard.Container) (bool, error) {
	// 检查服务状态，查询服务下的所有容器，如果所有容器
	// 均已启动，则表示服务运行正常，否整提示有容器未启动

	containers, err := m.client.ListContainers(true, false, "")
	if err != nil {
		return false, err
	}
	for i := range ci {
		for j := range containers {
			if containers[j].Id == ci[i].ContainerId {
				containerInfo, err := m.client.InspectContainer(containers[j].Id)
				if err != nil {
					return false, err
				}
				if containerInfo.State.Running != true {
					return false, nil
				} 
			}
		}
	}
	return true, nil
}

func (m DefaultManager) AutoGetYmlConfig(ci []*shipyard.Container) ([]*shipyard.YmlConfig, error) {
	// ci: container info
	// using ci to get ymlconfig from db which we stored when operating ymldeploy.
	fmt.Println("====1")
	keys := make([]string, 0, len(ci))
	for i := range ci {
		keys = append(keys, ci[i].ContainerName)
	}
	fmt.Println("====2")
	fmt.Println(keys)
	//res, err := r.Table(tblNameYmlConfig).Filter(func(row r.Term) interface{} {
	//	return r.Expr(keys).Contains(row.Field("containername"))
	//}).Run(m.session)

	res, err := r.Table(tblNameYmlConfig).Run(m.session)
	if res.IsNil() {
		fmt.Println("haha------3")
	}
	fmt.Println("====3")
	if err != nil {
		return nil, err
	}
	fmt.Println("====4")
	var yml []*shipyard.YmlConfig
	err = res.All(&yml)
	fmt.Println("====5")
	if err != nil {
		return nil, err
	}
	fmt.Println("====6")
	return yml, nil

}
func (m DefaultManager) AddService(s *shipyard.ServiceInfo) (string, error) {

	res, err := r.Table(tblNameServices).Filter(map[string]string{"name": s.Name}).Run(m.session)
	if err != nil {
		return "", err
	}
	if !res.IsNil() {
		return "", ErrServiceExists
	}

	s.ID = generateId(16)
	s.Status = "0"
	status, err := m.checkServiceStatus(s.Containers)
	if err != nil {
		return "", err
	}
	if status {
		s.Status = "1"
	}
	tmp := make(map[string]byte)
	for i := range s.Containers{
		l := len(tmp)
		tmp[s.Containers[i].Node] = 0
		if len(tmp) == l {
			continue
		}
		s.Hosts = append(s.Hosts, s.Containers[i].Node) 
	}

	if _, err := r.Table(tblNameServices).Insert(s).RunWrite(m.session); err != nil {
		return "", err
	}

	eventType := "add-service"

	m.logEvent(eventType, fmt.Sprintf("servicename=%s", s.Name), []string{"security"})

	return fmt.Sprintf(`"service_name": %s`, s.Name), nil
}

func (m DefaultManager) UpdateService(s *shipyard.ServiceInfo, serviceId string) (string, error) {

	res, err := m.GetService(serviceId)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", ErrServiceDoesNotExist
	}

	status, err := m.checkServiceStatus(s.Containers)
	if err != nil {
		return "", err
	}
	if status {
		s.Status = "1"
	}

	tmp := make(map[string]byte)
	for i := range s.Containers{
		l := len(tmp)
		tmp[s.Containers[i].Node] = 0
		if len(tmp) == l {
			continue
		}
		s.Hosts = append(s.Hosts, s.Containers[i].Node) 
	}

	// update
	if _, err := r.Table(tblNameServices).Get(serviceId).Update(s).RunWrite(m.session); err != nil {
		return "", err
	}

	eventType := "update-service"

	m.logEvent(eventType, fmt.Sprintf("serviceid=%s", serviceId), []string{"security"})

	return fmt.Sprintf(`"service_id": %s`, serviceId), nil
}

func (m DefaultManager) DeleteService(serviceId string) (string, error) {
	if _, err := r.Table(tblNameServices).Get(serviceId).Delete().Run(m.session); err != nil {
		return "", err
	}

	eventType := "delete-service"

	m.logEvent(eventType, fmt.Sprintf("serviceId=%s", serviceId), []string{"security"})

	return fmt.Sprintf(`"service_id": %s`, serviceId), nil
}

func (m DefaultManager) GetServiceYmlConfig(serviceId string) ([]*shipyard.YmlConfig, error) {
	res, err := m.GetService(serviceId)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, errors.New("相关服务不存在")
	}
	return res.YmlConfig, nil
}
func (m DefaultManager) GetServiceContainers(serviceId string) ([]*shipyard.Container, error) {
	res, err := m.GetService(serviceId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("相关服务不存在")
	}
	return res.Containers, nil
}

func (m DefaultManager) GetServiceApis(serviceId string) ([]string, error) {
	res, err := m.GetService(serviceId)
	if err != nil {
		return nil, err
	}

	if res == nil {
		return nil, errors.New("相关服务不存在")
	}
	return res.Apis, nil
}

func (m DefaultManager) GetServiceAddr(serviceId string) (string, error) {
	res, err := m.GetService(serviceId)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", errors.New("相关服务不存在")
	}

	return res.Addr, nil
}

func (m DefaultManager) ExportServiceYmlConfig(serviceId string) (string, *bytes.Buffer, error) {
	// send request.
	res, err := m.GetService(serviceId)
	if err != nil {
		return "", nil, err
	}

	if res == nil {
		return "", nil, errors.New("相关服务不存在")
	}
	
	//out, err := os.Create(fmt.Sprintf("%s.tar", res.Name))
	//if err != nil {
	//	return "", err
	//}
	tarName := fmt.Sprintf("%s.tar", res.Name)
	out := new(bytes.Buffer)
	tw := tar.NewWriter(out)
	// tmp stores path + node, to avoid exporting same file
	tmp := make(map[string]byte)
	for i := range res.YmlConfig {
		//if len(tmp) != 0 {
		//	for j := range tmp {
		//		if (res.YmlConfig.Path + res.YmlConfig.Node) == tmp[j]
		//	}
		//}
		// 如果path + node相同，表明这是同一文件，为因有的yml文件包含不止一个容器
		// 有可能是nginx + redis两个容器功用一个yml文件
		l := len(tmp)
		tmp[res.YmlConfig[i].Path + res.YmlConfig[i].Node] = 0
		if len(tmp) == l{
			continue
		}
		
		path := strings.TrimRight(res.YmlConfig[i].Path, "/")
		p := strings.Split(path, "/")
		var dirname string
		dirname = p[len(p)-1]
		filename := fmt.Sprintf("%s/%s/%s/docker-compose.yml", ContainerDir, res.YmlConfig[i].Id, dirname)
		f, err := os.Open(filename)
		fi, err := f.Stat()
		if err != nil {
			return "", nil, err
		}

		dhr := &tar.Header{
			// 这样可以和文件夹一起打包
			Name: dirname + "/" + "docker-compose.yml",
			Mode: 0600,
			Size: fi.Size(),
		}
		
		if err := tw.WriteHeader(dhr); err != nil {
			return "", nil, err
		}
		io.Copy(tw, f)
	}
	if err := tw.Close(); err != nil {
		return "", nil, err
	}
	return tarName, out, nil
}

func (m DefaultManager) ThirdpartyServices() ([]*shipyard.ThirdpartyServiceInfo, error) {
	res, err := r.Table(tblNameThirdpartyServices).Run(m.session)
	if err != nil {
		return nil, err
	}

	if res.IsNil() {
		return nil, nil
	}
	var s []*shipyard.ThirdpartyServiceInfo
	if err := res.All(&s); err != nil {
		return nil, err
	}

	return s, nil
}
func (m DefaultManager) GetThirdpartyService(serviceId string) (*shipyard.ThirdpartyServiceInfo, error) {
	res, err := r.Table(tblNameThirdpartyServices).Filter(map[string]string{"id": serviceId}).Run(m.session)
	defer res.Close()
	if err != nil {
		return nil, err
	}

	if res.IsNil() {
		return nil, ErrThirdpartyServiceDoesNotExist
	}

	var s *shipyard.ThirdpartyServiceInfo
	if err := res.One(&s); err != nil {
		return nil, err
	}

	return s, nil
}

//func (m DefaultManage QueryThirdpartyServices(queries string) ([]*shipyard.ThirdpartyServiceInfo, error) {
//	return nil, nil
//}
func (m DefaultManager) AddThirdpartyService(s *shipyard.ThirdpartyServiceInfo) (string, error) {
	res, err := r.Table(tblNameThirdpartyServices).Filter(map[string]string{"name": s.Name}).Run(m.session)
	if err != nil {
		return "", err
	}
	if !res.IsNil() {
		return "", ErrThirdpartyServiceExists
	}

	s.ID = generateId(16)

	if _, err := r.Table(tblNameThirdpartyServices).Insert(s).RunWrite(m.session); err != nil {
		return "", err
	}

	eventType := "add-thirdpartyservice"

	m.logEvent(eventType, fmt.Sprintf("servicename=%s", s.Name), []string{"security"})

	return fmt.Sprintf(`"service_name": %s`, s.Name), nil
}

func (m DefaultManager) UpdateThirdpartyService(s *shipyard.ThirdpartyServiceInfo, serviceId string) (string, error) {

	res, err := m.GetThirdpartyService(serviceId)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", ErrThirdpartyServiceDoesNotExist
	}
	// update
	if _, err := r.Table(tblNameThirdpartyServices).Get(serviceId).Update(s).RunWrite(m.session); err != nil {
		return "", err
	}

	eventType := "update-thirdpartyservice"

	m.logEvent(eventType, fmt.Sprintf("serviceid=%s", serviceId), []string{"security"})

	return fmt.Sprintf(`"service_id": %s`, serviceId), nil
}

func (m DefaultManager) DeleteThirdpartyService(serviceId string) (string, error) {
	if _, err := r.Table(tblNameThirdpartyServices).Get(serviceId).Delete().Run(m.session); err != nil {
		return "", err
	}

	eventType := "delete-thirdpartyservice"

	m.logEvent(eventType, fmt.Sprintf("serviceId=%s", serviceId), []string{"security"})

	return fmt.Sprintf(`"service_id": %s`, serviceId), nil
}

func (m DefaultManager) ServicesType() ([]*shipyard.ServiceTypeInfo, error) {
	res, err := r.Table(tblNameServiceType).Run(m.session)
	if err != nil {
		return nil, err
	}

	if res.IsNil() {
		return nil, nil
	}
	var s []*shipyard.ServiceTypeInfo
	if err := res.All(&s); err != nil {
		return nil, err
	}

	return s, nil
}

func (m DefaultManager) AddServiceType(s *shipyard.ServiceTypeInfo) (*shipyard.ServiceTypeInfo, error) {
	res, err := r.Table(tblNameServiceType).Filter(map[string]string{"name": s.Name}).Run(m.session)
	if err != nil {
		fmt.Println(err, 1)
		return nil, err
	}
	defer res.Close()
	if !res.IsNil() {
		fmt.Println(err, 2)
		return nil, ErrServiceTypeExists
	}
	s.ID = generateId(16)
	_, err = r.Table(tblNameServiceType).Insert(s).RunWrite(m.session)
	if err != nil {
		fmt.Println(err, 3)
		return nil, err
	}
	return s, nil
}

func (m DefaultManager) DeleteServiceType(serviceId string) (map[string]string, error) {
	if _, err := r.Table(tblNameServiceType).Filter(map[string]string{"id":serviceId}).Delete().Run(m.session); err != nil {
		return nil ,err
	}
	
	return map[string]string{"serviceTypeId": serviceId}, nil

}

//func (m DefaultManager) ScaleNode(addr string) (string, error) {
//	// add to node table
//	// when get nodes info, exclude not from this one
//	info, err := m.sendRequestToNodes(addr, "/addnode")
//	if err != nil {
//	}
//	_ = info
//	return "success to add node", nil
//}

func (m DefaultManager) DeleteNode(addr string) (string, error) {
	// delete from table
	// delete image ?? best to do is stop container and make sure it can only be activate by manual.
	info, err := m.sendRequestToNodes(addr, "/removenode")
	if err != nil {
	}
	_ = info
	return "success to remove node", nil
}

func (m DefaultManager) sendRequestToNodes(addr string, tag string) (string, error) {
	str := strings.TrimSuffix(addr, ":2375")
	// TODO encode url
	url := "http://" + str + ":7373/" + tag
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// 404
	// 不同的接口
	// 这样读出来的东西有换行符\n
	s := strings.TrimSuffix(string(b), "\n")
	s = strings.TrimSuffix(s, "\"")
	s = strings.TrimPrefix(s, "\"")
	return s, nil
}

func (m DefaultManager) Images() ([]*shipyard.ImageInfo, error) {

	// get image from database.
	//fmt.Println("start getting images...")
	//session := getUnixSession("192.168.2.102", "root", "244900")
	//var b bytes.Buffer
	//session.Stdout = &b
	//err := session.Run("docker image ls")
	//_ = err
	//fmt.Println(b.String())
	res, err := r.Table(tblNameImageInfo).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session)
	if err != nil {
		return nil, err
	}
	
	if res.IsNil() {
		return nil, nil
	}

	var imageInfo *shipyard.RethinkImageInfo
	err = res.One(&imageInfo)
	if err != nil {
		return nil, err
	}

	return imageInfo.Info, nil
}

func (m DefaultManager) PullImage(addr string, imageTag string) (string, error) {
	// send request to single swarm node.
	info, err := m.sendRequestToNodes(addr, "pullimage/" + imageTag)
	if err != nil {
		fmt.Println(err)
	}
	return info, nil
}

func (m DefaultManager)	ImageBatchDownload(imageId string) (string, error) {
	// 前端发送多个下载请求，不使用批量处理
	imageInfo, err := m.Images()
	if err != nil {
		return "数据库错误", err
	}
	var node string
	for i := range(imageInfo) {
		if imageId == imageInfo[i].Image.Id{
			rand.Seed(time.Now().Unix())
			n := rand.Intn(len(imageInfo[i].Node))
			node = imageInfo[i].Node[n]
			break
		}
	}
	return node, nil
} 

//func (m DefaultManager)	ImageBatchDelete(addrList []string) (string, error) {
//	// send request
//	return "", nil
//}

func (m DefaultManager) NodesInfo() ([]*shipyard.Node, error) {
	nodes, err := m.Nodes()
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

func (m DefaultManager) NodesGeneralInfo() (*shipyard.RethinkNodeGeneralInfo, error) {
	res, err := r.Table(tblNameNodesGeneralInfo).OrderBy(r.Desc("reqtime")).Limit(1).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	var ngis *shipyard.RethinkNodeGeneralInfo
	err = res.One(&ngis)
	if err != nil {
		return nil, err
	}
	return ngis, nil
}

func (m DefaultManager) checkAlert(addr string, info *shipyard.NodeGeneralSysinfo) (bool, map[string]string) {

	alertInfo := map[string]string{"cpualert": "", "diskalert": "", "loadalert": "", "vmalert": ""}
	if info == nil {
		return false, alertInfo
	}
	res, err := r.Table(tblNameAlert).Filter(map[string]string{"node": addr}).Run(m.session)
	if err != nil {
		log.Warnf("err query alert info (%s) : %s", addr, err)
		return false, alertInfo
	}

	defer res.Close()
	if res.IsNil() {
		return false, alertInfo
	}

	var alert *shipyard.AlertInfo
	err = res.One(&alert)
	if err != nil {
		return false, alertInfo
	}

	//alert := new(shipyard.AlertInfo)
	var b bool = false
	if info.CpuPercent > alert.CpuPercent {
		b = true
		alertInfo["cpuinfo"] = "Cpu过载"
	}
	if info.Disk > alert.Disk {
		b = true
		alertInfo["diskinfo"] = "磁盘空间不足"
	}
	//if info.Load > alert.Load {
	//	b = true
	//	alertInfo["loadinfo"] = "Cpu过载"
	//}
	if info.VmPercent > alert.VmPercent {
		b = true
		alertInfo["vminfo"] = "虚拟内存不足"
	}
	return b, alertInfo
}

func (m DefaultManager) NodesGetAlert(addr string) (*shipyard.AlertInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)

	res, err := r.Table(tblNameAlert).Filter(map[string]string{"node": addr}).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		alert := &shipyard.AlertInfo{
			Node:       addr,
			CpuPercent: "100",
			VmPercent:  "100",
			Load:       "100",
			Disk:       "100",
		}
		_, err := r.Table(tblNameAlert).Insert(alert).RunWrite(m.session)
		if err != nil {
			return alert, err
		}
		return alert, nil
	}

	var alert *shipyard.AlertInfo
	err = res.One(&alert)
	if err != nil {
		return nil, err
	}
	return alert, nil
}

func (m DefaultManager) NodesSetAlert(alert *shipyard.AlertInfo) (*shipyard.AlertInfo, error) {
	res, err := r.Table(tblNameAlert).Filter(map[string]string{"node": alert.Node}).Run(m.session)
	if err != nil {
		return alert, err
	}
	defer res.Close()
	if res.IsNil() {
		_, err = r.Table(tblNameAlert).Insert(alert).RunWrite(m.session)
		if err != nil {
			return alert, err
		}
	}

	_, err = r.Table(tblNameAlert).Filter(map[string]string{"node": alert.Node}).Update(alert).RunWrite(m.session)
	if err != nil {
		return alert, err
	}
	return alert, nil
}

func (m DefaultManager) NodesModifyAlert(alert *shipyard.AlertInfo) (*shipyard.AlertInfo, error) {
	_, err := r.Table(tblNameAlert).Filter(map[string]string{"node": alert.Node}).Update(alert).RunWrite(m.session)
	if err != nil {
		return alert, err
	}
	return alert, nil
}

func (m DefaultManager) GetHostInfo(addr string) (*shipyard.RespHostInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)
	res ,err := r.Table(tblNameHostInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		return nil, ErrHostInfoDoesNotExist
	}
	hostInfo := new(shipyard.RespHostInfo)
	err = res.One(hostInfo)
	if err != nil {
		return nil, err
	}

	return hostInfo, nil
}
func (m DefaultManager) GetMemInfo(addr string) (*shipyard.RespMemInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)

	res ,err := r.Table(tblNameMemInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		return nil, ErrMemInfoDoesNotExist
	}
	memInfo := new(shipyard.RespMemInfo)
	err = res.One(memInfo)
	if err != nil {
		return nil, err
	}

	return memInfo, nil
}

func (m DefaultManager) GetNetInfo(addr string) (*shipyard.RespNetInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)

	res ,err := r.Table(tblNameNetInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		return nil, ErrNetInfoDoesNotExist
	}
	netInfo := new(shipyard.RespNetInfo)
	err = res.One(netInfo)
	if err != nil {
		return nil, err
	}

	return netInfo, nil

}
func (m DefaultManager) GetLoadInfo(addr string) (*shipyard.RespLoadInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)

	res ,err := r.Table(tblNameLoadInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		return nil, ErrLoadInfoDoesNotExist
	}
	loadInfo := new(shipyard.RespLoadInfo)
	err = res.One(loadInfo)
	if err != nil {
		return nil, err
	}

	return loadInfo, nil

}
func (m DefaultManager) GetDiskInfo(addr string) (*shipyard.RespDiskInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)

	res ,err := r.Table(tblNameDiskInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		return nil, ErrDiskInfoDoesNotExist
	}
	diskInfo := new(shipyard.RespDiskInfo)
	err = res.One(diskInfo)
	if err != nil {
		return nil, err
	}

	return diskInfo, nil

}
func (m DefaultManager) GetCpuInfo(addr string) (*shipyard.RespCpuInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)

	res ,err := r.Table(tblNameCpuInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		return nil, ErrCpuInfoDoesNotExist
	}
	cpuInfo := new(shipyard.RespCpuInfo)
	err = res.One(cpuInfo)
	if err != nil {
		return nil, err
	}

	return cpuInfo, nil

}
func (m DefaultManager) GetUserInfo(addr string) (*shipyard.RespUserInfo, error) {
	b, err := base64.URLEncoding.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	addr = string(b)

	res ,err := r.Table(tblNameUserInfo).Filter(map[string]string{"node": addr}).OrderBy(r.Desc("reqtime")).Run(m.session)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if res.IsNil() {
		return nil, ErrUserInfoDoesNotExist
	}
	userInfo := new(shipyard.RespUserInfo)
	err = res.One(userInfo)
	if err != nil {
		return nil, err
	}

	return userInfo, nil

}

func (m DefaultManager) SaveServiceKey(key *auth.ServiceKey) error {
	if _, err := r.Table(tblNameServiceKeys).Insert(key).RunWrite(m.session); err != nil {
		return err
	}

	m.logEvent("add-service-key", fmt.Sprintf("description=%s", key.Description), []string{"security"})

	return nil
}

func (m DefaultManager) RemoveServiceKey(key string) error {
	if _, err := r.Table(tblNameServiceKeys).Filter(map[string]string{"key": key}).Delete().RunWrite(m.session); err != nil {
		return err
	}

	m.logEvent("delete-service-key", fmt.Sprintf("key=%s", key), []string{"security"})

	return nil
}

func (m DefaultManager) SaveEvent(event *shipyard.Event) error {
	if _, err := r.Table(tblNameEvents).Insert(event).RunWrite(m.session); err != nil {
		return err
	}

	return nil
}

func (m DefaultManager) Events(limit int) ([]*shipyard.Event, error) {
	t := r.Table(tblNameEvents).OrderBy(r.Desc("Time"))
	if limit > -1 {
		t.Limit(limit)
	}
	res, err := t.Run(m.session)
	if err != nil {
		return nil, err
	}
	events := []*shipyard.Event{}
	if err := res.All(&events); err != nil {
		return nil, err
	}
	return events, nil
}

func (m DefaultManager) PurgeEvents() error {
	if _, err := r.Table(tblNameEvents).Delete().RunWrite(m.session); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) ServiceKey(key string) (*auth.ServiceKey, error) {
	res, err := r.Table(tblNameServiceKeys).Filter(map[string]string{"key": key}).Run(m.session)
	if err != nil {
		return nil, err

	}
	if res.IsNil() {
		return nil, ErrServiceKeyDoesNotExist
	}
	var k *auth.ServiceKey
	if err := res.One(&k); err != nil {
		return nil, err
	}
	return k, nil
}

func (m DefaultManager) ServiceKeys() ([]*auth.ServiceKey, error) {
	res, err := r.Table(tblNameServiceKeys).Run(m.session)
	if err != nil {
		return nil, err
	}
	keys := []*auth.ServiceKey{}
	if err := res.All(&keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (m DefaultManager) Accounts() ([]*auth.Account, error) {
	res, err := r.Table(tblNameAccounts).OrderBy(r.Asc("username")).Run(m.session)
	if err != nil {
		return nil, err
	}
	accounts := []*auth.Account{}
	if err := res.All(&accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (m DefaultManager) Account(username string) (*auth.Account, error) {
	res, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Run(m.session)
	if err != nil {
		return nil, err

	}
	if res.IsNil() {
		return nil, ErrAccountDoesNotExist
	}
	var account *auth.Account
	if err := res.One(&account); err != nil {
		return nil, err
	}
	return account, nil
}

func (m DefaultManager) SaveAccount(account *auth.Account) error {
	var (
		hash      string
		eventType string
	)
	if account.Password != "" {
		h, err := auth.Hash(account.Password)
		if err != nil {
			return err
		}

		hash = h
	}
	// check if exists; if so, update
	acct, err := m.Account(account.Username)
	if err != nil && err != ErrAccountDoesNotExist {
		return err
	}

	// update
	if acct != nil {
		updates := map[string]interface{}{
			"first_name": account.FirstName,
			"last_name":  account.LastName,
			"roles":      account.Roles,
		}
		if account.Password != "" {
			updates["password"] = hash
		}

		if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": account.Username}).Update(updates).RunWrite(m.session); err != nil {
			return err
		}

		eventType = "update-account"
	} else {
		account.Password = hash
		if _, err := r.Table(tblNameAccounts).Insert(account).RunWrite(m.session); err != nil {
			return err
		}

		eventType = "add-account"
	}

	m.logEvent(eventType, fmt.Sprintf("username=%s", account.Username), []string{"security"})

	return nil
}

func (m DefaultManager) DeleteAccount(account *auth.Account) error {
	res, err := r.Table(tblNameAccounts).Filter(map[string]string{"id": account.ID}).Delete().Run(m.session)
	if err != nil {
		return err
	}

	if res.IsNil() {
		return ErrAccountDoesNotExist
	}

	m.logEvent("delete-account", fmt.Sprintf("username=%s", account.Username), []string{"security"})

	return nil
}

func (m DefaultManager) Roles() ([]*auth.ACL, error) {
	roles := auth.DefaultACLs()
	return roles, nil
}

func (m DefaultManager) Role(name string) (*auth.ACL, error) {
	acls, err := m.Roles()
	if err != nil {
		return nil, err
	}

	for _, r := range acls {
		if r.RoleName == name {
			return r, nil
		}
	}

	return nil, nil
}

func (m DefaultManager) GetAuthenticator() auth.Authenticator {
	return m.authenticator
}

func (m DefaultManager) Authenticate(username, password string) (bool, error) {
	// only get the account to get the hashed password if using the builtin auth
	passwordHash := ""
	if m.authenticator.Name() == "builtin" {
		acct, err := m.Account(username)
		if err != nil {
			log.Error(err)
			return false, ErrLoginFailure
		}

		passwordHash = acct.Password
	}

	a, err := m.authenticator.Authenticate(username, password, passwordHash)
	if !a || err != nil {
		log.Error(ErrLoginFailure)
		return false, ErrLoginFailure
	}

	return true, nil
}

func (m DefaultManager) NewAuthToken(username string, userAgent string) (*auth.AuthToken, error) {
	tk, err := m.authenticator.GenerateToken()
	if err != nil {
		return nil, err
	}
	acct, err := m.Account(username)
	if err != nil {
		return nil, err
	}
	token := &auth.AuthToken{}
	tokens := acct.Tokens
	found := false
	for _, t := range tokens {
		if t.UserAgent == userAgent {
			found = true
			t.Token = tk
			token = t
			break
		}
	}
	if !found {
		token = &auth.AuthToken{
			UserAgent: userAgent,
			Token:     tk,
		}
		tokens = append(tokens, token)
	}
	// delete token
	if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Filter(r.Row.Field("user_agent").Eq(userAgent)).Delete().Run(m.session); err != nil {
		return nil, err
	}
	// add
	if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Update(map[string]interface{}{"tokens": tokens}).RunWrite(m.session); err != nil {
		return nil, err
	}
	return token, nil
}

func (m DefaultManager) VerifyAuthToken(username, token string) error {
	acct, err := m.Account(username)
	if err != nil {
		return err
	}
	found := false
	for _, t := range acct.Tokens {
		if token == t.Token {
			found = true
			break
		}
	}
	if !found {
		return ErrInvalidAuthToken
	}
	return nil
}

func (m DefaultManager) VerifyServiceKey(key string) error {
	if _, err := m.ServiceKey(key); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) NewServiceKey(description string) (*auth.ServiceKey, error) {
	k, err := m.authenticator.GenerateToken()
	if err != nil {
		return nil, err
	}
	key := &auth.ServiceKey{
		Key:         k[24:],
		Description: description,
	}
	if err := m.SaveServiceKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (m DefaultManager) ChangePassword(username, password string) error {
	if !m.authenticator.IsUpdateSupported() {
		return fmt.Errorf("not supported for authenticator: %s", m.authenticator.Name())
	}

	hash, err := auth.Hash(password)
	if err != nil {
		return err
	}

	if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Update(map[string]string{"password": hash}).Run(m.session); err != nil {
		return err
	}

	m.logEvent("change-password", username, []string{"security"})

	return nil
}

func (m DefaultManager) WebhookKey(key string) (*dockerhub.WebhookKey, error) {
	res, err := r.Table(tblNameWebhookKeys).Filter(map[string]string{"key": key}).Run(m.session)
	if err != nil {
		return nil, err

	}

	if res.IsNil() {
		return nil, ErrWebhookKeyDoesNotExist

	}

	var k *dockerhub.WebhookKey
	if err := res.One(&k); err != nil {
		return nil, err

	}

	return k, nil
}

func (m DefaultManager) WebhookKeys() ([]*dockerhub.WebhookKey, error) {
	res, err := r.Table(tblNameWebhookKeys).OrderBy(r.Asc("image")).Run(m.session)
	if err != nil {
		return nil, err
	}
	keys := []*dockerhub.WebhookKey{}
	if err := res.All(&keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (m DefaultManager) NewWebhookKey(image string) (*dockerhub.WebhookKey, error) {
	k := generateId(16)
	key := &dockerhub.WebhookKey{
		Key:   k,
		Image: image,
	}

	if err := m.SaveWebhookKey(key); err != nil {
		return nil, err
	}

	return key, nil
}

func (m DefaultManager) SaveWebhookKey(key *dockerhub.WebhookKey) error {
	if _, err := r.Table(tblNameWebhookKeys).Insert(key).RunWrite(m.session); err != nil {
		return err

	}

	m.logEvent("add-webhook-key", fmt.Sprintf("image=%s", key.Image), []string{"webhook"})

	return nil
}

func (m DefaultManager) DeleteWebhookKey(id string) error {
	key, err := m.WebhookKey(id)
	if err != nil {
		return err

	}
	res, err := r.Table(tblNameWebhookKeys).Get(key.ID).Delete().Run(m.session)
	if err != nil {
		return err

	}

	if res.IsNil() {
		return ErrWebhookKeyDoesNotExist

	}

	m.logEvent("delete-webhook-key", fmt.Sprintf("image=%s", key.Image), []string{"webhook"})

	return nil
}

func (m DefaultManager) Nodes() ([]*shipyard.Node, error) {
	info, err := m.client.Info()
	if err != nil {
		return nil, err
	}

	nodes, err := parseClusterNodes(info.DriverStatus)
	if err != nil {
		return nil, err
	}

	return nodes, nil
}

func (m DefaultManager) Node(name string) (*shipyard.Node, error) {
	nodes, err := m.Nodes()
	if err != nil {
		return nil, err
	}

	for _, node := range nodes {
		if node.Name == name {
			return node, nil
		}
	}

	return nil, nil
}

func (m DefaultManager) PingRegistry(registry *shipyard.Registry) error {

	// TODO: Please note the trailing forward slash / which is needed for Artifactory, else you get a 404.
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v2/", registry.Addr), nil)

	if err != nil {
		return err
	}

	req.SetBasicAuth(registry.Username, registry.Password)

	var tlsConfig *tls.Config

	tlsConfig = nil

	if registry.TlsSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Create unsecured client
	trans := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: trans}

	resp, err := client.Do(req)

	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}

	return nil
}

func (m DefaultManager) AddRegistry(registry *shipyard.Registry) error {

	if err := registry.InitRegistryClient(); err != nil {
		return err
	}

	// TODO: consider not doing a test on adding the record, perhaps have a pingRegistry route that does this through API.
	if err := m.PingRegistry(registry); err != nil {
		log.Error(err)
		return ErrCannotPingRegistry
	}

	if _, err := r.Table(tblNameRegistries).Insert(registry).RunWrite(m.session); err != nil {
		return err
	}
	m.logEvent("add-registry", fmt.Sprintf("name=%s endpoint=%s", registry.Name, registry.Addr), []string{"registry"})

	return nil
}

func (m DefaultManager) RemoveRegistry(registry *shipyard.Registry) error {
	res, err := r.Table(tblNameRegistries).Get(registry.ID).Delete().Run(m.session)
	defer res.Close()
	if err != nil {
		return err
	}

	if res.IsNil() {
		return ErrRegistryDoesNotExist
	}

	m.logEvent("delete-registry", fmt.Sprintf("name=%s endpoint=%s", registry.Name, registry.Addr), []string{"registry"})

	return nil
}

func (m DefaultManager) Registries() ([]*shipyard.Registry, error) {
	res, err := r.Table(tblNameRegistries).OrderBy(r.Asc("name")).Run(m.session)
	defer res.Close()
	if err != nil {
		return nil, err
	}

	regs := []*shipyard.Registry{}
	if err := res.All(&regs); err != nil {
		return nil, err
	}

	for _, registry := range regs {
		if err := registry.InitRegistryClient(); err != nil {
			log.Errorf("%s", err.Error())
		}
	}

	return regs, nil
}

func (m DefaultManager) Registry(id string) (*shipyard.Registry, error) {
	res, err := r.Table(tblNameRegistries).Filter(map[string]string{"id": id}).Run(m.session)
	defer res.Close()
	if err != nil {
		return nil, err

	}
	if res.IsNil() {
		return nil, ErrRegistryDoesNotExist
	}
	var reg *shipyard.Registry
	if err := res.One(&reg); err != nil {
		return nil, err
	}

	if err := reg.InitRegistryClient(); err != nil {
		log.Errorf("%s", err.Error())
		return reg, err
	}

	return reg, nil
}

func (m DefaultManager) RegistryByAddress(addr string) (*shipyard.Registry, error) {
	res, err := r.Table(tblNameRegistries).Filter(map[string]string{"addr": addr}).Run(m.session)
	defer res.Close()
	if err != nil {
		return nil, err
	}
	if res.IsNil() {
		log.Debugf("Could not find registry with address %s", addr)
		return nil, ErrRegistryDoesNotExist
	}
	var reg *shipyard.Registry
	if err := res.One(&reg); err != nil {
		return nil, err
	}

	if err := reg.InitRegistryClient(); err != nil {
		log.Error(err)
		return reg, err
	}

	return reg, nil
}

func (m DefaultManager) CreateConsoleSession(c *shipyard.ConsoleSession) error {
	if _, err := r.Table(tblNameConsole).Insert(c).RunWrite(m.session); err != nil {
		return err
	}

	m.logEvent("create-console-session", fmt.Sprintf("container=%s", c.ContainerID), []string{"console"})

	return nil
}

func (m DefaultManager) RemoveConsoleSession(c *shipyard.ConsoleSession) error {
	res, err := r.Table(tblNameConsole).Get(c.ID).Delete().Run(m.session)
	if err != nil {
		return err
	}

	if res.IsNil() {
		return ErrConsoleSessionDoesNotExist
	}

	return nil
}

func (m DefaultManager) ConsoleSession(token string) (*shipyard.ConsoleSession, error) {
	res, err := r.Table(tblNameConsole).Filter(map[string]string{"token": token}).Run(m.session)
	if err != nil {
		return nil, err
	}

	if res.IsNil() {
		return nil, ErrConsoleSessionDoesNotExist
	}

	var c *shipyard.ConsoleSession
	if err := res.One(&c); err != nil {
		return nil, err
	}

	return c, nil
}

func (m DefaultManager) ValidateConsoleSessionToken(containerId string, token string) bool {
	cs, err := m.ConsoleSession(token)
	if err != nil {
		log.Errorf("error validating console session token: %s", err)
		return false
	}

	if cs == nil || cs.ContainerID != containerId {
		log.Warnf("unauthorized token request: %s", token)
		return false
	}

	if err := m.RemoveConsoleSession(cs); err != nil {
		log.Error(err)
		return false
	}

	return true
}
