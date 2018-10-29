package api

import (
	"fmt"
	"io/ioutil"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mailgun/oxy/forward"
	"github.com/shipyard/shipyard/auth"
	"github.com/shipyard/shipyard/controller/manager"
	"github.com/shipyard/shipyard/controller/middleware/access"
	"github.com/shipyard/shipyard/controller/middleware/audit"
	mAuth "github.com/shipyard/shipyard/controller/middleware/auth"
	"github.com/shipyard/shipyard/tlsutils"
	"golang.org/x/net/websocket"
)

type (
	Api struct {
		listenAddr         string
		manager            manager.Manager
		authWhitelistCIDRs []string
		enableCors         bool
		serverVersion      string
		allowInsecure      bool
		tlsCACertPath      string
		tlsCertPath        string
		tlsKeyPath         string
		dUrl               string
		fwd                *forward.Forwarder
	}

	ApiConfig struct {
		ListenAddr         string
		Manager            manager.Manager
		AuthWhiteListCIDRs []string
		EnableCORS         bool
		AllowInsecure      bool
		TLSCACertPath      string
		TLSCertPath        string
		TLSKeyPath         string
	}

	Credentials struct {
		Username string `json:"username,omitempty"`
		Password string `json:"password,omitempty"`
	}
)

func writeCorsHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	w.Header().Add("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
}

func NewApi(config ApiConfig) (*Api, error) {
	return &Api{
		listenAddr:         config.ListenAddr,
		manager:            config.Manager,
		authWhitelistCIDRs: config.AuthWhiteListCIDRs,
		enableCors:         config.EnableCORS,
		allowInsecure:      config.AllowInsecure,
		tlsCertPath:        config.TLSCertPath,
		tlsKeyPath:         config.TLSKeyPath,
		tlsCACertPath:      config.TLSCACertPath,
	}, nil 
}

func (a *Api) Run() error {
	globalMux := http.NewServeMux()
	controllerManager := a.manager
	client := a.manager.DockerClient()

	// forwarder for swarm
	var err error
	a.fwd, err = forward.New()
	if err != nil {
		return err
	}

	u := client.URL

	// setup redirect target to swarm
	scheme := "http://"

	// check if TLS is enabled and configure if so
	if client.TLSConfig != nil {
		log.Debug("configuring ssl for swarm redirect")
		scheme = "https://"
		// setup custom roundtripper with TLS transport
		r := forward.RoundTripper(
			&http.Transport{
				TLSClientConfig: client.TLSConfig,
			})
		f, err := forward.New(r)
		if err != nil {
			return err
		}

		a.fwd = f
	}

	a.dUrl = fmt.Sprintf("%s%s", scheme, u.Host)

	log.Debugf("configured docker proxy target: %s", a.dUrl)

	swarmRedirect := http.HandlerFunc(a.swarmRedirect)

	swarmHijack := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.swarmHijack(client.TLSConfig, a.dUrl, w, req)
	})

	apiRouter := mux.NewRouter()
	apiRouter.HandleFunc("/api/accounts", a.accounts).Methods("GET")
	apiRouter.HandleFunc("/api/accounts", a.saveAccount).Methods("POST")
	apiRouter.HandleFunc("/api/accounts/{username}", a.account).Methods("GET")
	apiRouter.HandleFunc("/api/accounts/{username}", a.deleteAccount).Methods("DELETE")
	apiRouter.HandleFunc("/api/roles", a.roles).Methods("GET")
	apiRouter.HandleFunc("/api/roles/{name}", a.role).Methods("GET")
	apiRouter.HandleFunc("/api/nodes", a.nodes).Methods("GET")
	apiRouter.HandleFunc("/api/nodes/{name}", a.node).Methods("GET")
	apiRouter.HandleFunc("/api/containers/{id}/scale", a.scaleContainer).Methods("POST")

	// 前端显示的标题设置
	apiRouter.HandleFunc("/api/settings", a.settings).Methods("GET")
	apiRouter.HandleFunc("/api/settings", a.updateSettings).Methods("GET")
	// 节点的增加和删除
	apiRouter.HandleFunc("/api/nodes/delete/{nodeaddr}", a.deleteNode).Methods("DELETE") //===new
	// 镜像处理
	apiRouter.HandleFunc("/api/images", a.images).Methods("GET") //===new
	//apiRouter.HandleFunc("/api/images/{imageid}/delete", a.imageDelete).Methods("DELETE") //===new
	apiRouter.HandleFunc("/api/images/pullimage", a.pullImage).Queries("tag", "{tag}", "nodeaddr", "{nodeaddr}").Methods("GET") //===new
	// 镜像的批量删除和下载
	// 应该前端可以控制批量删除
	//apiRouter.HandleFunc("/api/images/batch/delete", a.imagesBatchDelete).Methods("DELETE") //===new
	apiRouter.HandleFunc("/api/images/batch/download", a.imagesBatchDownload).Methods("GET") //===new

	// 读取编排文件以及通过编排文件部署容器
	apiRouter.HandleFunc("/api/containers/ymldeploy", a.ymlDeployRedirect).Methods("POST") //===new
	apiRouter.HandleFunc("/api/containers/getcontainer/{nodeaddr}", a.listNodeContainer).Methods("GET") //===new
	// 新增服务管理
	apiRouter.HandleFunc("/api/services", a.services).Methods("GET")//===new
	//apiRouter.HandleFunc("/api/services/query", a.queryServices).Queries("host", "{host}", "type", "{type}", "status", "{status}").Methods("GET") //===new
	apiRouter.HandleFunc("/api/services/get/{serviceid}", a.getService).Methods("GET")//===new
	apiRouter.HandleFunc("/api/services/autogetconfig", a.autoGetYmlConfig).Methods("POST") //===new
	apiRouter.HandleFunc("/api/services/add", a.addService).Methods("POST")             //===new
	apiRouter.HandleFunc("/api/services/update/{serviceid}", a.updateService).Methods("PUT")//===new
	apiRouter.HandleFunc("/api/services/delete/{serviceid}", a.deleteService).Methods("DELETE") //===new

	apiRouter.HandleFunc("/api/services/{serviceid}/getconfig", a.getServiceYmlConfig).Methods("GET")       //===new
	apiRouter.HandleFunc("/api/services/{serviceid}/getcontainers", a.getServiceContainers).Methods("GET")  //===new
	apiRouter.HandleFunc("/api/services/{serviceid}/getapis", a.getServiceApis).Methods("GET")              //===new
	apiRouter.HandleFunc("/api/services/{serviceid}/getaddr", a.getServiceAddr).Methods("GET")              //===new
	apiRouter.HandleFunc("/api/services/{serviceid}/exportconfig", a.exportServiceYmlConfig).Methods("GET") //===new
	// 服务类型管理
	apiRouter.HandleFunc("/api/servicestype", a.servicesType).Methods("GET")          //===new
	apiRouter.HandleFunc("/api/servicestype/add", a.addServiceType).Methods("POST")   //===new
	apiRouter.HandleFunc("/api/servicestype/{serviceTypeId}", a.deleteServiceType).Methods("DELETE") //===new
	// 第三方服务管理
	apiRouter.HandleFunc("/api/services/thirdparty/getlist", a.thirdpartyServices).Methods("GET")//===new
	apiRouter.HandleFunc("/api/services/thirdparty/get/{serviceid}", a.getThirdpartyService).Methods("GET")          //===new
	apiRouter.HandleFunc("/api/services/thirdparty/add", a.addThirdpartyService).Methods("POST") //===new
	apiRouter.HandleFunc("/api/services/thirdparty/update/{serviceid}", a.updateThirdpartyService).Methods("PUT")    //===new
	apiRouter.HandleFunc("/api/services/thirdparty/delete/{serviceid}", a.deleteThirdpartyService).Methods("DELETE") //===new
	// 服务监控
	apiRouter.HandleFunc("/api/serverinfo/nodes", a.nodesInfo).Methods("GET")                //===new
	apiRouter.HandleFunc("/api/serverinfo/nodes/general", a.nodesGeneralInfo).Methods("GET") //===new
	apiRouter.HandleFunc("/api/serverinfo/nodes/getalert/{nodeaddr}", a.nodesGetAlert).Methods("GET")   //===new
	apiRouter.HandleFunc("/api/serverinfo/nodes/setalert", a.nodesSetAlert).Methods("POST")   //===new
	apiRouter.HandleFunc("/api/serverinfo/nodes/modifyalert", a.nodesModifyAlert).Methods("PUT")   //===new
	apiRouter.HandleFunc("/api/serverinfo/hostinfo/{nodeaddr}", a.getHostInfo).Methods("GET")    //===new
	apiRouter.HandleFunc("/api/serverinfo/meminfo/{nodeaddr}", a.getMemInfo).Methods("GET")      //===new
	apiRouter.HandleFunc("/api/serverinfo/netinfo/{nodeaddr}", a.getNetInfo).Methods("GET")      //===new
	apiRouter.HandleFunc("/api/serverinfo/loadinfo/{nodeaddr}", a.getLoadInfo).Methods("GET")    //===new
	apiRouter.HandleFunc("/api/serverinfo/diskinfo/{nodeaddr}", a.getDiskInfo).Methods("GET")    //===new
	apiRouter.HandleFunc("/api/serverinfo/cpuinfo/{nodeaddr}", a.getCpuInfo).Methods("GET")      //===new
	apiRouter.HandleFunc("/api/serverinfo/userinfo/{nodeaddr}", a.getUserInfo).Methods("GET")    //===new

	apiRouter.HandleFunc("/api/events", a.events).Methods("GET")
	apiRouter.HandleFunc("/api/events", a.purgeEvents).Methods("DELETE")
	apiRouter.HandleFunc("/api/registries", a.registries).Methods("GET")
	apiRouter.HandleFunc("/api/registries", a.addRegistry).Methods("POST")
	apiRouter.HandleFunc("/api/registries/{registryId}", a.registry).Methods("GET")
	apiRouter.HandleFunc("/api/registries/{registryId}", a.removeRegistry).Methods("DELETE")
	apiRouter.HandleFunc("/api/registries/{registryId}/repositories", a.repositories).Methods("GET")
	apiRouter.HandleFunc("/api/registries/{registryId}/repositories/{repo:.*}", a.repository).Methods("GET")
	apiRouter.HandleFunc("/api/registries/{registryId}/repositories/{repo:.*}", a.deleteRepository).Methods("DELETE")
	apiRouter.HandleFunc("/api/servicekeys", a.serviceKeys).Methods("GET")
	apiRouter.HandleFunc("/api/servicekeys", a.addServiceKey).Methods("POST")
	apiRouter.HandleFunc("/api/servicekeys", a.removeServiceKey).Methods("DELETE")
	apiRouter.HandleFunc("/api/webhookkeys", a.webhookKeys).Methods("GET")
	apiRouter.HandleFunc("/api/webhookkeys/{id}", a.webhookKey).Methods("GET")
	apiRouter.HandleFunc("/api/webhookkeys", a.addWebhookKey).Methods("POST")
	apiRouter.HandleFunc("/api/webhookkeys/{id}", a.deleteWebhookKey).Methods("DELETE")
	apiRouter.HandleFunc("/api/consolesession/{container}", a.createConsoleSession).Methods("GET")
	apiRouter.HandleFunc("/api/consolesession/{token}", a.consoleSession).Methods("GET")
	apiRouter.HandleFunc("/api/consolesession/{token}", a.removeConsoleSession).Methods("DELETE")

	// global handler
	globalMux.Handle("/", http.FileServer(http.Dir("static")))

	// what's this suppose todo?
	// looks like used to record events.
	// turns out it is used to exclude from recording events
	// 前端做服务监控会发送大量的请求，这里不记录events
	auditExcludes := []string{
		"^/networks",
		"^/containers/json",
		"^/images/json",
		"^/api/serverinfo/cpuinfo",
		//"^/api/serverinfo/hostinfo",
		"^/api/serverinfo/meminfo",
		"^/api/serverinfo/netinfo",
		"^/api/serverinfo/diskinfo",
		"^/api/serverinfo/userinfo",
		"^/api/serverinfo/loadinfo",
		"^/api/events",
	}
	apiAuditor := audit.NewAuditor(controllerManager, auditExcludes)

	// api router; protected by auth
	apiAuthRouter := negroni.New()
	apiAuthRequired := mAuth.NewAuthRequired(controllerManager, a.authWhitelistCIDRs)
	apiAccessRequired := access.NewAccessRequired(controllerManager)
	apiAuthRouter.Use(negroni.HandlerFunc(apiAuthRequired.HandlerFuncWithNext))
	apiAuthRouter.Use(negroni.HandlerFunc(apiAccessRequired.HandlerFuncWithNext))
	apiAuthRouter.Use(negroni.HandlerFunc(apiAuditor.HandlerFuncWithNext))
	apiAuthRouter.UseHandler(apiRouter)
	globalMux.Handle("/api/", apiAuthRouter)

	// account router ; protected by auth
	accountRouter := mux.NewRouter()
	accountRouter.HandleFunc("/account/changepassword", a.changePassword).Methods("POST")
	accountAuthRouter := negroni.New()
	accountAuthRequired := mAuth.NewAuthRequired(controllerManager, a.authWhitelistCIDRs)
	accountAuthRouter.Use(negroni.HandlerFunc(accountAuthRequired.HandlerFuncWithNext))
	accountAuthRouter.Use(negroni.HandlerFunc(apiAuditor.HandlerFuncWithNext))
	accountAuthRouter.UseHandler(accountRouter)
	globalMux.Handle("/account/", accountAuthRouter)

	// login handler; public
	loginRouter := mux.NewRouter()
	loginRouter.HandleFunc("/auth/login", a.login).Methods("POST")
	globalMux.Handle("/auth/", loginRouter)
	globalMux.Handle("/exec", websocket.Handler(a.execContainer))

	// hub handler; public
	hubRouter := mux.NewRouter()
	hubRouter.HandleFunc("/hub/webhook/{id}", a.hubWebhook).Methods("POST")
	globalMux.Handle("/hub/", hubRouter)

	// swarm
	swarmRouter := mux.NewRouter()
	// these are pulled from the swarm api code to proxy and allow
	// usage with the standard Docker cli
	m := map[string]map[string]http.HandlerFunc{
		"GET": {
			"/_ping":                          swarmRedirect,
			"/events":                         swarmRedirect,
			"/info":                           swarmRedirect,
			"/version":                        swarmRedirect,
			"/images/json":                    swarmRedirect,
			"/images/viz":                     swarmRedirect,
			"/images/search":                  swarmRedirect,
			"/images/get":                     swarmRedirect,
			"/images/{name:.*}/get":           swarmRedirect,
			"/images/{name:.*}/history":       swarmRedirect,
			"/images/{name:.*}/json":          swarmRedirect,
			"/networks":                       swarmRedirect,
			"/networks/{name:.*}":             swarmRedirect,
			"/containers/ps":                  swarmRedirect,
			"/containers/json":                swarmRedirect,
			"/containers/{name:.*}/export":    swarmRedirect,
			"/containers/{name:.*}/changes":   swarmRedirect,
			"/containers/{name:.*}/json":      swarmRedirect,
			"/containers/{name:.*}/top":       swarmRedirect,
			"/containers/{name:.*}/logs":      swarmRedirect,
			"/containers/{name:.*}/stats":     swarmRedirect,
			"/containers/{name:.*}/attach/ws": swarmHijack,
			"/exec/{execid:.*}/json":          swarmRedirect,
		},
		"POST": {
			"/auth":                          swarmRedirect,
			"/commit":                        swarmRedirect,
			"/build":                         swarmRedirect,
			"/images/create":                 swarmRedirect,
			"/images/load":                   swarmRedirect,
			"/images/{name:.*}/push":         swarmRedirect,
			"/images/{name:.*}/tag":          swarmRedirect,
			"/networks/create":               swarmRedirect,
			"/networks/{name:.*}/connect":    swarmRedirect,
			"/networks/{name:.*}/disconnect": swarmRedirect,
			"/nodes/{id:.*}/update":          swarmRedirect,
			"/containers/create":             swarmRedirect,
			"/containers/{name:.*}/kill":     swarmRedirect,
			"/containers/{name:.*}/pause":    swarmRedirect,
			"/containers/{name:.*}/unpause":  swarmRedirect,
			"/containers/{name:.*}/rename":   swarmRedirect,
			"/containers/{name:.*}/restart":  swarmRedirect,
			"/containers/{name:.*}/start":    swarmRedirect,
			"/containers/{name:.*}/stop":     swarmRedirect,
			"/containers/{name:.*}/wait":     swarmRedirect,
			"/containers/{name:.*}/resize":   swarmRedirect,
			"/containers/{name:.*}/attach":   swarmHijack,
			"/containers/{name:.*}/copy":     swarmRedirect,
			"/containers/{name:.*}/exec":     swarmRedirect,
			"/exec/{execid:.*}/start":        swarmHijack,
			"/exec/{execid:.*}/resize":       swarmRedirect,
		},
		"DELETE": {
			"/networks/{name:.*}":   swarmRedirect,
			"/nodes/{id:.*}":        swarmRedirect,
			"/containers/{name:.*}": swarmRedirect,
			"/images/{name:.*}":     swarmRedirect,
		},
		"OPTIONS": {
			"": swarmRedirect,
		},
	}

	for method, routes := range m {
		for route, fct := range routes {
			localRoute := route
			localFct := fct
			wrap := func(w http.ResponseWriter, r *http.Request) {
				if a.enableCors {
					writeCorsHeaders(w, r)
				}
				localFct(w, r)
			}
			localMethod := method

			// add the new route
			swarmRouter.Path("/v{version:[0-9.]+}" + localRoute).Methods(localMethod).HandlerFunc(wrap)
			swarmRouter.Path(localRoute).Methods(localMethod).HandlerFunc(wrap)
		}
	}

	swarmAuthRouter := negroni.New()
	swarmAuthRequired := mAuth.NewAuthRequired(controllerManager, a.authWhitelistCIDRs)
	swarmAccessRequired := access.NewAccessRequired(controllerManager)
	swarmAuthRouter.Use(negroni.HandlerFunc(swarmAuthRequired.HandlerFuncWithNext))
	swarmAuthRouter.Use(negroni.HandlerFunc(swarmAccessRequired.HandlerFuncWithNext))
	swarmAuthRouter.Use(negroni.HandlerFunc(apiAuditor.HandlerFuncWithNext))
	swarmAuthRouter.UseHandler(swarmRouter)
	globalMux.Handle("/networks", swarmAuthRouter)
	globalMux.Handle("/networks/", swarmAuthRouter)
	globalMux.Handle("/containers/", swarmAuthRouter)
	globalMux.Handle("/_ping", swarmAuthRouter)
	globalMux.Handle("/commit", swarmAuthRouter)
	globalMux.Handle("/build", swarmAuthRouter)
	globalMux.Handle("/events", swarmAuthRouter)
	globalMux.Handle("/version", swarmAuthRouter)
	globalMux.Handle("/images/", swarmAuthRouter)
	globalMux.Handle("/exec/", swarmAuthRouter)
	globalMux.Handle("/v1.14/", swarmAuthRouter)
	globalMux.Handle("/v1.15/", swarmAuthRouter)
	globalMux.Handle("/v1.16/", swarmAuthRouter)
	globalMux.Handle("/v1.17/", swarmAuthRouter)
	globalMux.Handle("/v1.18/", swarmAuthRouter)
	globalMux.Handle("/v1.19/", swarmAuthRouter)
	globalMux.Handle("/v1.20/", swarmAuthRouter)
	globalMux.Handle("/v1.21/", swarmAuthRouter)
	globalMux.Handle("/v1.22/", swarmAuthRouter)
	globalMux.Handle("/v1.23/", swarmAuthRouter)
	globalMux.Handle("/v1.24/", swarmAuthRouter)
	globalMux.Handle("/v1.25/", swarmAuthRouter)
	globalMux.Handle("/v1.26/", swarmAuthRouter)
	globalMux.Handle("/v1.27/", swarmAuthRouter)
	globalMux.Handle("/v1.28/", swarmAuthRouter)
	globalMux.Handle("/v1.29/", swarmAuthRouter)
	globalMux.Handle("/v1.30/", swarmAuthRouter)
	globalMux.Handle("/v1.31/", swarmAuthRouter)
	globalMux.Handle("/v1.32/", swarmAuthRouter)
	globalMux.Handle("/v1.33/", swarmAuthRouter)
	globalMux.Handle("/v1.34/", swarmAuthRouter)
	globalMux.Handle("/v1.35/", swarmAuthRouter)
	globalMux.Handle("/v1.36/", swarmAuthRouter)
	globalMux.Handle("/v1.37/", swarmAuthRouter)

	// check for admin user
	if _, err := controllerManager.Account("admin"); err == manager.ErrAccountDoesNotExist {
		// create roles
		acct := &auth.Account{
			Username:  "admin",
			Password:  "shipyard",
			FirstName: "Shipyard",
			LastName:  "Admin",
			Roles:     []string{"admin"},
		}
		if err := controllerManager.SaveAccount(acct); err != nil {
			log.Fatal(err)
		}
		log.Infof("created admin user: username: admin password: shipyard")
	}

	log.Infof("controller listening on %s", a.listenAddr)

	s := &http.Server{
		Addr:    a.listenAddr,
		Handler: context.ClearHandler(globalMux),
	}

	var runErr error

	if a.tlsCertPath != "" && a.tlsKeyPath != "" {
		log.Infof("using TLS for communication: cert=%s key=%s",
			a.tlsCertPath,
			a.tlsKeyPath,
		)

		// setup TLS config
		var caCert []byte
		if a.tlsCACertPath != "" {
			ca, err := ioutil.ReadFile(a.tlsCACertPath)
			if err != nil {
				return err
			}

			caCert = ca
		}

		serverCert, err := ioutil.ReadFile(a.tlsCertPath)
		if err != nil {
			return err
		}

		serverKey, err := ioutil.ReadFile(a.tlsKeyPath)
		if err != nil {
			return err
		}

		tlsConfig, err := tlsutils.GetServerTLSConfig(caCert, serverCert, serverKey, a.allowInsecure)
		if err != nil {
			return err
		}

		s.TLSConfig = tlsConfig

		runErr = s.ListenAndServeTLS(a.tlsCertPath, a.tlsKeyPath)
	} else {
		runErr = s.ListenAndServe()
	}

	return runErr
}
