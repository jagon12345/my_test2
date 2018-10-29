package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/shipyard/shipyard"
)

func (a *Api) nodesInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	nodesInfo, err := a.manager.NodesInfo()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(nodesInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) nodesGeneralInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	generalInfo, err := a.manager.NodesGeneralInfo()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(generalInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) nodesGetAlert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	alert, err := a.manager.NodesGetAlert(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(alert); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) nodesSetAlert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var alt *shipyard.AlertInfo
	if err := json.NewDecoder(r.Body).Decode(&alt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	alert, err := a.manager.NodesSetAlert(alt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(alert); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) nodesModifyAlert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var alt *shipyard.AlertInfo
	if err := json.NewDecoder(r.Body).Decode(&alt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	alert, err := a.manager.NodesModifyAlert(alt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(alert); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}



func (a *Api) getHostInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	hostInfo, err := a.manager.GetHostInfo(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(hostInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) getMemInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	memInfo, err := a.manager.GetMemInfo(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(memInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) getNetInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	netInfo, err := a.manager.GetNetInfo(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(netInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) getLoadInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	loadInfo, err := a.manager.GetLoadInfo(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(loadInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) getDiskInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	diskInfo, err := a.manager.GetDiskInfo(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(diskInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) getCpuInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	cpuInfo, err := a.manager.GetCpuInfo(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(cpuInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) getUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	userInfo, err := a.manager.GetUserInfo(nodeaddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

