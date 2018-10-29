package api

import (
	"encoding/json"
	"net/http"
	//"strconv"
	"fmt"
	"io"

	"github.com/gorilla/mux"
	"github.com/shipyard/shipyard"
)

func (a *Api) services(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	services, err := a.manager.Services()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) getService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	services, err := a.manager.GetService(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

//func (a *Api) queryServices(w http.ResponseWriter, r *http.Request) {
//	w.Header().Set("content-type", "application/json")
//
//	vars := mux.Vars(r)
//	host := vars["host"]
//	serviceType := vars["type"]
//	status := vars["status"]
//	services, err := a.manager.QueryServices(host, serviceType, status)
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	if err := json.NewEncoder(w).Encode(services); err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//}

func (a *Api) autoGetYmlConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var ci []*shipyard.Container
	if err := json.NewDecoder(r.Body).Decode(&ci); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	services, err := a.manager.AutoGetYmlConfig(ci)
	fmt.Println("==========3")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("==========4")

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}


func (a *Api) addService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var s *shipyard.ServiceInfo
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	services, err := a.manager.AddService(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) updateService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var s *shipyard.ServiceInfo
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	services, err := a.manager.UpdateService(s, serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) deleteService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	services, err := a.manager.DeleteService(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) getServiceYmlConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	services, err := a.manager.GetServiceYmlConfig(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) getServiceContainers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	services, err := a.manager.GetServiceContainers(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) getServiceApis(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	apis, err := a.manager.GetServiceApis(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(apis); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) getServiceAddr(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	services, err := a.manager.GetServiceAddr(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) exportServiceYmlConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	tarName, out, err := a.manager.ExportServiceYmlConfig(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dis := fmt.Sprintf("attachment; filename=%s", tarName)
    w.Header().Set("Content-Disposition", dis)
    w.Header().Set("Content-Type", "application/x-tar")
	io.Copy(w, out)

}
