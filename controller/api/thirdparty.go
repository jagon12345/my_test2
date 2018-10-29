package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/shipyard/shipyard"
)

func (a *Api) thirdpartyServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	nodes, err := a.manager.ThirdpartyServices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(nodes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) getThirdpartyService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	node, err := a.manager.GetThirdpartyService(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) addThirdpartyService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var s *shipyard.ThirdpartyServiceInfo
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	node, err := a.manager.AddThirdpartyService(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) updateThirdpartyService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var s *shipyard.ThirdpartyServiceInfo
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	node, err := a.manager.UpdateThirdpartyService(s, serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) deleteThirdpartyService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceId := vars["serviceid"]
	node, err := a.manager.DeleteThirdpartyService(serviceId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
