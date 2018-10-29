package api

import (
	"encoding/json"
	"net/http"
	//"fmt"
	//"strconv"

	"github.com/gorilla/mux"
	"github.com/shipyard/shipyard"
)

func (a *Api) servicesType(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	servicesType, err := a.manager.ServicesType()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(servicesType); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) addServiceType(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	var s *shipyard.ServiceTypeInfo
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	servicesType, err := a.manager.AddServiceType(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(servicesType); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a *Api) deleteServiceType(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	serviceTypeId := vars["serviceTypeId"]
	servicesType, err := a.manager.DeleteServiceType(serviceTypeId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(servicesType); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}
