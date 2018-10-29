package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func (a *Api) images(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	nodes, err := a.manager.Images()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(nodes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) pullImage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	nodeaddr := vars["nodeaddr"]
	imageTag := vars["imageTag"]
	node, err := a.manager.PullImage(nodeaddr, imageTag)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) imagesBatchDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	//imageList
	//for {
	//	resp, err := client.Do()
	//	io.Copy(w, resp.Body)
	//}
	imageName := r.URL.Query()["imagename"][0]
	node, err := a.manager.ImageBatchDownload(imageName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	newURL := "http://" + node + ":7373/exportimage?imagename=" + imageName
	http.Redirect(w, r, newURL, 301)
}
