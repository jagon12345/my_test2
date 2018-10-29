package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"encoding/base64"
	"fmt"
	"io"
	//"os"
	//"io/ioutil"
	"bytes"
	//"mime/multipart"
	"mime"
	//"bufio"
	//"strings"

	"github.com/gorilla/mux"
)

func (a *Api) scaleContainer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	containerId := vars["id"]
	n := r.URL.Query()["n"]

	if len(n) == 0 {
		http.Error(w, "你必须输入一个数字 (param: n)", http.StatusBadRequest)
		return
	}

	numInstances, err := strconv.Atoi(n[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if numInstances <= 0 {
		http.Error(w, "你必须输入一个有效的值", http.StatusBadRequest)
		return
	}

	result := a.manager.ScaleContainer(containerId, numInstances)
	// If we received any errors, continue to write result to the writer, but return a 500
	if len(result.Errors) > 0 {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}


func (a *Api) ymlDeployRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	node := r.URL.Query()["nodeaddr"][0]
	path := r.URL.Query()["path"][0]
	b, err := base64.URLEncoding.DecodeString(node)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	node = string(b)

	fmt.Println("start parsing............")

	//node := r.MultipartForm.Value["node"][0]
	newURL := fmt.Sprintf("http://%s:7373/deploy?path=%s", node, path)
	fmt.Println(newURL)
	fmt.Println(r.ContentLength)
	// 这样传过去的r, body传不过去, why ??
	//http.Redirect(w, r, newURL, 301)
	// 因为301重定向GET方法，而POST方法不太安全?所以尽量不要重定向POST?
	bodyCopy := new(bytes.Buffer)
	//reader := multipart.NewReader(k)
	//io.Copy(writer, io.Body)
	req, err := http.NewRequest("POST", newURL, io.TeeReader(r.Body, bodyCopy)) 
	req.Header = r.Header
	//req.ContentLength= r.ContentLength
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if resp.StatusCode != 200 {
		http.Error(w, "部署失败", resp.StatusCode)
	}

	// 解析body获取yml信息
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	info, err := a.manager.SaveYmlConfigFile(bodyCopy, params["boundary"], path, node)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(info); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) listNodeContainer(w http.ResponseWriter, r *http.Request) {
	// list containers in specified node.
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	addr := vars["nodeaddr"]
	info, err := a.manager.ListNodeContainer(addr)
	if err != nil {
		fmt.Println(err, 2)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(info); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
}


//func (a *Api) uploadYmlConfig(w http.ResponseWriter, r *http.Request) {
//	//w.Header().Set("Content-Type", "mime/multipart")
//	w.Header().Set("Content-Type", "application/json")
//
//	fmt.Println("start parsing............")
//	err := r.ParseMultipartForm(1 * 1024 * 1024)
//	if err != nil {
//		fmt.Println(err, r.Header)
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	ymlConfig, err := a.manager.UploadYmlConfig(node, path, file)
//	if err != nil {
//		fmt.Println(err, 2)
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	if err := json.NewEncoder(w).Encode(ymlConfig); err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//
//	}
//}
//
//func (a *Api) deployFromYmlConfig(w http.ResponseWriter, r *http.Request) {
//	w.Header().Set("Content-Type", "application/json")
//
//	var y *shipyard.YmlConfig
//	if err := json.NewDecoder(r.Body).Decode(&y); err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	s, err := a.manager.DeployFromYmlConfig(y)
//
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	if err := json.NewEncoder(w).Encode(s); err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//
//	}
//}
