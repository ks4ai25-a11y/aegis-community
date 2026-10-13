// SPDX-License-Identifier: Apache-2.0
package main
import("encoding/json";"net/http";"time")
func main(){mux:=http.NewServeMux();mux.HandleFunc("GET /healthz",func(w http.ResponseWriter,r *http.Request){w.Write([]byte("ok"))});for _,p:=range []string{"/catalog","/test-pattern","/api/products/"}{mux.HandleFunc(p,func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");json.NewEncoder(w).Encode(map[string]any{"fixture":"synthetic-only","message":"Demo origin response","request_id":r.Header.Get("X-Aegis-Request-ID")})})};s:=&http.Server{Addr:":8080",Handler:mux,ReadHeaderTimeout:5*time.Second,ReadTimeout:15*time.Second,WriteTimeout:15*time.Second,MaxHeaderBytes:32768};if e:=s.ListenAndServe();e!=nil{panic(e)}}
