package main

import (
	"snmp-exporter/config"
	"gopkg.in/alecthomas/kingpin.v2"
	"net/http"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"strings"
	"fmt"
	"snmp-exporter/collectors"
	"github.com/gorilla/mux"
	"snmp-exporter/collectors/api"
)

var listenAddress = kingpin.Flag("web.listen-address","Address to listen on for web insterface and " +
	"telemetry.").Default(":9106").String()


func init()  {
	config.GetDBHandle()
}
func runCollector(collector prometheus.Collector,w http.ResponseWriter,r *http.Request)  {
	registry:= prometheus.NewRegistry()
	registry.MustRegister(collector)
	h:=promhttp.HandlerFor(registry,promhttp.HandlerOpts{})
	h.ServeHTTP(w,r)
}
func main() {
	kingpin.Parse()
	r := mux.NewRouter()
	r.HandleFunc("/snmp",handler)
	r.HandleFunc("/api/v1/netdev/interface/{uuid}",api.GetNetworkDeviceInterfaces)
	r.HandleFunc("/api/v1/lldp/{uuid}",api.GetLldpInfo)
	http.ListenAndServe(*listenAddress,r)
	
}
func handler(w http.ResponseWriter,r *http.Request)  {
	var collectorType prometheus.Collector
	target:= r.URL.Query().Get("target")
	if target=="" {
		http.Error(w,"'target' parameter must be specified",400)
		return
	}
	switch strings.Split(fmt.Sprintf("%s",r.URL),"?")[0] {
	case "snmp":
		collectorType = collectors.Collector{target}
		break
	default:
		break
	}
	runCollector(collectorType,w,r)
}
