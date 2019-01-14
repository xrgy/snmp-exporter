package api

import (
	"net/http"
	"github.com/soniah/gosnmp"
	"time"
	"snmp-exporter/config"
	"strconv"
	"log"
	"fmt"
	"encoding/json"
)

type InterfaceInfo struct {
	Interfaces []Interface 	`json:"interfaces"`
}
type Interface struct {
	IfIndex string `json:"ifindex"`
	IfDescr string `json:"ifdescr"`
	IfType string `json:"iftype"`
	IfAdminStatus string `json:"ifadminstatus"`
	IfOperStatus string `json:"ifoperstatus"`
} 

func GetNetworkDeviceInterfaces(w http.ResponseWriter,r *http.Request)  {
	monitor_info := config.GetMonitorInfo("uuid")
	snmp := gosnmp.GoSNMP{}
	snmp.MaxRepetitions = 10
	snmp.Retries = 2
	snmp.Timeout = time.Second * 10
	snmp.Target =  monitor_info.IP
	tempPort,err:= strconv.ParseInt(monitor_info.Port,10,16)
	if err!=nil {
		log.Printf("error type port:%s,%s",tempPort,err.Error())
		return
	}
	snmp.Port = uint16(tempPort) //应该是将tempPort转化
	switch monitor_info.Snmp_version {
	case "1":
		snmp.Version = gosnmp.Version1
		break
	case "2":
		snmp.Version = gosnmp.Version2c
		break
	case "3":
		snmp.Version = gosnmp.Version3
		break
	}
	snmp.Community = monitor_info.Read_community
	err = snmp.Connect()
	if err!=nil {
		log.Printf("connect to the target %s error,%s",snmp.Target,err.Error())
		return
	}
	defer snmp.Conn.Close()
	var ifDescrs, ifIndexs, ifType, ifAdminstatus, ifOperstatus []gosnmp.SnmpPDU
	if snmp.Version == gosnmp.Version1 {
		ifDescrs, err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.2")
		ifIndexs, err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.1")
		ifType, err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.3")
		ifAdminstatus,err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.7")
		ifOperstatus,err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.8")
	}else {
		ifDescrs, err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.2")
		ifIndexs, err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.1")
		ifType, err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.3")
		ifAdminstatus,err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.7")
		ifOperstatus,err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.8")
	}
	var interfaces []Interface
	for i :=0; i<len(ifDescrs);i++  {
		tempIfDescrs :=""
		tempIfIndexs :=""
		tempIfType :=""
		tempIfAdminstatus :=""
		tempIfOperstatus := ""
		tempIfDescrs = string(ifDescrs[i].Value.([]byte))
		temp1 := gosnmp.ToBigInt(ifIndexs[i].Value)
		tempIfIndexs = fmt.Sprintf("%s",temp1)
		temp2 := gosnmp.ToBigInt(ifType[i].Value)
		tempIfType = fmt.Sprintf("%s",temp2)
		temp3 := gosnmp.ToBigInt(ifAdminstatus[i].Value)
		tempIfAdminstatus = fmt.Sprintf("%s",temp3)
		temp4 := gosnmp.ToBigInt(ifOperstatus[i].Value)
		tempIfOperstatus = fmt.Sprintf("%s",temp4)
		tempInterface := Interface{tempIfIndexs,tempIfDescrs,tempIfType,tempIfAdminstatus,tempIfOperstatus}
		interfaces = append(interfaces,tempInterface)
	}
	w.Header().Set("Content-Type","application/json")
	json.NewEncoder(w).Encode(InterfaceInfo{interfaces})

}
