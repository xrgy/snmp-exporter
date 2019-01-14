package api

import (
	"net/http"
	"github.com/gorilla/mux"
	"snmp-exporter/config"
	"os/exec"
	"strings"
	"github.com/soniah/gosnmp"
	"time"
	"log"
	"strconv"
	"fmt"
	"snmp-exporter/collectors"
	"encoding/json"
)

type Lldpinfos struct{
	LldpInfos []Lldpinfo `json:"lldpinfos"`
}
type Lldpinfo struct {
	Uuid string `json:"uuid"`
	IP string `json:"ip"`
	LocalInfos []Localinfo `json:"localinfos"`
	RemInfos []RemInfo	`json:"reminfos"`
}
type Localinfo struct {
	LocalPortIndex string `json:"localportindex"`
	LocalChassisMac string `json:"localchassismac"`
	LocalPortName string `json:"localportname"`
}
type RemInfo struct {
	RemLocalIndex string `json:"remlocalindex"`
	RemChassisMac string `json:"remchassismac"`
	RemPortName string `json:"remportname"`
}

func GetLldpInfo(w http.ResponseWriter,r *http.Request){
	params := mux.Vars(r)
	//todo 不需要这个uuid 二级规格 因为都在网络设备表里面
	id := params["uuid"]
	var lldpinfo []Lldpinfo
	monitorInfos := config.GetlldpMonitorInfo(id)
	for k:=0; k<len(monitorInfos); k++ {
		monitor_info:=monitorInfos[k]
		ip := monitor_info.IP
		commmand := "ping -i 0.3 -w 5 " + ip + " -c 3 |tail-n 2 "
		cmd := exec.Command("/bin/sh","-c",commmand)
		ret,_ := cmd.Output()
		s := string(ret)
		if strings.Contains(s,"100% packet loss") {
			continue
		}
		snmp_version := monitor_info.Snmp_version
		community := monitor_info.Read_community
		port := monitor_info.Port
		if port == "" {
			port = "161"
		}
		if ip == ""  || snmp_version =="" ||community == "" {
			log.Printf("not enough monitor_info parameters")
			continue
		}
		PortStr,err := strconv.ParseInt(port,10,16)
		if err!=nil {
			continue
		}
		snmp := gosnmp.GoSNMP{}
		snmp.MaxRepetitions = 10
		snmp.Retries = 2
		snmp.Timeout = time.Second * 10
		snmp.Target = ip
		snmp.Port = uint16(PortStr)
		switch snmp_version {
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
		snmp.Community = community
		err = snmp.Connect()
		if err!=nil {
			log.Printf("error connnect to target: %s",ip)
			continue
		}
		//defer snmp.Conn.Close()
		_,err = snmp.Get([]string{"1.3.6.1.2.1.1"})
		if err!=nil {
			continue
		}
		var localinfo []Localinfo
		var ifDescrs,ifPhysAddress, ifIndexs,ifOperstatus []gosnmp.SnmpPDU
		if snmp.Version == gosnmp.Version1 {
			ifDescrs, err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.2")
			ifPhysAddress,err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.6")
			ifIndexs, err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.1")
			ifOperstatus,err = snmp.WalkAll("1.3.6.1.2.1.2.2.1.8")
		}else {
			ifDescrs, err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.2")
			ifPhysAddress,err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.6")
			ifIndexs, err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.1")
			ifOperstatus,err = snmp.BulkWalkAll("1.3.6.1.2.1.2.2.1.8")
		}
		for i :=0; i<len(ifDescrs);i++  {
			tempIfDescrs :=""
			tempIfIndexs :=""
			tempIfPhyAddress :=""
			tempIfOperstatus := ""
			temp2 := gosnmp.ToBigInt(ifOperstatus[i].Value)
			tempIfOperstatus = fmt.Sprintf("%s",temp2)
			if tempIfOperstatus!="1" {
				continue
			}
			tempIfDescrs = string(ifDescrs[i].Value.([]byte))
			temp1 := gosnmp.ToBigInt(ifIndexs[i].Value)
			tempIfIndexs = fmt.Sprintf("%s",temp1)
			tempIfPhyAddress = collectors.PduValueAsString(&ifPhysAddress[i],"PhysAddress48")
			tempLocalInfo := Localinfo{tempIfIndexs,tempIfPhyAddress,tempIfDescrs}
			localinfo = append(localinfo, tempLocalInfo)
		}

		var reminfo []RemInfo
		var lldpRemClassid,lldpRemPort []gosnmp.SnmpPDU
		if snmp.Version == gosnmp.Version1 {
			lldpRemClassid, err = snmp.WalkAll("1.0.8802.1.1.2.1.4.1.1.5")
			lldpRemPort,err = snmp.WalkAll("1.0.8802.1.1.2.1.4.1.1.7")
		}else {
			lldpRemClassid, err = snmp.BulkWalkAll("1.0.8802.1.1.2.1.4.1.1.5")
			lldpRemPort,err = snmp.BulkWalkAll("1.0.8802.1.1.2.1.4.1.1.7")
		}
		for i :=0; i<len(lldpRemClassid);i++  {
			remclassidoid := lldpRemClassid[i].Name[1:]
			remclassidoidspilt := strings.Split(remclassidoid,".")
			temLocalIndex := remclassidoidspilt[len(remclassidoidspilt)-2]
			tempRemDescrs :=""
			tempRemPhyAddress :=""
			tempRemDescrs = string(lldpRemPort[i].Value.([]byte))
			tempRemPhyAddress = collectors.PduValueAsString(&lldpRemClassid[i],"PhysAddress48")
			tempRemInfo := RemInfo{temLocalIndex,tempRemPhyAddress,tempRemDescrs}
			reminfo = append(reminfo, tempRemInfo)
		}
		tempLldpInfo := Lldpinfo{monitor_info.Uuid,ip,localinfo,reminfo}
		lldpinfo = append(lldpinfo, tempLldpInfo)
		snmp.Conn.Close()
	}
	w.Header().Set("Content-Type","application/json")
	json.NewEncoder(w).Encode(Lldpinfos{lldpinfo})
}
