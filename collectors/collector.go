package collectors

import (
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"snmp-exporter/config"
	"log"
	"errors"
	"github.com/soniah/gosnmp"
	"fmt"
	"strconv"
	"time"
	"strings"
	"os/exec"
)

var (
	snmp_v1_path = "snmp_v1.yml"
	snmp_v2_path = "snmp_v2.yml"
	configpath   = flag.String("config.path", "./config/public/", "path to config files")
)

type Collector struct {
	Target string
}

// Describe implements Prometheus.Collector.
func (c Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dummy", "dummy", nil, nil)
}

type SnmpScraper struct {
	TargetType string
	Module     *config.Module
	Nmodules   *config.NModule
	Snmp       gosnmp.GoSNMP
}
type MetricNode struct {
	metric   *config.Metric
	children map[int]*MetricNode
}

func (c Collector) Collect(ch chan<- prometheus.Metric) {
	scrape, err := c.newSNMPScraper(ch)
	if err != nil {
		log.Printf("%s", err.Error())
		return
	}
	var avgPingTime = float64(0)
	targetIP := (*scrape).Snmp.Target
	command := "ping " + targetIP + " -c 3 |sed -n '7,$p'"
	cmd := exec.Command("/bin/sh","-c",command)
	ret,_ :=cmd.Output()
	s := string(ret)
	if s!="" {
		ping_result := strings.Split(s,"\n")
		if strings.ContainsAny(ping_result[1],"/") {
			line2 := strings.Split(ping_result[1],"/")
			pingTime,err := strconv.ParseFloat(line2[3],64)
			if err!=nil {
				log.Printf("error parse ping time")
			}else {
				avgPingTime = pingTime
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("snmp_ping_avgtime","snmp ping times",[]string{"targetIP"},nil),
		prometheus.GaugeValue,float64(avgPingTime),targetIP)
	start := time.Now()
	err = (*scrape).Snmp.Connect()
	if err !=nil {
		log.Printf("error connecting to target %s: %s",targetIP,err.Error())
		return
	}
	defer (&scrape).Snmp.Conn.Close()
	_,err=(*scrape).Snmp.Get([]string{"1.3.6.1.2.1.1.2"})
	if err!=nil {
		log.Printf("error connecting to target %s: %s",targetIP,err.Error())
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("snmp_monitorstatus","snmp monitor status",nil,nil),
			prometheus.GaugeValue,0)
		return
	}
	ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("snmp_monitorstatus","snmp monitor status",nil,nil),
		prometheus.GaugeValue,1)
PrivateLoop:
	for _, m := range (*scrape).Nmodules.NMetric {
		log.Printf("scrape type:%s", m.Type)
		for _, v := range m.AllMetrics {
			oid := v.Oid
			var npdus []gosnmp.SnmpPDU
			var idxs []string
			if v.Policy != "" {
				switch v.Policy {
				case "nonezero":
					npdus, idxs = DoNoneZero(SnmpWalk((*scrape).Snmp, oid))
				default:
					npdus, idxs = DoDefault(SnmpWalk((*scrape).Snmp, oid))
				}
			}
			if v.Indexes != nil {
				prometheusCount := 0
				labellist, labellen := MakeLabels((*scrape).Snmp, *v, idxs)
				for a := 0; a < labellen; a++ {
					var s string
					labelName := []string{}
					labelValue := []string{}
					for _, label := range labellist {
						labelName = append(labelName, label.Labelname)
						if len(label.Labelvalues) == 1 {
							labelValue = append(labelValue, label.Labelvalues[0])
							s = s + label.Labelname + "=" + label.Labelvalues[0] + ","
						} else {
							labelValue = append(labelValue, label.Labelvalues[0])
							s = s + label.Labelname + "=" + label.Labelvalues[a] + ","
						}
					}
					if npdus[a].Value != nil {
						ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(v.Name, "", labelName, nil),
							prometheus.GaugeValue, float64(gosnmp.ToBigInt(npdus[a].Value).Int64()), labelValue...)
						prometheusCount += 1
					}
				}
				if prometheusCount != 0 {
					continue PrivateLoop
				}
			} else {
				for _, pdu := range npdus {
					if pdu.Value != nil {
						ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(v.Name, "", nil, nil),
							prometheus.GaugeValue, float64(gosnmp.ToBigInt(pdu.Value).Int64()))
						continue PrivateLoop
					}
				}
			}
		}
	}

	snmp := (*scrape).Snmp
	module := (*scrape).Module
	start = time.Now()
	pdus, err := ScrapeTarget(snmp, module)
	if err != nil {
		log.Printf("Error scraping target %s: %s", snmp.Target, err)
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error scraping target", nil, nil), err)
		return
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_walk_duration_seconds", "Time SNMP walk/bulkwalk took.", nil, nil),
		prometheus.GaugeValue,
		float64(time.Since(start).Seconds()))
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_pdus_returned", "PDUs returned from walk.", nil, nil),
		prometheus.GaugeValue,
		float64(len(pdus)))
	oidToPdu := make(map[string]gosnmp.SnmpPDU, len(pdus))
	for _, pdu := range pdus {
		oidToPdu[pdu.Name[1:]] = pdu
	}

	metricTree := buildMetricTree(module.Metrics)
	// Look for metrics that match each pdu.
PduLoop:
	for oid, pdu := range oidToPdu {
		head := metricTree
		oidList := oidToList(oid)
		for i, o := range oidList {
			var ok bool
			head, ok = head.children[o]
			if !ok {
				continue PduLoop
			}
			if head.metric != nil {
				// Found a match.
				samples := pduToSamples(oidList[i+1:], &pdu, head.metric, oidToPdu)
				for _, sample := range samples {
					ch <- sample
				}
				break
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_duration_seconds", "Total SNMP time scrape took (walk and processing).", nil, nil),
		prometheus.GaugeValue,
		float64(time.Since(start).Seconds()))
}
func SnmpWalk(snmp gosnmp.GoSNMP, oid string) []gosnmp.SnmpPDU {
	if snmp.Version == gosnmp.Version1 {
		pdus,err := snmp.WalkAll(oid)
		if err!=nil {
			log.Printf("walk err:%s",err.Error())
		}
		return pdus
	}else {
		pdus,err := snmp.BulkWalkAll(oid)
		if err!=nil {
			log.Printf("walk oid %s err:%s",oid,err.Error())
		}
		return pdus
	}
}
func DoDefault(pdus []gosnmp.SnmpPDU) ([]gosnmp.SnmpPDU, []string) {
	var indexs []string
	var index string
	for _, v := range pdus {
		ss := strings.Split(v.Name, ".")
		index = ss[len(ss)-1]
		indexs = append(indexs, index)
	}
	return pdus, indexs
}
func DoNoneZero(pdus []gosnmp.SnmpPDU) ([]gosnmp.SnmpPDU, []string) {
	var snmpPDUS []gosnmp.SnmpPDU
	var indexs []string
	var index string
	for _, v := range pdus {
		if v.Value == nil {
			continue
		}
		if float64(gosnmp.ToBigInt(v.Value).Int64()) > 0 {
			snmpPDUS = append(snmpPDUS, v)
			ss := strings.Split(v.Name, ".")
			index = ss[len(ss)-1]
			indexs = append(indexs, index)
		}
	}
	return snmpPDUS, indexs
}
func MakeLabels(snmp gosnmp.GoSNMP, metric config.NMetric, indexs []string) ([]config.Label, int) {
	var labels []config.Label
	var count int
	for _, v := range metric.Indexes {
		la, c := getLabels(snmp, v, indexs)
		labels = append(labels, la)
		count = c
	}
	return labels, count
}
func getLabels(snmp gosnmp.GoSNMP, index *config.NMetric, indexs []string) (config.Label, int) {
	var metricLabel config.Label
	var newIndexs []string
	metricLabel.Labelname = index.Name
	if index.Value != "" {
		for _, i := range indexs {
			newIndexs = append(newIndexs, index.Value+i)
		}
		metricLabel.Labelvalues = newIndexs
		return metricLabel, len(indexs)
	} else {
		oid := index.Oid
		for _, v := range indexs {
			newoid := oid + "." + v
			var oids = []string{newoid}
			result, err1 := snmp.Get(oids)
			if err1 != nil {
				log.Printf("get error:%s", err1.Error())
				newIndexs = append(newIndexs, "--")
				metricLabel.Labelvalues = newIndexs
			} else {
				pdu := (*result).Variables[0]
				ni := PduValueAsString(&pdu, "DisplayString")
				newIndexs = append(newIndexs, ni)
				metricLabel.Labelvalues = newIndexs
			}
		}
		if index.Indexes != nil {
			return getLabels(snmp, index.Indexes[0], newIndexs)
		}
		return metricLabel, len(newIndexs)
	}
}
func (c Collector) newSNMPScraper(ch chan<- prometheus.Metric) (*SnmpScraper, error) {
	monitor_info := config.GetMonitorInfo(c.Target)
	ip := monitor_info.IP
	//moduleName := monitor_info.Params_maps["module"]
	snmp_version := monitor_info.Snmp_version
	community := monitor_info.Read_community
	port := monitor_info.Port
	if port == "" {
		port = "161"
	}
	if ip == ""  || snmp_version == "" || community == "" {
		log.Printf("not enough monitor_info parameters")
		return nil, errors.New("not enough monitor_info parameters")
	}
	snmp_auth := config.Auth{
		Community: community,
	}
	configfile := ""
	switch snmp_version {
	case "1":
		configfile = snmp_v1_path
		break
	case "2":
		configfile = snmp_v2_path
		break
	case "3":
		break
	default:
		return nil, errors.New("invaild snmp version: " + snmp_version)
	}
	cfg, err := config.LoadFile(*configpath + configfile)
	if err != nil {
		msg := fmt.Sprintf("Error Parsing config file:%s", err)
		log.Printf(msg)
		return nil, err
	}
	module := &config.Module{}
	module, ok := (*cfg)["network_device"]
	if !ok {
		return nil, errors.New("error get snmp,yml")
	}
	PortStr, err := strconv.ParseInt(port, 10, 16)
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
	snmp.Community = snmp_auth.Community
	scraper := SnmpScraper{
		//TargetType: moduleName,
		Module:     module,
		Snmp:       snmp,
	}
	return &scraper, nil
}

func ScrapeTarget(snmp gosnmp.GoSNMP, config *config.Module) ([]gosnmp.SnmpPDU, error) {

	// Do the actual walk.
	err := snmp.Connect()
	if err != nil {
		return nil, fmt.Errorf("Error connecting to target %s: %s", snmp.Target, err)
	}
	defer snmp.Conn.Close()

	result := []gosnmp.SnmpPDU{}

	for _, subtree := range config.Walk {
		var pdus []gosnmp.SnmpPDU
		log.Printf("Walking target %q subtree %q", snmp.Target, subtree)
		walkStart := time.Now()
		if snmp.Version == gosnmp.Version1 {
			pdus, err = snmp.WalkAll(subtree)
		} else {
			pdus, err = snmp.BulkWalkAll(subtree)
		}
		if err != nil {
			return nil, fmt.Errorf("Error walking target %s: %s", snmp.Target, err)
		} else {
			log.Printf("Walk of target %q subtree %q completed in %s", snmp.Target, subtree, time.Since(walkStart))
		}
		result = append(result, pdus...)
	}
	return result, nil
}

// Build a tree of metrics from the config, for fast lookup when there's lots of them.
func buildMetricTree(metrics []*config.Metric) *MetricNode {
	metricTree := &MetricNode{children: map[int]*MetricNode{}}
	for _, metric := range metrics {
		head := metricTree
		for _, o := range oidToList(metric.Oid) {
			_, ok := head.children[o]
			if !ok {
				head.children[o] = &MetricNode{children: map[int]*MetricNode{}}
			}
			head = head.children[o]
		}
		head.metric = metric
	}
	return metricTree
}

func oidToList(oid string) []int {
	result := []int{}
	for _, x := range strings.Split(oid, ".") {
		o, _ := strconv.Atoi(x)
		result = append(result, o)
	}
	return result
}

func indexesToLabels(indexOids []int, metric *config.Metric, oidToPdu map[string]gosnmp.SnmpPDU) map[string]string {
	labels := map[string]string{}
	labelOids := map[string][]int{}

	// Covert indexes to useful strings.
	for _, index := range metric.Indexes {
		str, subOid, remainingOids := indexOidsAsString(indexOids, index.Type, index.FixedSize)
		// The labelvalue is the text form of the index oids.
		labels[index.Labelname] = str
		// Save its oid in case we need it for lookups.
		labelOids[index.Labelname] = subOid
		// For the next iteration.
		indexOids = remainingOids
	}

	// Perform lookups.
	for _, lookup := range metric.Lookups {
		oid := lookup.Oid
		for _, label := range lookup.Labels {
			for _, o := range labelOids[label] {
				oid = fmt.Sprintf("%s.%d", oid, o)
			}
		}
		if pdu, ok := oidToPdu[oid]; ok {
			labels[lookup.Labelname] = PduValueAsString(&pdu, lookup.Type)
		} else {
			labels[lookup.Labelname] = ""
		}
	}

	return labels
}

func pduToSamples(indexOids []int, pdu *gosnmp.SnmpPDU, metric *config.Metric, oidToPdu map[string]gosnmp.SnmpPDU) []prometheus.Metric {
	// The part of the OID that is the indexes.
	labels := indexesToLabels(indexOids, metric, oidToPdu)

	value := getPduValue(pdu)
	t := prometheus.UntypedValue

	labelnames := make([]string, 0, len(labels)+1)
	labelvalues := make([]string, 0, len(labels)+1)
	for k, v := range labels {
		labelnames = append(labelnames, k)
		labelvalues = append(labelvalues, v)
	}

	switch metric.Type {
	case "counter":
		t = prometheus.CounterValue
	case "gauge":
		t = prometheus.GaugeValue
	case "Float", "Double":
		t = prometheus.GaugeValue
	default:
		// It's some form of string.
		t = prometheus.GaugeValue
		value = 1.0
		// For strings we put the value as a label with the same name as the metric.
		// If the name is already an index, we do not need to set it again.
		if _, ok := labels[metric.Name]; !ok {
			labelnames = append(labelnames, metric.Name)
			labelvalues = append(labelvalues, PduValueAsString(pdu, metric.Type))
		}
	}

	return []prometheus.Metric{prometheus.MustNewConstMetric(prometheus.NewDesc(metric.Name, metric.Help, labelnames, nil),
		t, value, labelvalues...)}
}

// Convert oids to a string index value.
//
// Returns the string, the oids that were used and the oids left over.
func indexOidsAsString(indexOids []int, typ string, fixedSize int) (string, []int, []int) {
	switch typ {
	case "Integer32", "Integer", "gauge", "counter":
		// Extract the oid for this index, and keep the remainder for the next index.
		subOid, indexOids := splitOid(indexOids, 1)
		return fmt.Sprintf("%d", subOid[0]), subOid, indexOids
	case "PhysAddress48":
		subOid, indexOids := splitOid(indexOids, 6)
		parts := make([]string, 6)
		for i, o := range subOid {
			parts[i] = fmt.Sprintf("%02X", o)
		}
		return strings.Join(parts, ":"), subOid, indexOids
	case "OctetString":
		var subOid []int
		// The length of fixed size indexes come from the MIB.
		// For varying size, we read it from the first oid.
		length := fixedSize
		if length == 0 {
			subOid, indexOids = splitOid(indexOids, 1)
			length = subOid[0]
		}
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		if len(parts) == 0 {
			return "", subOid, indexOids
		} else {
			return fmt.Sprintf("0x%X", string(parts)), subOid, indexOids
		}
	case "DisplayString":
		var subOid []int
		length := fixedSize
		if length == 0 {
			subOid, indexOids = splitOid(indexOids, 1)
			length = subOid[0]
		}
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		// ASCII, so can convert staight to utf-8.
		return string(parts), subOid, indexOids
	case "IpAddr":
		subOid, indexOids := splitOid(indexOids, 4)
		parts := make([]string, 4)
		for i, o := range subOid {
			parts[i] = strconv.Itoa(o)
		}
		return strings.Join(parts, "."), subOid, indexOids
	case "InetAddressType":
		subOid, indexOids := splitOid(indexOids, 1)
		switch subOid[0] {
		case 0:
			return "unknown", subOid, indexOids
		case 1:
			return "ipv4", subOid, indexOids
		case 2:
			return "ipv6", subOid, indexOids
		case 3:
			return "ipv4z", subOid, indexOids
		case 4:
			return "ipv6z", subOid, indexOids
		case 16:
			return "dns", subOid, indexOids
		default:
			return strconv.Itoa(subOid[0]), subOid, indexOids
		}
	default:
		log.Fatalf("Unknown index type %s", typ)
		return "", nil, nil
	}
}

// Right pad oid with zeros, and split at the given point.
// Some routers exclude trailing 0s in responses.
func splitOid(oid []int, count int) ([]int, []int) {
	head := make([]int, count)
	tail := []int{}
	for i, v := range oid {
		if i < count {
			head[i] = v
		} else {
			tail = append(tail, v)
		}
	}
	return head, tail
}

// This mirrors decodeValue in gosnmp's helper.go.
func PduValueAsString(pdu *gosnmp.SnmpPDU, typ string) string {
	switch pdu.Value.(type) {
	case int:
		return strconv.Itoa(pdu.Value.(int))
	case uint:
		return strconv.FormatUint(uint64(pdu.Value.(uint)), 10)
	case uint64:
		return strconv.FormatUint(pdu.Value.(uint64), 10)
	case float32:
		return strconv.FormatFloat(float64(pdu.Value.(float32)), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(pdu.Value.(float64), 'f', -1, 64)
	case string:
		if pdu.Type == gosnmp.ObjectIdentifier {
			// Trim leading period.
			return pdu.Value.(string)[1:]
		}
		// DisplayString
		return pdu.Value.(string)
	case []byte:
		if typ == "" {
			typ = "OctetString"
		}
		// Reuse the OID index parsing code.
		parts := make([]int, len(pdu.Value.([]byte)))
		for i, o := range pdu.Value.([]byte) {
			parts[i] = int(o)
		}
		if typ == "OctetString" || typ == "DisplayString" {
			// Prepend the length, as it is explicit in an index.
			parts = append([]int{len(pdu.Value.([]byte))}, parts...)
		}
		str, _, _ := indexOidsAsString(parts, typ, 0)
		return str
	case nil:
		return ""
	default:
		// This shouldn't happen.
		log.Printf("Got PDU with unexpected type: Name: %s Value: '%s', Go Type: %T SNMP Type: %s", pdu.Name, pdu.Value, pdu.Value, pdu.Type)
		return fmt.Sprintf("%s", pdu.Value)
	}
}

func getPduValue(pdu *gosnmp.SnmpPDU) float64 {
	switch pdu.Type {
	case gosnmp.Counter64:
		return float64(gosnmp.ToBigInt(pdu.Value).Uint64())
	case gosnmp.OpaqueFloat:
		return float64(pdu.Value.(float32))
	case gosnmp.OpaqueDouble:
		return pdu.Value.(float64)
	default:
		return float64(gosnmp.ToBigInt(pdu.Value).Int64())
	}
}
