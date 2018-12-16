package config

import (
	"os"
	"log"
	"time"
	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	"database/sql"
)

var db *sql.DB

type ConnectInfoData struct {
	Uuid 		string
	IP          string
	Params_maps map[string]string
}
type Monitor_info []byte
type ConnectInfo struct {
	uuid string
	ip     string
	m_info Monitor_info
}

func GetDBHandle() *sql.DB {
	var err error
	DBUsername := os.Getenv("DB_USERNAME")
	DBPassword := os.Getenv("DB_PASSWORD")
	DBEndpoint := os.Getenv("DB_ENDPOINT")
	DBDatabase := os.Getenv("DB_DATABASE")
	dsn := DBUsername + ":" + DBPassword + "@(" + DBEndpoint + ")/" + DBDatabase
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("get DB handle error: %v", err)
	}
	db.SetMaxOpenConns(100)
	db.SetConnMaxLifetime(28000 * time.Second)
	err = db.Ping()
	if err != nil {
		log.Printf("connecting DB error: %v ", err)
	}
	return db
}
func GetMonitorInfo(id string) ConnectInfoData {
	info := queryConnectInfo(id)
	m:=info.m_info
	m_info_map := make(map[string]string)
	if len(m)!=0 {
		err := json.Unmarshal(m,&m_info_map)
		if err!=nil {
			log.Printf("Unmarshal error")
		}
	}
	con_info_data:=ConnectInfoData{
		"",
		info.ip,
		m_info_map,
	}
	return con_info_data
}
func queryConnectInfo(id string) ConnectInfo {
	rows, err := db.Query("select ip,monitor_info from tbl_monitor_record where uuid=?", id)
	if err != nil {
		log.Printf("query error")
	}
	info := ConnectInfo{}
	for rows.Next() {
		err = rows.Scan(&info.ip, &info.m_info)
	}
	defer rows.Close()
	return info
}
func CloseDBHandle()  {
	db.Close()
}
func GetlldpMonitorInfo(id string) []ConnectInfoData {
	rows, err := db.Query("select uuid,ip,monitor_info from tbl_monitor_record where deleted=0 and middle_resource_type_id=?", id)
	if err != nil {
		log.Printf("query error")
	}
	infos := []ConnectInfo{}
	for rows.Next() {
		info := ConnectInfo{}
		err = rows.Scan(&info.uuid, &info.ip, &info.m_info)
		infos = append(infos, info)
	}
	defer rows.Close()
	conninfos := []ConnectInfoData{}
	for i:=0; i< len(infos);i++  {
		info := infos[i]
		m:=info.m_info
		m_info_map := make(map[string]string)
		if len(m)!=0 {
			err := json.Unmarshal(m,&m_info_map)
			if err!=nil {
				log.Printf("Unmarshal error")
			}
		}
		con_info_data:=ConnectInfoData{
			info.uuid,
			info.ip,
			m_info_map,
		}
		conninfos = append(conninfos, con_info_data)
	}
	return conninfos
}