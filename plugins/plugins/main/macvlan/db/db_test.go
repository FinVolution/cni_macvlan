package db

import (
	"fmt"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/config"
	"github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
	"testing"
)

func Test_db_get_put_1(t *testing.T) {

	macvlanlog.InitLog(AddMacVlanLog)
	defer macvlanlog.Close()

	dbconn := DBConnect()

	macvlanlog.DebugLog.Println("DBConfigFile: ", DBConfigFile)
	macvlanlog.DebugLog.Println("AddMacVlanLog: ", AddMacVlanLog)
	macvlanlog.DebugLog.Println("DelMacVlanLog:", DelMacVlanLog)
	macvlanlog.DebugLog.Println("NetWorkConfigFile:", NetWorkConfigFile)

	err, id, ip, active := GetIp(dbconn, "aaa")
	fmt.Println(err, id, ip, active)
	UpdatePod(dbconn, "aaa", id, ip, 0)
	err, id, ip, active = GetIp(dbconn, "bbb")
	fmt.Println(err, id, ip, active)
	//GetIp(dbconn, "bbb")
	UpdatePod(DBConnect(), "aaa", id, "192.168.6.15", 0)
	//GetIp(dbconn, "aaa")
}
