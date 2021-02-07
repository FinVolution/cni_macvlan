package macvlannet

import (
	. "github.com/containernetworking/plugins/plugins/main/macvlan/config"
	"github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
	"github.com/containernetworking/plugins/plugins/main/macvlan/stringutils"
	"testing"
)

func TestCreateNewJson(t *testing.T) {

	macvlanlog.InitLog(AddMacVlanLog)
	defer macvlanlog.Close()

	//s1 := `{"cniVersion":"","ipMasq":false,"ipam":{"gateway":"GateWayIP","rangeEnd":"RANGEENDIP","rangeStart":"RANGESTARTIP","routes":[{"dst":"10.1.5.0/24", "gw": "10.1.5.1"},{"dst":"10.1.4.0/24","gw": "10.1.4.1"},{"dst":"0.0.0.0/0"}],"subnet":"SUBNET","type":"host-local"},"isGateway":true,"master":"BANDNAME","mode":"bridge","name":"CNINAME","type":"macvlan"}`
	s1 := `{"cniVersion":"","ipMasq":false,"ipam":{"gateway":"GateWayIP","rangeEnd":"RANGEENDIP","rangeStart":"RANGESTARTIP","routes":[{"dst":"0.0.0.0/0"}],"subnet":"SUBNET","type":"host-local"},"isGateway":true,"master":"BANDNAME","mode":"bridge","name":"CNINAME","type":"macvlan"}`

	//NetWorkConfigFile := `  c:\opt\network.conf  `
	macvlanmap, bondmap := stringutils.GetMapFromFile(NetWorkConfigFile)
	s3 := stringutils.CreateNewJson(s1, "10.1.5.31", macvlanmap, bondmap)

	args := `IgnoreUnknown=1;K8S_POD_NAMESPACE=default-borrow;K8S_POD_NAME=stargate.1000002821.s318.g3.1;K8S_POD_INFRA_CONTAINER_ID=3923122089ff38440a77f59ccf8c5c1cc83c115901136042342800af412a8b60`
	ContainerID := "3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b"
	IfName := "eth0"

	r, _ := GetIpamIp("10.1.5.185", s3, args, ContainerID, IfName)

	t.Log(r.String())
	s5 := r.String()
	s4 := "IP4:{IP:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.1.5.1 Routes:[{Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}]}, DNS:{Nameservers:[] Domain: Search:[] Options:[]}"
	t.Log(s4)
	if s4 != s5 {
		t.Error("s4 != s5")
	}
}
