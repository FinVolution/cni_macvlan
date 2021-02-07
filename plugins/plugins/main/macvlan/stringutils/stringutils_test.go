package stringutils

import (
	"fmt"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/config"
	"testing"
)

//  "IgnoreUnknown=1;K8S_POD_NAMESPACE=default-borrow;K8S_POD_NAME=stargate.1000001236.s2449.g2.1;K8S_POD_INFRA_CONTAINER_ID=47e920f60b848d083a59221a235f1405eee0975b1f899450770e3db647083b12"
func Test_db_get_put_1(t *testing.T) {
	src := "    IgnoreUnknown=1;K8S_POD_NAMESPACE=default-borrow;K8S_POD_NAME=stargate.1000001236.s2449.g2.1;K8S_POD_INFRA_CONTAINER_ID=47e920f60b848d083a59221a235f1405eee0975b1f899450770e3db647083b12"

	r := StringToMap(src, ";", "=")

	if len(r) != 4 {
		t.Error("分类总数不正确")
	}
	if r["IgnoreUnknown"] != "1" {
		t.Error("IgnoreUnknown")
	}
	if r["K8S_POD_NAMESPACE"] != "default-borrow" {
		t.Error("K8S_POD_NAMESPACE")
	}
	if r["K8S_POD_NAME"] != "stargate.1000001236.s2449.g2.1" {
		t.Error("K8S_POD_NAME")
	}
	if r["K8S_POD_INFRA_CONTAINER_ID"] != "47e920f60b848d083a59221a235f1405eee0975b1f899450770e3db647083b12" {
		t.Error("K8S_POD_INFRA_CONTAINER_ID")
	}
	t.Log("success")
	fmt.Println(r["K8S_POD_INFRA_CONTAINER_ID"])

}

func Test_db_get_put_2(t *testing.T) {

	r1, r2 := GetMapFromFile(NetWorkConfigFile)

	if len(r1) != 4 {
		t.Error("分类总数不正确")
	}

	if r1["10.1.4.0"] != "cni_macvlan1004" {
		t.Error("10.1.4.0")
	}

	if r1["10.1.5.0"] != "cni_macvlan1005" {
		t.Error("10.1.5.0")
	}
	if r1["10.1.6.0"] != "cni_macvlan1006" {
		t.Error("10.1.6.0")
	}

	if r1["10.1.7.0"] != "cni_macvlan1007" {
		t.Error("10.1.7.0")
	}

	if len(r2) != 4 {
		t.Error("分类总数不正确")
	}

	if r2["10.1.4.0"] != "bond0.1004" {
		t.Error("10.1.4.0")
	}

	if r2["10.1.5.0"] != "bond0.1005" {
		t.Error("10.1.5.0")
	}
	if r2["10.1.6.0"] != "bond0.1006" {
		t.Error("10.1.6.0")
	}

	if r2["10.1.7.0"] != "bond0.1007" {
		t.Error("10.1.7.0")
	}
}

func Test_db_get_put_3(t *testing.T) {
	x := GetMasterFromIp("192.168.3.1")
	if x != "192.168.3.0" {
		t.Error("10.1.7.0")
	}
	x = GetMasterFromIp("10.13.3.1")
	if x != "10.13.3.0" {
		t.Error("10.13.3.0")
	}

}

func TestGetPodName(t *testing.T) {
	s := "IgnoreUnknown=1;K8S_POD_NAMESPACE=default-framework;K8S_POD_NAME=stargate.9900000000.s79.g6.1;K8S_POD_INFRA_CONTAINER_ID=25b9c89ef9c7e460af404fcae21bf152eac76c0f31c0e2299cefb52dff157f3c"
	l := GetPodName(s)
	if l != "stargate.9900000000.s79.g6.1" {
		t.Error("stargate.9900000000.s79.g6.1")
	}
}
func TestCreateNewJson(t *testing.T) {
	//s1 := `{"cniVersion":"","ipMasq":false,"ipam":{"gateway":"GateWayIP","rangeEnd":"RANGEENDIP","rangeStart":"RANGESTARTIP","routes":[{"dst":"0.0.0.0/0"}],"subnet":"SUBNET","type":"host-local"},"isGateway":true,"master":"BANDNAME","mode":"bridge","name":"CNINAME","type":"macvlan"}`
	s2 := `{"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.1.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}`
	//NetWorkConfigFile //:= `  c:\opt\network.conf  `
	macvlanmap, bondmap := GetMapFromFile(NetWorkConfigFile)
	s3 := CreateNewJson(ConstMacVlanString, "10.1.5.31", macvlanmap, bondmap)
	if s3 != s2 {
		t.Error(s2)
		t.Error(s3)

	} else {
		t.Log("ok")
	}

}

/*

[Debug]2019/05/22 16:11:00 ipam.ExecAdd Result:
IP4:{IP:{IP:10.1.5.185 Mask:ffffff00}
Gateway:10.1.5.1
Routes:[{Dst:{IP:0.0.0.0 Mask:00000000}
GW:<nil>}]},
DNS:{Nameservers:[] Domain: Search:[] Options:[]}  version:

*/
