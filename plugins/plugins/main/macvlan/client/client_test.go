package client

import (
	"fmt"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/config"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
	"testing"
)



func TestClient2(t *testing.T) {
	InitLog(AddMacVlanLog)
	ip, err := GetIpOfPodFromStargate(GetGateConnStr(), "aaa")
	if err != nil {
		panic(err)
	}

	ip, err = GetIpOfPodFromStargate(GetGateConnStr(), "bbb")
	if err == nil {
		t.Error("Wrong response")
	}

	fmt.Println("ip = ", ip)
}
func TestClient3(t *testing.T) {
	InitLog(AddMacVlanLog)
	ip, err := GetIpOfPodFromStargate("http://127.0.0.1:8080/api/v1/pods", "stargate.1000000880.s2419.g1.1")
	if err != nil {
		panic(err)
	}
	fmt.Println(ip)
}
func TestClient4(t *testing.T) {
	InitLog(AddMacVlanLog)
	ip, err := ParseK8SJson(Demojson)
	if err != nil {
		panic(err)
	}
	if ip != "192.168.0.1" {
		panic(ip)
	}
}
