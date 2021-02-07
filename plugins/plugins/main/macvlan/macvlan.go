// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"github.com/containernetworking/plugins/plugins/main/macvlan/client"

	//"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	//"github.com/containernetworking/plugins/plugins/main/macvlan/db"
	"github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
	"github.com/containernetworking/plugins/plugins/main/macvlan/macvlannet"
	"github.com/containernetworking/plugins/plugins/main/macvlan/stringutils"
	"net"
	"runtime"

	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/config"
)

const (
	IPv4InterfaceArpProxySysctlTemplate = "net.ipv4.conf.%s.proxy_arp"
)

var IpFromDB string

var PodName string

type NetConf struct {
	types.NetConf
	Master string `json:"master"`
	Mode   string `json:"mode"`
	MTU    int    `json:"mtu"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func getDefaultRouteInterfaceName() (string, error) {
	routeToDstIP, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return "", err
	}

	for _, v := range routeToDstIP {
		if v.Dst == nil {
			l, err := netlink.LinkByIndex(v.LinkIndex)
			if err != nil {
				return "", err
			}
			return l.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("no default route interface found")
}

func loadConf(bytes []byte) (*NetConf, string, error) {

	n := &NetConf{}
	macvlanlog.DebugLog.Println("load Conf: ", string(bytes))
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}

	/*
		types.NetConf
		Master string `json:"master"`
		Mode   string `json:"mode"`
		MTU    int    `json:"mtu"`
	*/
	macvlanlog.DebugLog.Println("loaded Conf: n.master", n.Master, " mode: ", n.Mode, " mtu: ", n.MTU, " n.version", n.CNIVersion)
	if n.Master == "" {
		macvlanlog.DebugLog.Println("n.Master == \"\"")
		defaultRouteInterface, err := getDefaultRouteInterfaceName()
		if err != nil {
			return nil, "", err
		}
		macvlanlog.DebugLog.Println("default interface == ", defaultRouteInterface)
		n.Master = defaultRouteInterface
	}
	return n, n.CNIVersion, nil
}

func modeFromString(s string) (netlink.MacvlanMode, error) {
	switch s {
	case "", "bridge":
		macvlanlog.DebugLog.Println("应该是bridge 模式")
		return netlink.MACVLAN_MODE_BRIDGE, nil
	case "private":
		return netlink.MACVLAN_MODE_PRIVATE, nil
	case "vepa":
		return netlink.MACVLAN_MODE_VEPA, nil
	case "passthru":
		return netlink.MACVLAN_MODE_PASSTHRU, nil
	default:
		return 0, fmt.Errorf("unknown macvlan mode: %q", s)
	}
}

func modeToString(mode netlink.MacvlanMode) (string, error) {
	switch mode {
	case netlink.MACVLAN_MODE_BRIDGE:
		return "bridge", nil
	case netlink.MACVLAN_MODE_PRIVATE:
		return "private", nil
	case netlink.MACVLAN_MODE_VEPA:
		return "vepa", nil
	case netlink.MACVLAN_MODE_PASSTHRU:
		return "passthru", nil
	default:
		return "", fmt.Errorf("unknown macvlan mode: %q", mode)
	}
}

func createMacvlan(conf *NetConf, ifName string, netns ns.NetNS) (*current.Interface, error) {
	macvlanlog.DebugLog.Println("createMacvlan")
	macvlan := &current.Interface{}

	macvlanlog.DebugLog.Println("modeFromString:", conf.Mode)
	mode, err := modeFromString(conf.Mode)
	if err != nil {
		return nil, err
	}
	macvlanlog.DebugLog.Println("modeFromString: mode:", mode)
	macvlanlog.DebugLog.Println("LinkByName :", conf.Master)
	m, err := netlink.LinkByName(conf.Master)
	if err != nil {
		macvlanlog.DebugLog.Println("failed to lookup master :", conf.Master, " ", err)
		return nil, fmt.Errorf("failed to lookup master %q: %v", conf.Master, err)
	}

	// due to kernel bug we have to create with tmpName or it might
	// collide with the name on the host and error out
	tmpName, err := ip.RandomVethName()
	if err != nil {
		return nil, err
	}
	macvlanlog.DebugLog.Println("RandomVethName :", tmpName)

	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         conf.MTU,
			Name:        tmpName,
			ParentIndex: m.Attrs().Index,
			Namespace:   netlink.NsFd(int(netns.Fd())),
		},
		Mode: mode,
	}
	macvlanlog.DebugLog.Println("Macvlan : mtu:", conf.MTU, " name: ", tmpName, " ParentIndex:", m.Attrs().Index,
		" namespace: ", int(netns.Fd()), "Mode: ", mode)
	macvlanlog.DebugLog.Println("netlink.LinkAdd(mv)")
	if err := netlink.LinkAdd(mv); err != nil {
		return nil, fmt.Errorf("failed to create macvlan: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		macvlanlog.DebugLog.Println("netns.Do")

		// TODO: duplicate following lines for ipv6 support, when it will be added in other places
		ipv4SysctlValueName := fmt.Sprintf(IPv4InterfaceArpProxySysctlTemplate, tmpName)
		macvlanlog.DebugLog.Println("netns.Do ipv4SysctlValueName: ", ipv4SysctlValueName)
		if _, err := sysctl.Sysctl(ipv4SysctlValueName, "1"); err != nil {
			// remove the newly added link and ignore errors, because we already are in a failed state
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to set proxy_arp on newly added interface %q: %v", tmpName, err)
		}
		macvlanlog.DebugLog.Println("ip.RenameLink: ", tmpName, ifName)
		err := ip.RenameLink(tmpName, ifName)
		if err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to rename macvlan to %q: %v", ifName, err)
		}
		macvlan.Name = ifName
		macvlanlog.DebugLog.Println("macvlan.Name: ", ifName)
		// Re-fetch macvlan to get all properties/attributes

		contMacvlan, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch macvlan %q: %v", ifName, err)
		}
		macvlanlog.DebugLog.Println("netlink.LinkByName: ", ifName, " contMacvlan:", contMacvlan)
		macvlan.Mac = contMacvlan.Attrs().HardwareAddr.String()
		macvlan.Sandbox = netns.Path()
		macvlanlog.DebugLog.Println("netlink.LinkByName: ", ifName, " macvlan.Mac:", macvlan.Mac, " macvlan.Sandbox: ", macvlan.Sandbox)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return macvlan, nil
}

func cmdAdd(args *skel.CmdArgs) error {

	/*
		fileName := AddMacVlanLog
		logFile,err  := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logFile,err  = os.Create(fileName)
		}
		defer logFile.Close()
	*/
	macvlanlog.InitLog(AddMacVlanLog)
	defer macvlanlog.Close()

	/*

		[Debug]2019/05/22 16:11:00 read input from ContainerID: 3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b
		[Debug]2019/05/22 16:11:00 read input from Netns: /proc/14713/ns/net
		[Debug]2019/05/22 16:11:00 read input from IfName: eth0
		[Debug]2019/05/22 16:11:00 read input from Args: IgnoreUnknown=1;K8S_POD_NAMESPACE=default-ops;K8S_POD_NAME=stargate.1000002918.s2469.g1.1;K8S_POD_INFRA_CONTAINER_ID=3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b
		[Debug]2019/05/22 16:11:00 read input from Path: /opt/cni/bin
		[Debug]2019/05/22 16:11:00 read input from StdinData: {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.113.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}
		[Debug]2019/05/22 16:11:00 load Conf:  {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.1.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}
		[Debug]2019/05/22 16:11:00 loaded Conf: n.master bond0.1005  mode:  bridge  mtu:  0  n.version
		[Debug]2019/05/22 16:11:00 isLayer3  true
		[Debug]2019/05/22 16:11:00 ns.GetNS  /proc/14713/ns/net
		[Debug]2019/05/22 16:11:00 开始创建macvlan 网络 dev: eth0  loadConf:  &{{ cni_macvlan1005 macvlan map[] {host-local} {[]  [] []} map[] <nil>} bond0.1005 bridge 0}  netns: &{0xc00000e128 false}
		[Debug]2019/05/22 16:11:00 createMacvlan
		[Debug]2019/05/22 16:11:00 modeFromString: bridge
		[Debug]2019/05/22 16:11:00 应该是bridge 模式
		[Debug]2019/05/22 16:11:00 modeFromString: mode: 3
		[Debug]2019/05/22 16:11:00 LinkByName : bond0.1005
		[Debug]2019/05/22 16:11:00 RandomVethName : veth1b5aa3e8
		[Debug]2019/05/22 16:11:00 Macvlan : mtu: 0  name:  veth1b5aa3e8  ParentIndex: 624  namespace:  5 Mode:  3
		[Debug]2019/05/22 16:11:00 netlink.LinkAdd(mv)
		[Debug]2019/05/22 16:11:00 netns.Do
		[Debug]2019/05/22 16:11:00 netns.Do ipv4SysctlValueName:  net.ipv4.conf.veth1b5aa3e8.proxy_arp
		[Debug]2019/05/22 16:11:00 ip.RenameLink:  veth1b5aa3e8 eth0
		[Debug]2019/05/22 16:11:00 macvlan.Name:  eth0
		[Debug]2019/05/22 16:11:00 netlink.LinkByName:  eth0  contMacvlan: &{{2 1500 0 eth0 5a:0c:dc:d2:38:47 broadcast|multicast 4098 624 0 <nil>  0xc0001aa0e8 0 0xc0001641a0 ether <nil> down 0 0 0 []} 3 []}
		[Debug]2019/05/22 16:11:00 netlink.LinkByName:  eth0  macvlan.Mac: 5a:0c:dc:d2:38:47  macvlan.Sandbox:  /proc/14713/ns/net
		[Debug]2019/05/22 16:11:00 Yes I am a Layer3  true
		[Debug]2019/05/22 16:11:00 ipam.ExecAdd(n.IPAM.Type, args.StdinData)  type:  host-local  stdin:  {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.113.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}
		[Debug]2019/05/22 16:11:00 ipam.ExecAdd Result: IP4:{IP:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.1.5.1 Routes:[{Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}]}, DNS:{Nameservers:[] Domain: Search:[] Options:[]}  version:
		[Debug]2019/05/22 16:11:00 current.NewResultFromResult CNIVersion 0.4.0
		[Debug]2019/05/22 16:11:00 current.IPs   {Version:4 Interface:<nil> Address:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.1.5.1}
		[Debug]2019/05/22 16:11:00 current.Routes   {Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}
		[Debug]2019/05/22 16:11:00 current.Routes   {[]  [] []}
		[Debug]2019/05/22 16:11:00 result.IPs  [{Version:4 Interface:<nil> Address:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.1.5.1}]
		[Debug]2019/05/22 16:11:00 result.Routes   [{Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}]
		[Debug]2019/05/22 16:11:00 ipc.Interface    0xc0001ee528
		[Debug]2019/05/22 16:11:00 netns.Do
		[Debug]2019/05/22 16:11:00 ipam.ConfigureIface     eth0 Interfaces:[{Name:eth0 Mac:5a:0c:dc:d2:38:47 Sandbox:/proc/14713/ns/net}], IP:[{Version:4 Interface:0xc0001ee528 Address:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.113.5.1}], Routes:[{Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}], DNS:{Nameservers:[] Domain: Search:[] Options:[]}
		[Debug]2019/05/22 16:11:00 net.InterfaceByName     eth0
		[Debug]2019/05/22 16:11:00 arping.GratuitousArpOverIface     10.1.5.185 {2 1500 eth0 5a:0c:dc:d2:38:47 up|broadcast|multicast}
		[Debug]2019/05/22 16:11:01 I will close  /proc/14713/ns/net



	*/

	// 创建一个日志对象

	macvlanlog.DebugLog.Println("read input from ContainerID:", args.ContainerID)
	macvlanlog.DebugLog.Println("read input from Netns:", args.Netns)
	macvlanlog.DebugLog.Println("read input from IfName:", args.IfName)
	macvlanlog.DebugLog.Println("read input from Args:", args.Args)
	macvlanlog.DebugLog.Println("read input from Path:", args.Path)
	macvlanlog.DebugLog.Println("read input from StdinData:", string(args.StdinData))
	macvlanlog.DebugLog.Println("read host from config :", client.GetGateConnStr())
	//dbconn = db.DBConnect()

	localpodname := stringutils.GetPodName(args.Args)

	PodName = localpodname
	ip, err := client.GetIpOfPodFromStargate(client.GetGateConnStr(), PodName)

	IpFromDB = ip

	if err != nil || IpFromDB == "" {
		macvlanlog.DebugLog.Println("can't get ip from db", PodName)
		//	return fmt.Errorf("Can't get ip from db ")
		macvlanlog.DebugLog.Println("begin cmdAdd_withoutip()")
		return cmdAdd_withoutip(args)

	} else {
		macvlanlog.DebugLog.Println("begin cmdAdd_withip()")
		return cmdAdd_withip(args)
	}

}

func cmdDel(args *skel.CmdArgs) error {

	macvlanlog.InitLog(DelMacVlanLog)
	defer macvlanlog.Close()

	macvlanlog.DebugLog.Println("read host from config :", client.GetGateConnStr())
	//dbconn = db.DBConnect()

	localpodname := stringutils.GetPodName(args.Args)

	PodName = localpodname
	ip, err := client.GetIpOfPodFromStargate(client.GetGateConnStr(), PodName)

	IpFromDB = ip

	if err != nil || IpFromDB == "" {
		macvlanlog.DebugLog.Println("can't get ip from db", args.ContainerID)
		//	return fmt.Errorf("Can't get ip from db ")
		macvlanlog.DebugLog.Println("begin cmdDel_withoutip()")
		return cmdDel_withoutip(args)

	} else {
		macvlanlog.DebugLog.Println("begin cmdDel_withip()")
		return cmdDel_withip(args)
	}

}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("macvlan"))
}

func cmdCheck(args *skel.CmdArgs) error {

	macvlanlog.InitLog(AddMacVlanLog)
	defer macvlanlog.Close()

	/*

		[Debug]2019/05/22 16:11:00 read input from ContainerID: 3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b
		[Debug]2019/05/22 16:11:00 read input from Netns: /proc/14713/ns/net
		[Debug]2019/05/22 16:11:00 read input from IfName: eth0
		[Debug]2019/05/22 16:11:00 read input from Args: IgnoreUnknown=1;K8S_POD_NAMESPACE=default-ops;K8S_POD_NAME=stargate.1000002918.s2469.g1.1;K8S_POD_INFRA_CONTAINER_ID=3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b
		[Debug]2019/05/22 16:11:00 read input from Path: /opt/cni/bin
		[Debug]2019/05/22 16:11:00 read input from StdinData: {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.113.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}
		[Debug]2019/05/22 16:11:00 load Conf:  {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.1.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}
		[Debug]2019/05/22 16:11:00 loaded Conf: n.master bond0.1005  mode:  bridge  mtu:  0  n.version
		[Debug]2019/05/22 16:11:00 isLayer3  true
		[Debug]2019/05/22 16:11:00 ns.GetNS  /proc/14713/ns/net
		[Debug]2019/05/22 16:11:00 开始创建macvlan 网络 dev: eth0  loadConf:  &{{ cni_macvlan1005 macvlan map[] {host-local} {[]  [] []} map[] <nil>} bond0.1005 bridge 0}  netns: &{0xc00000e128 false}
		[Debug]2019/05/22 16:11:00 createMacvlan
		[Debug]2019/05/22 16:11:00 modeFromString: bridge
		[Debug]2019/05/22 16:11:00 应该是bridge 模式
		[Debug]2019/05/22 16:11:00 modeFromString: mode: 3
		[Debug]2019/05/22 16:11:00 LinkByName : bond0.1005
		[Debug]2019/05/22 16:11:00 RandomVethName : veth1b5aa3e8
		[Debug]2019/05/22 16:11:00 Macvlan : mtu: 0  name:  veth1b5aa3e8  ParentIndex: 624  namespace:  5 Mode:  3
		[Debug]2019/05/22 16:11:00 netlink.LinkAdd(mv)
		[Debug]2019/05/22 16:11:00 netns.Do
		[Debug]2019/05/22 16:11:00 netns.Do ipv4SysctlValueName:  net.ipv4.conf.veth1b5aa3e8.proxy_arp
		[Debug]2019/05/22 16:11:00 ip.RenameLink:  veth1b5aa3e8 eth0
		[Debug]2019/05/22 16:11:00 macvlan.Name:  eth0
		[Debug]2019/05/22 16:11:00 netlink.LinkByName:  eth0  contMacvlan: &{{2 1500 0 eth0 5a:0c:dc:d2:38:47 broadcast|multicast 4098 624 0 <nil>  0xc0001aa0e8 0 0xc0001641a0 ether <nil> down 0 0 0 []} 3 []}
		[Debug]2019/05/22 16:11:00 netlink.LinkByName:  eth0  macvlan.Mac: 5a:0c:dc:d2:38:47  macvlan.Sandbox:  /proc/14713/ns/net
		[Debug]2019/05/22 16:11:00 Yes I am a Layer3  true
		[Debug]2019/05/22 16:11:00 ipam.ExecAdd(n.IPAM.Type, args.StdinData)  type:  host-local  stdin:  {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.113.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}
		[Debug]2019/05/22 16:11:00 ipam.ExecAdd Result: IP4:{IP:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.1.5.1 Routes:[{Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}]}, DNS:{Nameservers:[] Domain: Search:[] Options:[]}  version:
		[Debug]2019/05/22 16:11:00 current.NewResultFromResult CNIVersion 0.4.0
		[Debug]2019/05/22 16:11:00 current.IPs   {Version:4 Interface:<nil> Address:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.1.5.1}
		[Debug]2019/05/22 16:11:00 current.Routes   {Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}
		[Debug]2019/05/22 16:11:00 current.Routes   {[]  [] []}
		[Debug]2019/05/22 16:11:00 result.IPs  [{Version:4 Interface:<nil> Address:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.1.5.1}]
		[Debug]2019/05/22 16:11:00 result.Routes   [{Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}]
		[Debug]2019/05/22 16:11:00 ipc.Interface    0xc0001ee528
		[Debug]2019/05/22 16:11:00 netns.Do
		[Debug]2019/05/22 16:11:00 ipam.ConfigureIface     eth0 Interfaces:[{Name:eth0 Mac:5a:0c:dc:d2:38:47 Sandbox:/proc/14713/ns/net}], IP:[{Version:4 Interface:0xc0001ee528 Address:{IP:10.1.5.185 Mask:ffffff00} Gateway:10.113.5.1}], Routes:[{Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>}], DNS:{Nameservers:[] Domain: Search:[] Options:[]}
		[Debug]2019/05/22 16:11:00 net.InterfaceByName     eth0
		[Debug]2019/05/22 16:11:00 arping.GratuitousArpOverIface     10.1.5.185 {2 1500 eth0 5a:0c:dc:d2:38:47 up|broadcast|multicast}
		[Debug]2019/05/22 16:11:01 I will close  /proc/14713/ns/net



	*/

	// 创建一个日志对象

	macvlanlog.DebugLog.Println("cmdCheck read input from ContainerID:", args.ContainerID)
	macvlanlog.DebugLog.Println("cmdCheck read input from Netns:", args.Netns)
	macvlanlog.DebugLog.Println("cmdCheck read input from IfName:", args.IfName)
	macvlanlog.DebugLog.Println("cmdCheck read input from Args:", args.Args)
	macvlanlog.DebugLog.Println("cmdCheck read input from Path:", args.Path)
	macvlanlog.DebugLog.Println("cmdCheck read input from StdinData:", string(args.StdinData))

	n, _, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	isLayer3 := n.IPAM.Type != ""

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	if isLayer3 {
		// run the IPAM plugin and get back the config to apply
		err = ipam.ExecCheck(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	// Parse previous result.
	if n.NetConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	var contMap current.Interface
	// Find interfaces for names whe know, macvlan device name inside container
	for _, intf := range result.Interfaces {
		if args.IfName == intf.Name {
			if args.Netns == intf.Sandbox {
				contMap = *intf
				continue
			}
		}
	}

	// The namespace must be the same as what was configured
	if args.Netns != contMap.Sandbox {
		return fmt.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			contMap.Sandbox, args.Netns)
	}

	m, err := netlink.LinkByName(n.Master)
	if err != nil {
		return fmt.Errorf("failed to lookup master %q: %v", n.Master, err)
	}

	// Check prevResults for ips, routes and dns against values found in the container
	if err := netns.Do(func(_ ns.NetNS) error {

		// Check interface against values found in the container
		err := validateCniContainerInterface(contMap, m.Attrs().Index, n.Mode)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func validateCniContainerInterface(intf current.Interface, parentIndex int, modeExpected string) error {

	var link netlink.Link
	var err error

	if intf.Name == "" {
		return fmt.Errorf("Container interface name missing in prevResult: %v", intf.Name)
	}
	link, err = netlink.LinkByName(intf.Name)
	if err != nil {
		return fmt.Errorf("Container Interface name in prevResult: %s not found", intf.Name)
	}
	if intf.Sandbox == "" {
		return fmt.Errorf("Error: Container interface %s should not be in host namespace", link.Attrs().Name)
	}

	macv, isMacvlan := link.(*netlink.Macvlan)
	if !isMacvlan {
		return fmt.Errorf("Error: Container interface %s not of type macvlan", link.Attrs().Name)
	}

	mode, err := modeFromString(modeExpected)
	if macv.Mode != mode {
		currString, err := modeToString(macv.Mode)
		if err != nil {
			return err
		}
		confString, err := modeToString(mode)
		if err != nil {
			return err
		}
		return fmt.Errorf("Container macvlan mode %s does not match expected value: %s", currString, confString)
	}

	if intf.Mac != "" {
		if intf.Mac != link.Attrs().HardwareAddr.String() {
			return fmt.Errorf("Interface %s Mac %s doesn't match container Mac: %s", intf.Name, intf.Mac, link.Attrs().HardwareAddr)
		}
	}

	return nil
}

func cmdAdd_withip(args *skel.CmdArgs) error {

	macvlanmap, bondmap := stringutils.GetMapFromFile(NetWorkConfigFile)
	if len(macvlanmap) == 0 {
		return fmt.Errorf("len(macvlanmap) ")
	}
	if len(bondmap) == 0 {
		return fmt.Errorf("len(bondmap) ")
	}

	newStdinData := stringutils.CreateNewJson(ConstMacVlanString, IpFromDB, macvlanmap, bondmap)

	n, cniVersion, err := loadConf([]byte(newStdinData))
	if err != nil {
		return err
	}

	isLayer3 := n.IPAM.Type != ""
	macvlanlog.DebugLog.Println("isLayer3 ", isLayer3)

	macvlanlog.DebugLog.Println("ns.GetNS ", args.Netns)
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()
	defer macvlanlog.DebugLog.Println("I will close ", netns.Path())

	macvlanlog.DebugLog.Println("开始创建macvlan 网络 dev:", args.IfName, " loadConf: ", n, " netns:", netns)
	macvlanInterface, err := createMacvlan(n, args.IfName, netns)
	if err != nil {
		return err
	}

	// Delete link if err to avoid link leak in this ns
	defer func() {
		if err != nil {
			netns.Do(func(_ ns.NetNS) error {
				return ip.DelLinkByName(args.IfName)
			})
		}
	}()

	// Assume L2 interface only
	result := &current.Result{CNIVersion: cniVersion, Interfaces: []*current.Interface{macvlanInterface}}

	if isLayer3 {
		macvlanlog.DebugLog.Println("Yes I am a Layer3 ", isLayer3)
		// run the IPAM plugin and get back the config to apply

		macvlanlog.DebugLog.Println("ipam.ExecAdd(n.IPAM.Type, args.StdinData)", " type: ", n.IPAM.Type, " stdin: ", string(args.StdinData))

		macvlanmap, bondmap := stringutils.GetMapFromFile(NetWorkConfigFile)

		stdinData := stringutils.CreateNewJson(ConstMacVlanString, IpFromDB, macvlanmap, bondmap)
		macvlanlog.DebugLog.Println("skill ipam.ExecAdd ")
		r, err := macvlannet.GetIpamIp(IpFromDB, stdinData, args.Args, args.ContainerID, args.IfName)
		macvlanlog.DebugLog.Println("skill ipam.ExecAdd ")
		//r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			macvlanlog.DebugLog.Println("macvlannet.GetIpamIp error != nil ", err)
			return err
		}

		macvlanlog.DebugLog.Println("macvlannet.GetIpamIp:", r.String())

		// Invoke ipam del if err to avoid ip leak
		defer func() {
			if err != nil {
				macvlanlog.DebugLog.Println(" Invoke ipam del if err to avoid ip leak , we don't need do it")
				//ipam.ExecDel(n.IPAM.Type, args.StdinData)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		ipamResult, err := current.NewResultFromResult(r)
		if err != nil {
			return err
		}

		macvlanlog.DebugLog.Println("current.NewResultFromResult CNIVersion", ipamResult.CNIVersion)
		for _, item := range ipamResult.IPs {
			macvlanlog.DebugLog.Println("current.IPs  ", item)
		}
		for _, item := range ipamResult.Interfaces {
			macvlanlog.DebugLog.Println("current.Interfaces  ", item)
		}

		for _, item := range ipamResult.Routes {
			macvlanlog.DebugLog.Println("current.Routes  ", item)
		}

		macvlanlog.DebugLog.Println("current.Routes  ", ipamResult.DNS)

		if len(ipamResult.IPs) == 0 {
			return errors.New("IPAM plugin returned missing IP config")
		}

		result.IPs = ipamResult.IPs
		macvlanlog.DebugLog.Println("result.IPs ", ipamResult.IPs)
		result.Routes = ipamResult.Routes
		macvlanlog.DebugLog.Println("result.Routes  ", ipamResult.Routes)

		for _, ipc := range result.IPs {
			// All addresses apply to the container macvlan interface
			ipc.Interface = current.Int(0)
			macvlanlog.DebugLog.Println("ipc.Interface   ", ipc.Interface)
		}

		err = netns.Do(func(_ ns.NetNS) error {
			macvlanlog.DebugLog.Println("netns.Do   ")

			macvlanlog.DebugLog.Println("ipam.ConfigureIface    ", args.IfName, result)
			if err := ipam.ConfigureIface(args.IfName, result); err != nil {
				return err
			}
			macvlanlog.DebugLog.Println("net.InterfaceByName    ", args.IfName)
			contVeth, err := net.InterfaceByName(args.IfName)
			if err != nil {
				return fmt.Errorf("failed to look up %q: %v", args.IfName, err)
			}

			for _, ipc := range result.IPs {
				if ipc.Version == "4" {
					macvlanlog.DebugLog.Println("arping.GratuitousArpOverIface    ", ipc.Address.IP, *contVeth)
					_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		// For L2 just change interface status to up
		//
		macvlanlog.DebugLog.Println("Yes I am a Layer2 ", isLayer3)
		err = netns.Do(func(_ ns.NetNS) error {
			macvlanInterfaceLink, err := netlink.LinkByName(args.IfName)
			if err != nil {
				return fmt.Errorf("failed to find interface name %q: %v", macvlanInterface.Name, err)
			}

			if err := netlink.LinkSetUp(macvlanInterfaceLink); err != nil {
				return fmt.Errorf("failed to set %q UP: %v", args.IfName, err)
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	result.DNS = n.DNS

	return types.PrintResult(result, cniVersion)

}

func cmdAdd_withoutip(args *skel.CmdArgs) error {
	n, cniVersion, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	isLayer3 := n.IPAM.Type != ""

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	macvlanInterface, err := createMacvlan(n, args.IfName, netns)
	if err != nil {
		return err
	}

	// Delete link if err to avoid link leak in this ns
	defer func() {
		if err != nil {
			netns.Do(func(_ ns.NetNS) error {
				return ip.DelLinkByName(args.IfName)
			})
		}
	}()

	// Assume L2 interface only
	result := &current.Result{CNIVersion: cniVersion, Interfaces: []*current.Interface{macvlanInterface}}

	if isLayer3 {
		// run the IPAM plugin and get back the config to apply
		r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}

		// Invoke ipam del if err to avoid ip leak
		defer func() {
			if err != nil {
				ipam.ExecDel(n.IPAM.Type, args.StdinData)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		ipamResult, err := current.NewResultFromResult(r)
		if err != nil {
			return err
		}

		if len(ipamResult.IPs) == 0 {
			return errors.New("IPAM plugin returned missing IP config")
		}

		result.IPs = ipamResult.IPs
		result.Routes = ipamResult.Routes

		for _, ipc := range result.IPs {
			// All addresses apply to the container macvlan interface
			ipc.Interface = current.Int(0)
		}

		err = netns.Do(func(_ ns.NetNS) error {
			if err := ipam.ConfigureIface(args.IfName, result); err != nil {
				return err
			}

			contVeth, err := net.InterfaceByName(args.IfName)
			if err != nil {
				return fmt.Errorf("failed to look up %q: %v", args.IfName, err)
			}

			for _, ipc := range result.IPs {
				if ipc.Version == "4" {
					_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		// For L2 just change interface status to up
		err = netns.Do(func(_ ns.NetNS) error {
			macvlanInterfaceLink, err := netlink.LinkByName(args.IfName)
			if err != nil {
				return fmt.Errorf("failed to find interface name %q: %v", macvlanInterface.Name, err)
			}

			if err := netlink.LinkSetUp(macvlanInterfaceLink); err != nil {
				return fmt.Errorf("failed to set %q UP: %v", args.IfName, err)
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	result.DNS = n.DNS

	return types.PrintResult(result, cniVersion)
}

func cmdDel_withoutip(args *skel.CmdArgs) error {
	n, _, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	isLayer3 := n.IPAM.Type != ""

	if isLayer3 {
		err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		if err := ip.DelLinkByName(args.IfName); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})

	return err
}

func cmdDel_withip(args *skel.CmdArgs) error {
	macvlanmap, bondmap := stringutils.GetMapFromFile(NetWorkConfigFile)
	if len(macvlanmap) == 0 {
		return fmt.Errorf("len(macvlanmap) ")
	}
	if len(bondmap) == 0 {
		return fmt.Errorf("len(bondmap) ")
	}

	new_args_StdinData := stringutils.CreateNewJson(ConstMacVlanString, IpFromDB, macvlanmap, bondmap)
	args.StdinData = []byte(new_args_StdinData)

	n, _, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	isLayer3 := n.IPAM.Type != ""

	if isLayer3 {
		macvlanlog.DebugLog.Println("Hacking, we skip ipam local-host process, ", args.ContainerID)
		/*
			err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
			if err != nil {
				return err
			}
		*/

	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {

		if err := ip.DelLinkByName(args.IfName); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})

	return err

}
