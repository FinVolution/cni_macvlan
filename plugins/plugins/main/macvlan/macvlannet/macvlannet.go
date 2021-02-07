package macvlannet

import (
	"bufio"
	"github.com/containernetworking/plugins/plugins/main/macvlan/stringutils"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
	"os"
	"strings"
)

func GetIpamIp(ipString string, StdinData string, Args string, ContainerID string, IfName string) (types.Result, error) {

	/*
		[Debug]2019/05/22 16:11:00 read input from ContainerID: 3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b
			[Debug]2019/05/22 16:11:00 read input from Netns: /proc/14713/ns/net
			[Debug]2019/05/22 16:11:00 read input from IfName: eth0
			[Debug]2019/05/22 16:11:00 read input from Args: IgnoreUnknown=1;K8S_POD_NAMESPACE=default-ops;K8S_POD_NAME=stargate.1000002918.s2469.g1.1;K8S_POD_INFRA_CONTAINER_ID=3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b
			[Debug]2019/05/22 16:11:00 read input from Path: /opt/cni/bin
			[Debug]2019/05/22 16:11:00 read input from StdinData: {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.1.5.1","rangeEnd":"10.1.5.200","rangeStart":"10.1.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.113.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}
	*/
	//ContainerID := "3ac446b5f82a214d51729ab025f36c2ca08ca0b87d58b273f1d1e7cbb199cd3b"
	//Netns := "/proc/14713/ns/net"
	//IfName := "eth0"
	//Path := "/opt/cni/bin"
	//stdinData := `{"cniVersion":"","ipMasq":false,"ipam":{"gateway":"10.113.5.1","rangeEnd":"10.113.5.200","rangeStart":"10.113.5.100","routes":[{"dst":"0.0.0.0/0"}],"subnet":"10.113.5.0/24","type":"host-local"},"isGateway":true,"master":"bond0.1005","mode":"bridge","name":"cni_macvlan1005","type":"macvlan"}`
	/*
		DebugLog.Println("read input from ContainerID:", ContainerID)
		DebugLog.Println("read input from Netns:", Netns)
		DebugLog.Println("read input from IfName:", IfName)
	*/
	DebugLog.Println("read input from Args:", Args)

	//DebugLog.Println("read input from Path:", Path)
	DebugLog.Println("read input from StdinData:", StdinData)

	ipamConf, confVersion, err := allocator.LoadIPAMConfig([]byte(StdinData), Args)
	if err != nil {
		return nil, err
	}

	DebugLog.Println("allocator.LoadIPAMConfig confVersion", confVersion)
	DebugLog.Println("allocator.LoadIPAMConfig  IPAMConfig", *ipamConf)

	result := &current.Result{}

	if ipamConf.ResolvConf != "" {
		DebugLog.Println(" ipamConf.ResolvConf != \"\" ")
		dns, err := parseResolvConf(ipamConf.ResolvConf)
		if err != nil {
			return nil, err
		}
		result.DNS = *dns
	}
	var requestedIP net.IP

	/*
		DebugLog.Println("disk.New ", ipamConf.Name, "datadir:", ipamConf.DataDir)
		store, err := disk.New(ipamConf.Name, ipamConf.DataDir)
		if err != nil {
			return nil, err
		}
		defer store.Close()

		// Keep the allocators we used, so we can release all IPs if an error
		// occurs after we start allocating
		allocs := []*allocator.IPAllocator{}

		// Store all requested IPs in a map, so we can easily remove ones we use
		// and error if some remain
		requestedIPs := map[string]net.IP{} //net.IP cannot be a key

		for _, ip := range ipamConf.IPArgs {
			requestedIPs[ip.String()] = ip
			DebugLog.Println("for _, ip := range ipamConf.IPArgs ", ip.String(), " ip", ip)
		}

		for _, rangeset := range ipamConf.Ranges {
			//allocator := allocator.NewIPAllocator(&rangeset, store, idx)

			// Check to see if there are any custom IPs requested in this range.

			for k, ip := range requestedIPs {
				if rangeset.Contains(ip) {
					requestedIP = ip
					delete(requestedIPs, k)
					break
				}
			}

	*/

	version := "4"
	requestedIP = net.ParseIP(ipString)
	mask := net.CIDRMask(24, 32)
	gwip := net.ParseIP(stringutils.GetGatewayFromIp(ipString))
	reservedIP := &net.IPNet{IP: requestedIP, Mask: mask}

	ipConf := &current.IPConfig{
		Version: version,
		Address: *reservedIP,
		Gateway: gwip,
	}

	result.IPs = append(result.IPs, ipConf)

	/*
		// If an IP was requested that wasn't fulfilled, fail
		if len(requestedIPs) != 0 {
			for _, alloc := range allocs {
				_ = alloc.Release(ContainerID, IfName)
			}
			errstr := "failed to allocate all requested IPs:"
			for _, ip := range requestedIPs {
				errstr = errstr + " " + ip.String()
			}
			return nil, fmt.Errorf(errstr)
		}

	*/

	result.Routes = ipamConf.Routes

	/*

		type Result struct {
			CNIVersion string         `json:"cniVersion,omitempty"`
			Interfaces []*Interface   `json:"interfaces,omitempty"`
			IPs        []*IPConfig    `json:"ips,omitempty"`
			Routes     []*types.Route `json:"routes,omitempty"`
			DNS        types.DNS      `json:"dns,omitempty"`
		}
	*/

	newResult, err := result.GetAsVersion(confVersion)
	if err != nil {
		return nil, err
	}
	//types.xxx
	DebugLog.Println("newResult  ", newResult.String())
	//types.PrintResult(result, confVersion)

	newResult, err = result.GetAsVersion(confVersion)
	if err != nil {
		return newResult, err
	}
	return newResult, err

	/*
		// Plugin must return result in same version as specified in netconf
		versionDecoder := &version.ConfigDecoder{}
		confVersion, err := versionDecoder.Decode(netconf)
		if err != nil {
			return nil, err
		}
	*/
	//return version.NewResult(confVersion, stdoutBytes)
}

// parseResolvConf parses an existing resolv.conf in to a DNS struct
func parseResolvConf(filename string) (*types.DNS, error) {
	fp, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	dns := types.DNS{}
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Skip comments, empty lines
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			dns.Nameservers = append(dns.Nameservers, fields[1])
		case "domain":
			dns.Domain = fields[1]
		case "search":
			dns.Search = append(dns.Search, fields[1:]...)
		case "options":
			dns.Options = append(dns.Options, fields[1:]...)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &dns, nil
}
