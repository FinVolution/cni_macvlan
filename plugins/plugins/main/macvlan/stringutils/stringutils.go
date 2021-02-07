package stringutils

import (
	"io/ioutil"
	"strings"
)

const (
	startIp = "100"
	endIp   = "200"
)

func CleanString(conn string) string {
	//fmt.Println([]byte(conn))
	conn = strings.Replace(conn, "\n", "", -1)
	conn = strings.Replace(conn, "\r", "", -1)
	conn = strings.Replace(conn, " ", "", -1)
	//fmt.Println([]byte(conn))
	return conn
}

func GetPodName(conn string) string {
	v := StringToMap(conn, ";", "=")
	value, ok := v["K8S_POD_NAME"]
	if ok {
		return value
	}
	return ""
}

func GetMapFromFile(filename string) (map[string]string, map[string]string) {
	result := map[string]string{}
	data, err := ioutil.ReadFile(CleanString(filename))
	if err != nil {
		return result, result
	}
	result1, result2 := StringTo2Maps(string(data), ";", "=", ",")
	return result1, result2
}

func StringToMap(src string, split string, equal string) map[string]string {
	src = CleanString(src)
	v := strings.Split(src, split)
	result := map[string]string{}
	for _, item := range v {
		v2 := strings.Split(item, equal)
		if len(v2) == 2 {
			result[v2[0]] = v2[1]
		}
	}
	return result
}

func StringTo2Maps(src string, split string, equal string, split2 string) (macvlanmap map[string]string, bondmap map[string]string) {
	src = CleanString(src)
	v := strings.Split(src, split)
	macvlanmap = map[string]string{}
	bondmap = map[string]string{}
	for _, item := range v {
		v2 := strings.Split(item, equal)
		if len(v2) == 2 {
			//result[v2[0]] = v2[1]
			v3 := strings.Split(v2[1], split2)
			if len(v3) == 2 {
				macvlanmap[v2[0]] = v3[0]
				bondmap[v2[0]] = v3[1]
			}
		}
	}
	return macvlanmap, bondmap
}

func GetMasterFromIp(ip string) string {
	v := strings.Split(ip, ".")
	if len(v) == 4 {
		return v[0] + "." + v[1] + "." + v[2] + "." + "0"
	}
	return "0.0.0.0"
}

func GetGatewayFromIp(ip string) string {
	v := strings.Split(ip, ".")
	if len(v) == 4 {
		return v[0] + "." + v[1] + "." + v[2] + "." + "1"
	}
	return "0.0.0.0"
}

func GetStartFromIp(ip string) string {
	v := strings.Split(ip, ".")
	if len(v) == 4 {
		return v[0] + "." + v[1] + "." + v[2] + "." + startIp
	}
	return "0.0.0.0"
}

func GetEndFromIp(ip string) string {
	v := strings.Split(ip, ".")
	if len(v) == 4 {
		return v[0] + "." + v[1] + "." + v[2] + "." + endIp
	}
	return "0.0.0.0"
}

func GetSubnetFromIp(ip string) string {
	v := strings.Split(ip, ".")
	if len(v) == 4 {
		return v[0] + "." + v[1] + "." + v[2] + "." + "0/24"
	}
	return "0.0.0.0/24"
}

func CreateNewJson(src string, newIp string, macVlan map[string]string, bondMap map[string]string) string {

	startip := GetStartFromIp(newIp)
	endip := GetEndFromIp(newIp)
	subnet := GetSubnetFromIp(newIp)
	master := GetMasterFromIp(newIp)
	gateway := GetGatewayFromIp(newIp)
	//   // {"cniVersion":"","ipMasq":false,"ipam":{"gateway":"GateWayIP","rangeEnd":"RANGEENDIP","rangeStart":"RANGESTARTIP","routes":[{"dst":"0.0.0.0/0"}],"subnet":"SUBNET","type":"host-local"},"isGateway":true,"master":"BANDNAME","mode":"bridge","name":"CNINAME","type":"macvlan"}

	src = strings.Replace(src, "GateWayIP", gateway, -1)
	src = strings.Replace(src, "RANGESTARTIP", startip, -1)
	src = strings.Replace(src, "RANGEENDIP", endip, -1)

	src = strings.Replace(src, "SUBNET", subnet, -1)
	cniname, ok := macVlan[master]
	if ok {
		src = strings.Replace(src, "CNINAME", cniname, -1)
	}
	bandname, ok := bondMap[master]
	if ok {
		src = strings.Replace(src, "BANDNAME", bandname, -1)
	}

	return src

}
