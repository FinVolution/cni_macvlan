package client

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type IpRecord struct {
	Code       int    `json:"code"`
	Message    string `json:"message"`
	StackTrace string `json:"stackTrace"`

	Detail string `json:"details"`
}

 
 
var (
	// 匹配 IP4
	ip4Pattern = `((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)`
	ip4        = regexpCompile(ip4Pattern)
)

func regexpCompile(str string) *regexp.Regexp {
	return regexp.MustCompile("^" + str + "$")
}

 
func isMatch(exp *regexp.Regexp, val interface{}) bool {
	switch v := val.(type) {
	case []rune:
		return exp.MatchString(string(v))
	case []byte:
		return exp.Match(v)
	case string:
		return exp.MatchString(v)
	default:
		return false
	}
}

func getIp(result string) (string, error) {

	stb := &IpRecord{}

	err := json.Unmarshal([]byte(result), &stb)
	if err != nil {
		return "", err
	} else {
		if stb.Code != 0 {
			return "", fmt.Errorf("return Code is not 0")
		}

		Ip := strings.Replace(stb.Detail, " ", "", -1)
		b := isMatch(ip4, Ip)
		if !b {
			err = fmt.Errorf("ip is not a ipv4 " + Ip)
		}
		return Ip, err
	}
}
