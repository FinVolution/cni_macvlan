package client

import (
	"fmt"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/config"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
	"github.com/containernetworking/plugins/plugins/main/macvlan/stringutils"
	"io/ioutil"
	"net/http"
	"time"
)

func GetIpOfPodFromStargate(url string, podname string) (ip string, err error) {

	DebugLog.Println("URL:>", url)

	timeout := time.Duration(5 * time.Second)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("wrong url  http.NewRequest " + url)
	}

	q := req.URL.Query()

	q.Add("fieldSelector", "metadata.name="+podname)

	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("client.Do  error")
	}
	defer resp.Body.Close()

	DebugLog.Println("response Status:", resp.Status)
	DebugLog.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	DebugLog.Println("response Body:", string(body))
	ip, err = ParseK8SJson(string(body))
	return ip, err
}

func GetGateConnStr() string {
	dat, err := ioutil.ReadFile(stringutils.CleanString(GATEConfigFile))
	if err != nil {
		return ""
	}
	conn := string(dat)
	conn = stringutils.CleanString(conn)
	return conn
}
