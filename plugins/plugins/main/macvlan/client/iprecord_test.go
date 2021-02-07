package client

import (
	"fmt"
	"testing"
)

func TestJson_1(t *testing.T) {
	s := `{"code":0,"message":"请求成功完成。","stackTrace":null,"details":"192.168.1.1"}`

	ip, err := getIp(s)
	if err != nil {
		t.Error(err)
	}
	if ip != "192.168.1.1" {
		t.Error(ip)
	}

	s = `{"code":120,"message":"请求成功完成。","stackTrace":null,"details":"192.168.1.1"}`
	ip, err = getIp(s)
	if err == nil {
		t.Error(err)
	}
	if ip != "" {
		t.Error(ip)
	}
}

func TestJson_2(t *testing.T) {

	s1 := "{  \"ip\" : \"192.168.3.4\"  }"
	ip, err := getIp(s1)
	if err != nil {

		t.Error(err)
	} else {
		fmt.Println("ip :", ip)
	}
	s1 = "{  \"ip\" : \"\"  }"
	ip, err = getIp(s1)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("ip :", ip)
	}

	s1 = "{  \"ip\" : \"null\"  }"

	ip, err = getIp(s1)
	if err != nil {

		t.Error(err)
	} else {
		fmt.Println("ip :", ip)
	}

	s1 = "{  \"ip\" : null  }"
	ip, err = getIp(s1)
	if err != nil {

		t.Error(err)
	} else {
		fmt.Println("ip :", ip)
	}
	s1 = "{  \"ip\" : \"1111\" "
	ip, err = getIp(s1)
	if err != nil {

		fmt.Println(err)
	} else {
		t.Error("wrong")
	}

}
