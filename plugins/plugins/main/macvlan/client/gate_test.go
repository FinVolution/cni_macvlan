package client

import (
	"testing"
)

func Test_httpclient(t *testing.T) {

	s1 := "http://www.163.com"

	s2 := GetGateConnStr()
	if s1 != s2 {
		t.Error(s1, " ", s2)
	}

}
