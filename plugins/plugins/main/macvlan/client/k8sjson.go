package client

import (
	"encoding/json"
	"fmt"

	. "github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
)

type K8sJson struct {
	ApiVersion string            `json:"apiVersion"`
	Items      []interface{}     `json:"items"`
	Kind       string            `json:"kind"`
	Metadata   map[string]string `json:"metadata"`
}

type Item struct {
	Metadata MetaDataStruct         `json:"metadata"`
	Spec     map[string]interface{} `json:"spec"`
	Status   map[string]interface{} `json:"status"`
}

type MetaDataStruct struct {
	CreationTimestamp string `json:"creationTimestamp"`

	Labels map[string]string `json:"labels"`

	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	ResourceVersion string `json:"resourceVersion"`
	SselfLink       string `json:"selfLink"`
	Uid             string `json:"uid" `
}

func ParseK8SJson(k8sjson string) (ip string, err error) {
	var a K8sJson
	Ip_add := ""
	DebugLog.Println(k8sjson)
	if err := json.Unmarshal([]byte(k8sjson), &a); err != nil {
		return "", fmt.Errorf("wrong json format")
	} else {
		DebugLog.Println(a)
		for key_items, value_items := range a.Items {
			DebugLog.Println(key_items)
			raw_value_items, ok := value_items.(map[string]interface{})
			if !ok {

				return "", fmt.Errorf("wrong json format")
			}

			for key_metadata, value_metadata := range raw_value_items {
				DebugLog.Println(key_metadata)

				if key_metadata == "metadata" {
					raw_value_metadata, ok := value_metadata.(map[string]interface{})
					if !ok {
						return "", fmt.Errorf("wrong json format metadata ")

					}
					for key_labels, value_labels := range raw_value_metadata {
						if key_labels == "labels" {
							labels_map, ok := value_labels.(map[string]interface{})
							if !ok {
								return "", fmt.Errorf("wrong json format labels ")
							}
							for key_ip, value_ip := range labels_map {
								DebugLog.Println(key_ip)
								if key_ip == "ip" {
									raw_ip_value, ok := value_ip.(string)
									if !ok {
										return "", fmt.Errorf("wrong json format ip ")
									}
									DebugLog.Println(raw_ip_value)
									Ip_add = raw_ip_value
								}
							}

						}
					}

				}
			}

		}
	}
	return Ip_add, nil
}
