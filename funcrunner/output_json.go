package funcrunner

import (
	"encoding/json"
	"log"
)

func Marshal(v any) []byte {
	bs, err := json.Marshal(v)
	if err != nil {
		log.Fatalf("failure to marshal data: %s\n", err)
	}
	return bs
}

type DevInfo struct {
	Name         string `json:"name"`
	Name2        string `json:"name2"`
	ManagementIP string `json:"mgmt_ip"`
	Vendor       string `json:"vendor"`
	Platform     string `json:"platform"`
	Serial       string `json:"serial"`
	Serial2      string `json:"serial2"`
	Version      string `json:"version"`
	Parent       string `json:"parent,omitempty"`
	UUID         string `json:"uuid"`
	CPU          string `json:"cpu,omitempty"`
	RAM          string `json:"ram,omitempty"`
	Bandwidth    string `json:"bandwidth,omitempty"`
}

type IntInfo struct {
	Hostname    string   `json:"hostname"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Driver      string   `json:"driver"`
	Mac         string   `json:"mac"`
	IPInfo      []IPInfo `json:"ipinfo"`
	Parent      string   `json:"parent,omitempty"`
	SNMPIndex   string   `json:"snmp_index"`
	Optic	    Optic    `json:"optic,omitempty"`
}

type IFIndex struct {
	Hostname string `json:"hostname"`
	IFName   string `json:"interface_name"`
	IFIndex  string `json:"interface_index"`
}

type IPInfo struct {
	Address string            `json:"address"`
	Network string            `json:"network"`
	Bits    int               `json:"bits"`
	Arp     map[string]string `json:"arp"`
}

type ArpInfo struct {
	Hostname  string `json:"hostname"`
	Mac       string `json:"mac"`
	IPAddress string `json:"ip_address"`
	Intf      string `json:"interface"`
}

type Backup struct {
	Hostname   string `json:"hostname"`
	DeviceType string `json:"device_type"`
	Data       string `json:"data"`
	Hash       string `json:"hash"`
}

type NTP struct {
	Hostname   string   `json:"hostname"`
	NTPServers []string `json:"ntp_servers"`
}

type SNMP struct {
	Hostname string   `json:"hostname"`
	Servers  []string `json:"snmp_servers"`
}

type Optic struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	ModelType    string `json:"model_type,omitempty"`
	MediaType    string `json:"media_type,omitempty"`
}
