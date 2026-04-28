package funcrunner

import (
	"log"
	"strings"

	"github.com/natenjoy/funcrunner/scraper"
)

var SDXCommands = map[string][]string{
	"arpinfo": []string{"exit"},
	"devinfo": []string{"show systemstatus"},
	"intinfo": []string{"show systemstatus", "show networkconfig"},
	"ifindex": []string{"exit"},
}

var SDXProcess = map[string]func([]*scraper.SSHRequest) []byte{
	"arpinfo": SDXArpInfo,
	"devinfo": SDXDevInfo,
	"intinfo": SDXIntInfo,
	"ifindex": SDXIFIndex,
}

func SDXIntInfo(srs []*scraper.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(SDXCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}

		var i = IntInfo{Hostname: sr.Hostname, Name: "LA Management", Driver: "veth", IPInfo: make([]IPInfo, 0)}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Host Id:") {
				macStr := strings.Fields(line)[2]
				i.Mac = ConvertMacAddress(strings.Trim(macStr, " \t"))
				break
			}
		}
		var mgmtip, mask, network string
		for _, line := range strings.Split(sr.Responses[1], "\n") {
			if strings.Contains(line, "Management Service IP Address:") {
				mgmtip = strings.Fields(line)[4]
			}
			if strings.Contains(line, "Netmask") && !strings.Contains(line, "XEN") {
				mask = strings.Fields(line)[1]
			}
		}
		network = GetSubnet(mgmtip, mask)
		i.IPInfo = append(i.IPInfo, IPInfo{Address: mgmtip, Network: network, Bits: CountBits(mask), Arp: make(map[string]string, 0)})
		intInfo = append(intInfo, i)
	}
	return Marshal(intInfo)
}

func SDXDevInfo(srs []*scraper.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(SDXCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var newDevInfo DevInfo
		newDevInfo.Name = sr.Hostname
		newDevInfo.ManagementIP = sr.IPAddress
		newDevInfo.Vendor = "Citrix"
		newDevInfo.Serial = sr.Netdev.SerialNumber
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Platform:") {
				field := strings.Split(line, "Platform:")[1]
				newDevInfo.Platform = strings.Trim(field, " \t")
			}
			if strings.Contains(line, "Build:") {
				field1 := strings.Split(line, "Build:")[1]
				field2 := strings.Split(field1, ",")[0]
				newDevInfo.Version = strings.Trim(field2, " \t")
			}
		}
		deviceInfo = append(deviceInfo, newDevInfo)
	}
	return Marshal(deviceInfo)
}

// Not applicable
func SDXArpInfo(srs []*scraper.SSHRequest) []byte {
	var arpInfo = []ArpInfo{}
	return Marshal(arpInfo)
}

func SDXIFIndex(srs []*scraper.SSHRequest) []byte {
        var ifindex = []IFIndex{}
        return Marshal(ifindex)
}
