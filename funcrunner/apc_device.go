package funcrunner

import (
	"log"
	"strings"

	"github.com/natenjoy/funcrunner/netdevs"
)

var APCCommands = map[string][]string{
	"arpinfo": []string{"exit"},
	"devinfo": []string{"about"},
	"intinfo": []string{"tcpip"},
	"getntp":  []string{"ntp"},
	"getsnmp": []string{"snmp"},
	"ifindex": []string{"exit"},
}

var APCProcess = map[string]func([]*netdevs.SSHRequest) []byte{
	"arpinfo": APCArpInfo,
	"devinfo": APCDevInfo,
	"intinfo": APCIntInfo,
	"getntp":  APCGetNTP,
	"getsnmp": APCGetSNMP,
	"ifindex": APCIFIndex,
}

func APCIntInfo(srs []*netdevs.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(APCCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var i = IntInfo{Hostname: sr.Hostname, Name: "mgmt", Driver: "100mbps", IPInfo: make([]IPInfo, 0)}
		var ip = IPInfo{Arp: make(map[string]string, 0)}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Active IPv4 Address:") {
				fields := strings.Fields(line)
				ip.Address = fields[3]
			}
			if strings.Contains(line, "Active IPv4 Subnet Mask:") {
				fields := strings.Fields(line)
				ip.Bits = CountBits(fields[4])
			}
			if strings.Contains(line, "Ethernet MAC:") {
				mac := strings.Fields(line)[2]
				i.Mac = ConvertMacAddress(mac)
			}
		}
		ip.Network = GetSubnet(ip.Address, BitsToMask(ip.Bits))
		i.IPInfo = append(i.IPInfo, ip)
		intInfo = append(intInfo, i)
	}
	return Marshal(intInfo)

}

func APCGetNTP(srs []*netdevs.SSHRequest) []byte {
	var ntp []NTP
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(APCCommands["getntp"]) {
			log.Printf("failed to retrieve the ntp config for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var n = NTP{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Active Primary NTP Server:") {
				n.NTPServers = append(n.NTPServers, strings.Fields(line)[4])
			}
			if strings.Contains(line, "Active Secondary NTP Server:") {
				n.NTPServers = append(n.NTPServers, strings.Fields(line)[4])
			}
		}
		ntp = append(ntp, n)
	}
	return Marshal(ntp)
}

func APCDevInfo(srs []*netdevs.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(APCCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var newDevInfo DevInfo
		newDevInfo.Name = sr.Hostname
		newDevInfo.ManagementIP = sr.IPAddress
		newDevInfo.Vendor = "APC"
		newDevInfo.Serial = sr.Netdev.SerialNumber
		newDevInfo.Serial2 = sr.Netdev.SerialNumberSecondary
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.HasPrefix(line, "Model Number:") {
				if newDevInfo.Platform != "" {
					continue
				}
				field := strings.Split(line, ":")[1]
				platform := strings.Trim(field, " \t")
				newDevInfo.Platform = platform
			}
			if strings.HasPrefix(line, "Version:") && newDevInfo.Version != "" {
				field := strings.Split(line, ":")[1]
				version := strings.Trim(field, " \t")
				newDevInfo.Version = version
			}
		}
		deviceInfo = append(deviceInfo, newDevInfo)
	}
	return Marshal(deviceInfo)
}

func APCGetSNMP(srs []*netdevs.SSHRequest) []byte {
	var snmp []SNMP
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(APCCommands["getsnmp"]) {
			log.Printf("failed to retrieve the ntp config for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var s = SNMP{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Active Primary NTP Server:") {
				s.Servers = append(s.Servers, strings.Fields(line)[4])
			}
		}
		snmp = append(snmp, s)
	}
	return Marshal(snmp)
}

// Not applicable
func APCArpInfo(srs []*netdevs.SSHRequest) []byte {
	var arpInfo = []ArpInfo{}
	return Marshal(arpInfo)
}

func APCIFIndex(srs []*netdevs.SSHRequest) []byte {
	var ifindex = []IFIndex{}
	return Marshal(ifindex)
}
