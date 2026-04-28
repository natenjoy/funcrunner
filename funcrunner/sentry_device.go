package funcrunner

import (
	_ "fmt"
	"log"
	"strings"

	"github.com/natenjoy/funcrunner/scraper"
)

var SENTRYCommands = map[string][]string{
	"arpinfo": []string{"exit"},
	"getntp":  []string{"show sntp"},
	"devinfo": []string{"show system", "show units"},
	"intinfo": []string{"show network"},
	"ifindex": []string{"exit"},
}

var SENTRYProcess = map[string]func([]*scraper.SSHRequest) []byte{
	"arpinfo": SENTRYArpInfo,
	"getntp":  SENTRYGetNTP,
	"devinfo": SENTRYDevInfo,
	"intinfo": SENTRYIntInfo,
	"ifindex": SENTRYIFIndex,
}

func SENTRYIntInfo(srs []*scraper.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(SENTRYCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var i = IntInfo{Hostname: sr.Hostname, Name: "mgmt", Driver: "100mbps", IPInfo: make([]IPInfo, 0)}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "IPv4 Address:") && len(i.IPInfo) == 0 {
				var ip = IPInfo{Arp: make(map[string]string, 0)}
				fields := strings.Fields(line)
				ip.Address = fields[2]
				ip.Bits = CountBits(fields[5])
				ip.Network = GetSubnet(ip.Address, fields[5])
				i.IPInfo = append(i.IPInfo, ip)
			}
			if strings.Contains(line, "Ethernet MAC:") {
				mac := strings.Fields(line)[2]
				i.Mac = ConvertMacAddress(mac)
			}
		}
		intInfo = append(intInfo, i)
	}
	return Marshal(intInfo)
}

func SENTRYGetNTP(srs []*scraper.SSHRequest) []byte {
	var ntp []NTP
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(SENTRYCommands["getntp"]) {
			log.Printf("failed to retrieve the ntp config for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var n = NTP{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Host:") {
				n.NTPServers = append(n.NTPServers, strings.Fields(line)[2])
			}
		}
		ntp = append(ntp, n)
	}
	return Marshal(ntp)
}

func SENTRYDevInfo(srs []*scraper.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(SENTRYCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var newDevInfo DevInfo
		newDevInfo.Name = sr.Hostname
		newDevInfo.ManagementIP = sr.IPAddress
		newDevInfo.Vendor = "Sentry"
		newDevInfo.Serial = sr.Netdev.SerialNumber
		newDevInfo.Serial2 = sr.Netdev.SerialNumberSecondary
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Firmware") {
				field := strings.Fields(line)[5]
				version := strings.Trim(field, " \t")
				newDevInfo.Version = version
			}
		}
		for _, line := range strings.Split(sr.Responses[1], "\n") {
			if strings.Contains(line, "Model Number:") {
				field := strings.Fields(line)[2]
				platform := strings.Trim(field, " \t")
				newDevInfo.Platform = platform
			}
		}
		deviceInfo = append(deviceInfo, newDevInfo)
	}
	return Marshal(deviceInfo)
}

// Not applicable
func SENTRYArpInfo(srs []*scraper.SSHRequest) []byte {
	var arpInfo = []ArpInfo{}
	return Marshal(arpInfo)
}

func SENTRYIFIndex(srs []*scraper.SSHRequest) []byte {
        var ifindex = []IFIndex{}
        return Marshal(ifindex)
}
