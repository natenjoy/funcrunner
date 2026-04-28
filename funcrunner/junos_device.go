package funcrunner

import (
	_ "fmt"
	"log"
	"strconv"
	"strings"

	"github.com/natenjoy/funcrunner/scraper"
)

var JUNOSCommands = map[string][]string{
	"arpinfo": []string{"show arp no-resolve"},
	"backup":  []string{"show configuration | display set"},
	"devinfo": []string{
		"show version | match \"Model|Hostname|Junos:\"",
		"show chassis hardware | match Chassis"},
	"intinfo": []string{"show interfaces", "show chassis hardware"},
	"getntp":  []string{"show configuration system ntp | display set"},
	"ifindex": []string{"show interfaces"},
}

var JUNOSProcess = map[string]func([]*scraper.SSHRequest) []byte{
	"arpinfo": JUNOSArpInfo,
	"backup":  JUNOSBackup,
	"devinfo": JUNOSDevInfo,
	"intinfo": JUNOSIntInfo,
	"getntp":  JUNOSGetNTP,
	"ifindex": JUNOSIFIndex,
}

func JUNOSIFIndex(srs []*scraper.SSHRequest) []byte {
	var ifIndex []IFIndex
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(JUNOSCommands["ifindex"]) {
			log.Printf("failed to retrieve the interface indices for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		for _, block := range strings.Split(sr.Responses[0], "\n\n") {
			var i = IFIndex{Hostname: sr.Hostname}
			for _, line := range strings.Split(block, "\n") {
				if strings.Contains(line, "Physical interface:") {
					i.IFName = strings.Trim(strings.Fields(line)[2], " ,")
					i.IFName = strings.ToLower(i.IFName)
				}
				if strings.Contains(line, " SNMP ifIndex: ") {
					i.IFIndex = strings.Split(line, " SNMP ifIndex: ")[1]
					ifIndex = append(ifIndex, i)
					break
				}
				if strings.Contains(line, "Logical interface ") {
					i.IFName = strings.ToLower(strings.Fields(line)[2])
					i.IFIndex = strings.Trim(strings.Split(line, " (SNMP ifIndex ")[1], " )")
					ifIndex = append(ifIndex, i)
					break
				}
			}
		}
	}
	return Marshal(ifIndex)
}

func JUNOSArpInfo(srs []*scraper.SSHRequest) []byte {
	var arpInfo []ArpInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(JUNOSCommands["arpinfo"]) {
			log.Printf("failed to retrieve the arp info for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var a = ArpInfo{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "none") {
				fields := strings.Fields(line)
				a.IPAddress = fields[1]
				a.Mac = ConvertMacAddress(fields[0])
				a.Intf = fields[2]
				a.Intf = strings.ToLower(a.Intf)
				arpInfo = append(arpInfo, a)
				a = ArpInfo{Hostname: sr.Hostname}
			}
		}
	}
	return Marshal(arpInfo)
}

/*
func GetOpticsMap(hostnaem, chassis string) map[string]Optic {
	opticsMap := map[string]Optic{}
	fpc, pic := "0", "0"
	for _, line := range strings.Split(chassis, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[0] == "FPC" {
			fpc = fields[1]
			continue
		}
		if fields[0] == "PIC" {
			pic = fields[1]
			continue
		}
//      Xcvr 0     REV 01   740-031981   G7G2008122        SFP+-10G-LR
//      Xcvr 1              NON-JNPR     AD76J50172        SFP+-10G-LR
      		media, serial, model, manufacturer := "", "", "", "Juniper"
		if fields[0] == "Xcvr" {
			if fields[2] == "NON-JNPR" {
				media = fields[4]
				serial = fields[3]
				model = "NONJNPR"
				manufacturer = "NONJNPR"
			} else {
				media  = fields[6]
				serial = fields[5]
				model = fields[4]
			}
			prefix := "xe-"
			if strings.Contains(media, "40G") {
				prefix = "et-"
			} else if strings.Contains(media, "1G") {
				prefix = "ge-"
			}

*/




func JUNOSIntInfo(srs []*scraper.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		// opticsMap := GetOpticsMap(sr.hostname, sr.Responses[1])
		if sr.Error != nil || len(sr.Responses) != len(JUNOSCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		for _, block := range strings.Split(sr.Responses[0], "\n\n") {
			var i = IntInfo{Hostname: sr.Hostname, IPInfo: make([]IPInfo, 0)}
			var logical bool
			for _, line := range strings.Split(block, "\n") {
				if strings.Contains(line, "Physical interface:") || strings.Contains(line, "Logical interface") {
					logical = strings.Contains(line, "Logical interface")
					i.Name = strings.Trim(strings.Fields(line)[2], " ,")
					i.Name = strings.ToLower(i.Name)
					continue
				}
				if strings.Contains(line, "Description:") {
					i.Description = strings.Split(line, "Description: ")[1]
					continue
				}
				if strings.Contains(line, "Current address: ") {
					i.Mac = strings.Trim(strings.Fields(line)[2], " ,")
					continue
				}
				if strings.Contains(line, "Destination: ") {
					var ip = IPInfo{Arp: make(map[string]string, 0)}
					netStr := strings.Trim(strings.Fields(line)[1], " ,")
					if !strings.Contains(netStr, "/") {
						continue
					}
					bitStr := strings.Split(netStr, "/")[1]
					ip.Bits, _ = strconv.Atoi(bitStr)
					ip.Address = strings.Trim(strings.Fields(line)[3], " ,")
					if strings.Contains(ip.Address, ":") { // No IPv6
						continue
					}
					ip.Network = GetSubnet(ip.Address, BitsToMask(ip.Bits))
					i.IPInfo = append(i.IPInfo, ip)
					continue
				}
				if strings.Contains(line, "Speed: ") {
					speedStr := strings.Fields(strings.Split(line, "Speed: ")[1])[0]
					i.Driver = strings.Trim(speedStr, " ,")
					continue
				}
				if strings.Contains(line, " AE bundle: ") {
					i.Parent = strings.Split(strings.Fields(line)[4], ".")[0]
					i.Parent = strings.Replace(i.Parent, " ", "", -1)
					i.Parent = strings.ToLower(i.Parent)
				}
			}
			if logical {
				i.Mac = intInfo[len(intInfo)-1].Mac
				i.Driver = intInfo[len(intInfo)-1].Driver
			}
			if i.Name != "" {
				intInfo = append(intInfo, i)
			}
		}
	}
	return Marshal(intInfo)
}

func JUNOSBackup(srs []*scraper.SSHRequest) []byte {
	var backup []Backup
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(JUNOSCommands["backup"]) {
			log.Printf("failed to retrieve the backup for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		data := sr.Responses[0] // No variable lines need removal
		backup = append(backup, Backup{
			Hostname:   sr.Hostname,
			DeviceType: sr.Netdev.OperatingSystem,
			Data:       data,
			Hash:       GetHash(data)})
	}
	return Marshal(backup)
}

func JUNOSDevInfo(srs []*scraper.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(JUNOSCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var newDevInfo DevInfo
		newDevInfo.ManagementIP = sr.IPAddress
		newDevInfo.Vendor = "Juniper"
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.HasPrefix(line, "Model:") {
				field := strings.Split(line, ":")[1]
				platform := strings.Trim(field, " \t")
				newDevInfo.Platform = platform
			}
			if strings.HasPrefix(line, "Junos:") {
				field := strings.Fields(line)[1]
				version := strings.Trim(field, " \t")
				newDevInfo.Version = version
			}
			if strings.HasPrefix(line, "Hostname:") {
				field := strings.Fields(line)[1]
				hostname := strings.Trim(field, " \t")
				if newDevInfo.Name == "" {
					newDevInfo.Name = hostname
				} else {
					newDevInfo.Name2 = hostname
				}
			}
		}
		for _, line := range strings.Split(sr.Responses[1], "\n") {
			if strings.HasPrefix(line, "Chassis") {
				field := strings.Fields(line)[1]
				serial := strings.Trim(field, " \t")
				if newDevInfo.Serial == "" {
					newDevInfo.Serial = serial
				} else {
					newDevInfo.Serial2 = serial
				}
			}
		}
		deviceInfo = append(deviceInfo, newDevInfo)
	}
	return Marshal(deviceInfo)
}

func JUNOSGetNTP(srs []*scraper.SSHRequest) []byte {
	var ntp []NTP
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(JUNOSCommands["getntp"]) {
			log.Printf("failed to retrieve the ntp config for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var n = NTP{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "ntp server") {
				fields := strings.Fields(line)
				n.NTPServers = append(n.NTPServers, fields[len(fields)-1])
			}
		}
		ntp = append(ntp, n)
	}
	return Marshal(ntp)
}
