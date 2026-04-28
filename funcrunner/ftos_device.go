package funcrunner

import (
	_ "fmt"
	"log"
	"strconv"
	"strings"

	"github.com/natenjoy/funcrunner/scraper"
)

var FTOSCommands = map[string][]string{
	"arpinfo": []string{
		"show arp",
		"show arp vrf manta",
		"show arp vrf ceres_net",
		"show arp vrf region_public",
		"show arp vrf region_neptune"},
	"backup":  []string{"show startup-config"},
	"devinfo": []string{"show inventory"},
	"intinfo": []string{"show interfaces"},
	"getntp":  []string{"show running | grep ntp.server"},
	"ifindex": []string{"show interfaces"},
}

var FTOSProcess = map[string]func([]*scraper.SSHRequest) []byte{
	"arpinfo": FTOSArpInfo,
	"backup":  FTOSBackup,
	"devinfo": FTOSDevInfo,
	"intinfo": FTOSIntInfo,
	"ifindex": FTOSIFIndex,
	"getntp":  FTOSGetNTP,
}

func FTOSIFIndex(srs []*scraper.SSHRequest) []byte {
	var ifIndex []IFIndex
	for _, sr := range srs {
                if sr.Error != nil || len(sr.Responses) != len(FTOSCommands["ifindex"]) {
                        log.Printf("failed to retrieve the interface indices for %s: %s", sr.Hostname, sr.Error)
                        continue
                }
                for _, block := range strings.Split(sr.Responses[0], "\n\n\n") {
			var i = IFIndex{Hostname: sr.Hostname}
                        for idx, line := range strings.Split(block, "\n") {
                                if idx == 0 {
                                        i.IFName = strings.Join(strings.Fields(line)[:2], "")
                                        i.IFName = strings.ToLower(i.IFName)
                                        continue
                                }
				if strings.Contains(line, "Interface index is ") {
					i.IFIndex = strings.Fields(line)[3]
					break
				}
			}
			if i.IFIndex != "" {
				ifIndex = append(ifIndex, i)
			}
		}
	}
	return Marshal(ifIndex)
}

func FTOSArpInfo(srs []*scraper.SSHRequest) []byte {
	var arpInfo []ArpInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(FTOSCommands["arpinfo"]) {
			log.Printf("failed to retrieve the arp info for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		for _, response := range sr.Responses {
			if strings.Contains(response, "% Error") {
				continue
			}
			var a = ArpInfo{Hostname: sr.Hostname}
			for _, line := range strings.Split(response, "\n") {
				if strings.HasPrefix(line, "Internet") {
					replace1 := strings.Replace(line, "Po ", "Port-channel", 1)
					replace2 := strings.Replace(replace1, "Ma ", "ManagementEthernet", 1)
					replace3 := strings.Replace(replace2, "Te ", "TenGigabitEthernet", 1)
					replace4 := strings.Replace(replace3, "Hu ", "hundredGigE", 1)
					replace5 := strings.Replace(replace4, "Fo ", "fortyGigE", 1)
					line1 := strings.Replace(replace5, "Vl ", "Vlan", 1)
					fields := strings.Fields(line1)
					a.IPAddress = fields[1]
					a.Mac = ConvertMacAddress(fields[3])
					var intf1, intf2 string
					intf1 = fields[4]
					intf2 = fields[5]
					if intf1 != "-" {
						a.Intf = intf1
						a.Intf = strings.ToLower(a.Intf)
						arpInfo = append(arpInfo, a)
					}
					if intf2 != "-" {
						a.Intf = intf2
						a.Intf = strings.ToLower(a.Intf)
						arpInfo = append(arpInfo, a)
					}
					a = ArpInfo{Hostname: sr.Hostname}
				}
			}
		}
	}
	return Marshal(arpInfo)
}

func FTOSIntInfo(srs []*scraper.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(FTOSCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		for _, block := range strings.Split(sr.Responses[0], "\n\n\n") {
			var i = IntInfo{Hostname: sr.Hostname, Driver: "veth", IPInfo: make([]IPInfo, 0)}
			for idx, line := range strings.Split(block, "\n") {
				if idx == 0 {
					i.Name = strings.Join(strings.Fields(line)[:2], "")
					i.Name = strings.ToLower(i.Name)
					continue
				}
				if strings.Contains(line, "Description:") {
					i.Description = strings.Split(line, "Description: ")[1]
					continue
				}
				if strings.Contains(line, "Current address is ") {
					i.Mac = strings.Split(line, "Current address is ")[1]
					continue
				}
				if strings.Contains(line, "LineSpeed") {
					if strings.Contains(i.Name, "port-channel") {
						i.Driver = "lag"
						continue
					}
					if strings.Contains(i.Name, "vlan") {
                                                i.Driver = "veth"
                                                continue
                                        }
					i.Driver = strings.Fields(line)[1]
					i.Driver = strings.Trim(i.Driver, " ,")
					if i.Driver != "auto" {
						i.Driver += "mbps"
					}
					continue
				}
				if strings.Contains(line, "Internet address is") || strings.Contains(line, "Secondary address is") {
					ipStr := strings.Fields(line)[3]
					if ipStr == "not" {
						continue
					}
					var ip = IPInfo{Arp: make(map[string]string, 0)}
					ipArr := strings.Split(ipStr, "/")
					ip.Address = ipArr[0]
					ip.Bits, _ = strconv.Atoi(ipArr[1])
					ip.Network = GetSubnet(ip.Address, BitsToMask(ip.Bits))
					i.IPInfo = append(i.IPInfo, ip)
					continue
				}
				if strings.Contains(line, "Port is part of ") {
					i.Parent = strings.Split(line, "Port is part of ")[1]
					i.Parent = strings.Replace(i.Parent, " ", "", -1)
					i.Parent = strings.ToLower(i.Parent)
				}
			}
			if i.Driver == "auto" {
				if strings.Contains(i.Name, "TenGig") {
					i.Driver = "10000mbps"
				} else if strings.Contains(i.Name, "forty") {
					i.Driver = "40000mbps"
				} else if strings.Contains(i.Name, "Management") {
					i.Driver = "1000mbps"
				}
			}
			if strings.Contains(i.Name, "channel") {
				i.Driver = "lag"
			}
			if i.Name != "" {
				intInfo = append(intInfo, i)
			}
		}

	}
	return Marshal(intInfo)
}

func FTOSBackup(srs []*scraper.SSHRequest) []byte {
	var backup []Backup
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(FTOSCommands["backup"]) {
			log.Printf("failed to retrieve the backup for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		data := StripFirstLines(sr.Responses[0], 3) //First 3 lines are unnecessary and have variable data
		backup = append(backup, Backup{
			Hostname:   sr.Hostname,
			DeviceType: sr.Netdev.OperatingSystem,
			Data:       data,
			Hash:       GetHash(data)})
	}
	return Marshal(backup)
}

func FTOSDevInfo(srs []*scraper.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(FTOSCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var newDevInfo DevInfo
		newDevInfo.Name = sr.Hostname
		newDevInfo.ManagementIP = sr.IPAddress
		newDevInfo.Vendor = "Dell"
		newDevInfo.Serial = sr.Netdev.SerialNumber
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.HasPrefix(line, "System Type") {
				field := strings.Split(line, ":")[1]
				platform := strings.Trim(field, " \t")
				newDevInfo.Platform = platform
			}
			if strings.HasPrefix(line, "Software Version") {
				field := strings.Split(line, ":")[1]
				version := strings.Trim(field, " \t")
				newDevInfo.Version = version
			}
		}
		deviceInfo = append(deviceInfo, newDevInfo)
	}
	return Marshal(deviceInfo)
}

func FTOSGetNTP(srs []*scraper.SSHRequest) []byte {
	var ntp []NTP
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(FTOSCommands["getntp"]) {
			log.Printf("failed to retrieve the ntp config for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var n = NTP{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "ntp server") {
				n.NTPServers = append(n.NTPServers, strings.Fields(line)[2])
			}
		}
		ntp = append(ntp, n)
	}
	return Marshal(ntp)
}
