package funcrunner

import (
	"log"
	"strconv"
	"strings"

	"github.com/natenjoy/funcrunner/netdevs"
)

var IOSCommands = map[string][]string{
	"arpinfo": []string{"show arp"},
	"backup":  []string{"show startup-config"},
	"devinfo": []string{"show version"},
	"intinfo": []string{"show interfaces"},
	"getntp":  []string{"show ntp config"},
	"ifindex": []string{"show snmp mib ifmib ifindex"},
}

var IOSProcess = map[string]func([]*netdevs.SSHRequest) []byte{
	"arpinfo": IOSArpInfo,
	"backup":  IOSBackup,
	"devinfo": IOSDevInfo,
	"intinfo": IOSIntInfo,
	"getntp":  IOSGetNTP,
	"ifindex": IOSIFIndex,
}

func IOSIFIndex(srs []*netdevs.SSHRequest) []byte {
	var ifIndex []IFIndex
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(IOSCommands["ifindex"]) {
			log.Printf("failed to retrieve the interface indices for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var i = IFIndex{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			line1 := strings.Replace(line, "unrouted ", "", -1)
			line2 := strings.Trim(line1, " \t")
			keyVal := strings.Split(line2, ": Ifindex = ")
			key1 := keyVal[0]
			key2 := strings.Replace(key1, " ", "", -1)
			i.IFName = strings.ToLower(key2)
			i.IFIndex = ""
			if len(keyVal) > 1 {
				i.IFIndex = keyVal[1]
			}
			ifIndex = append(ifIndex, i)
		}
	}
	return Marshal(ifIndex)
}

func IOSArpInfo(srs []*netdevs.SSHRequest) []byte {
	var arpInfo []ArpInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(IOSCommands["arpinfo"]) {
			log.Printf("failed to retrieve the arp info for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var a = ArpInfo{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Internet") {
				fields := strings.Fields(line)
				a.IPAddress = fields[1]
				a.Mac = ConvertMacAddress(fields[3])
				a.Intf = fields[5]
				a.Intf = strings.ToLower(a.Intf)
				arpInfo = append(arpInfo, a)
				a = ArpInfo{Hostname: sr.Hostname}
			}
		}
	}
	return Marshal(arpInfo)
}

func IOSIntInfo(srs []*netdevs.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(IOSCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var i = IntInfo{Hostname: sr.Hostname, Driver: "veth", IPInfo: make([]IPInfo, 0)}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if string(line[0]) != " " {
				if i.Name != "" {
					intInfo = append(intInfo, i)
				}
				i = IntInfo{Hostname: sr.Hostname, Driver: "veth", IPInfo: make([]IPInfo, 0)}
				i.Name = strings.Fields(line)[0]
				i.Name = strings.ToLower(i.Name)
				continue
			}
			if strings.Contains(line, "Description:") {
				i.Description = strings.Split(line, "Description: ")[1]
				continue
			}
			if strings.Contains(line, "Hardware is") && strings.Contains(line, "address is") {
				s := strings.Split(line, "address is ")
				m := strings.Fields(s[1])[0]
				i.Mac = ConvertMacAddress(m)
				continue
			}
			if strings.Contains(line, "BW ") {
				if strings.Contains(i.Name, "port-channel") {
					i.Driver = "lag"
					continue
				}
				if strings.Contains(i.Name, "vlan") {
					i.Driver = "veth"
					continue
				}
				bwStr := strings.Split(line, " BW ")[1]
				i.Driver = strings.Split(bwStr, ",")[0]
				continue
			}
			if strings.Contains(line, "Internet address is") || strings.Contains(line, "Secondary address") {
				ipstr := strings.Fields(line)[3]
				var ip = IPInfo{Arp: make(map[string]string, 0)}
				ip.Address = strings.Split(ipstr, "/")[0]
				ipBitStr := strings.Split(ipstr, "/")[1]
				ip.Bits, _ = strconv.Atoi(ipBitStr)
				ip.Network = GetSubnet(ip.Address, BitsToMask(ip.Bits))
				i.IPInfo = append(i.IPInfo, ip)
				continue
			}
		}
	}
	return Marshal(intInfo)
}

func IOSBackup(srs []*netdevs.SSHRequest) []byte {
	var backup []Backup
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(IOSCommands["backup"]) {
			log.Printf("failed to retrieve the backup for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		data := StripFirstLines(sr.Responses[0], 5) //First 5 lines are unnecessary and have variable data
		backup = append(backup, Backup{
			Hostname:   sr.Hostname,
			DeviceType: sr.Netdev.OperatingSystem,
			Data:       data,
			Hash:       GetHash(data)})
	}
	return Marshal(backup)
}

func IOSDevInfo(srs []*netdevs.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(IOSCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var newDevInfo DevInfo
		newDevInfo.Name = sr.Hostname
		newDevInfo.ManagementIP = sr.IPAddress
		newDevInfo.Vendor = "Cisco"
		newDevInfo.Serial = sr.Netdev.SerialNumber
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.HasPrefix(line, "Model number") {
				field := strings.Split(line, ":")[1]
				platform := strings.Trim(field, " \t")
				newDevInfo.Platform = platform
			}
			if strings.HasPrefix(line, "Cisco IOS Software") {
				field1 := strings.Split(line, "Version")[1]
				field2 := strings.Split(field1, ",")[0]
				version := strings.Trim(field2, " \t")
				newDevInfo.Version = version
			}
		}
		deviceInfo = append(deviceInfo, newDevInfo)
	}
	return Marshal(deviceInfo)
}

func IOSGetNTP(srs []*netdevs.SSHRequest) []byte {
	var ntp []NTP
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(IOSCommands["getntp"]) {
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
