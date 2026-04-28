package funcrunner

import (
	_ "fmt"
	"log"
	"strconv"
	"strings"

	"github.com/natenjoy/funcrunner/scraper"
)

var EOSCommands = map[string][]string{
	"arpinfo": []string{"show arp vrf all"},
	"backup":  []string{"show startup-config"},
	"devinfo": []string{"show version"},
	"intinfo": []string{"show interfaces","show inventory | grep -E 'Arista.Networks| FS '", "show interfaces transceiver properties | grep -E '^Name|^Media'"},
	"getntp":  []string{"show running | grep ntp.server"},
	"ifindex": []string{"show snmp mib ifmib ifindex"},
}

var EOSProcess = map[string]func([]*scraper.SSHRequest) []byte{
	"arpinfo": EOSArpInfo,
	"backup":  EOSBackup,
	"devinfo": EOSDevInfo,
	"intinfo": EOSIntInfo,
	"getntp":  EOSGetNTP,
	"ifindex": EOSIFIndex,
}

func GetOpticsMap(inv, tcvr string) map[string]Optic {
	invMap := map[string][]string{}
	for _, line := range strings.Split(inv, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		l := len(fields)
		intf := fields[0]
		manufacturer := fields[1]
		model := fields[l-3]
		serial := fields[l-2]
		invMap[intf] = []string{model, serial, manufacturer}
	}
	opsMap := map[string]Optic{}
	lines := strings.Split(tcvr, "\n")
	for index, line := range lines {
		if !strings.Contains(line, "Media") {
			continue
		}
		intFields := strings.Fields(lines[index-1])
		intf := intFields[len(intFields)-1]
		if !strings.HasPrefix(intf, "Et") {
			continue
		}
		intf = string(intf[2:]) //Strips the 'Et'
		// if / in string, remove last element and create string
		if strings.Contains(intf, "/") {
			intfSplit := strings.Split(intf, "/")
			l := len(intfSplit)
			intf = strings.Join(intfSplit[:l-1], "/")
		}

		media := strings.Fields(line)[2]
		val, ok := invMap[intf]
		if !ok {
			continue
		}
		optic := Optic{
			Manufacturer: val[2],
			SerialNumber: val[1],
			ModelType: val[0],
			MediaType: media}
		opsMap["ethernet" + intf] = optic
	}
	return opsMap
}

func EOSIFIndex(srs []*scraper.SSHRequest) []byte {
	var ifIndex []IFIndex
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(EOSCommands["ifindex"]) {
			log.Printf("failed to retrieve the interface indices for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var i = IFIndex{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, ": Ifindex = ") {
				sp := strings.Split(line, ": Ifindex = ")
				i.IFName = strings.ToLower(sp[0])
				i.IFIndex = sp[1]
				ifIndex = append(ifIndex, i)
			}
		}
	}
	return Marshal(ifIndex)
}

func EOSArpInfo(srs []*scraper.SSHRequest) []byte {
	var arpInfo []ArpInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(EOSCommands["arpinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var a = ArpInfo{Hostname: sr.Hostname}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			replace1 := strings.Replace(line, "not learned", "", 1)
			fields := strings.Fields(replace1)
			if len(fields) > 5 || len(fields) < 4 {
				continue
			}
			a.IPAddress = fields[0]
			a.Mac = ConvertMacAddress(fields[2])
			a.Intf = strings.Trim(fields[3], ",")
			a.Intf = strings.ToLower(a.Intf)
			arpInfo = append(arpInfo, a)
			if len(fields) == 5 {
				a.Intf = strings.Trim(fields[4], ",")
				a.Intf = strings.ToLower(a.Intf)
				arpInfo = append(arpInfo, a)
			}
			a = ArpInfo{Hostname: sr.Hostname}
		}
	}
	return Marshal(arpInfo)
}

func EOSIntInfo(srs []*scraper.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(EOSCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		opticsMap := GetOpticsMap(sr.Responses[1], sr.Responses[2])
		var i = IntInfo{Hostname: sr.Hostname, Driver: "veth", IPInfo: make([]IPInfo, 0)}
		// Added \nend to response to ensure last interface appends
		for _, line := range strings.Split(sr.Responses[0] + "\nend", "\n") {
			if len(line) == 0 {
				continue
			}
			if line[0:1] != " " { // Check to see if the line starts with space
				if i.Hostname != "" && i.Name != "" {
					intInfo = append(intInfo, i)
				}
				i = IntInfo{Hostname: sr.Hostname, Driver: "veth", IPInfo: make([]IPInfo, 0)} // reset struct to defaults
				i.Name = strings.Fields(line)[0]
				i.Name = strings.ToLower(i.Name)
			
				if strings.Contains(i.Name, ".") {
					continue
				}
				intf := i.Name
				if strings.Contains(intf, "/") {
					intfSplit := strings.Split(intf, "/")
					intf = strings.Join(intfSplit[:len(intfSplit)-1], "/")
				}

				val, ok := opticsMap[intf]
				if ok {
					i.Optic = val
					delete(opticsMap, intf)
				}
				continue
			}
			if strings.Contains(line, "Hardware is") && strings.Contains(line, "address is") {
				macStr := strings.Fields(line)[5]
				i.Mac = ConvertMacAddress(macStr)
				continue
			}
			if strings.Contains(line, "BW") {
				if strings.Contains(i.Name, "port-channel") {
					i.Driver = "lag"
					continue
				}
				if strings.Contains(i.Name, "vlan") {
					i.Driver = "veth"
					continue
				}
				s := strings.Split(line, "BW ")[1]
				f := strings.Fields(s)[0]
				i.Driver = string(f[:len(f)-3]) + "mbps" // Takes last 3 0's off since rate is kbits
				continue
			}
			if strings.Contains(line, "Description: ") {
				i.Description = strings.Split(line, "Description: ")[1]
				continue
			}
			if strings.Contains(line, "Member of ") {
				i.Parent = strings.Split(line, "Member of ")[1]
				i.Parent = strings.Replace(i.Parent, " ", "", -1)
				i.Parent = strings.ToLower(i.Parent)
				continue
			}
			if strings.Contains(line, "Secondary address is") || strings.Contains(line, "Internet address is") {
				var ip = IPInfo{Arp: make(map[string]string, 0)}
				ipStr := strings.Fields(line)[3]
				ipArr := strings.Split(ipStr, "/")
				ip.Address = ipArr[0]
				ip.Bits, _ = strconv.Atoi(ipArr[1])
				ip.Network = GetSubnet(ip.Address, BitsToMask(ip.Bits))
				i.IPInfo = append(i.IPInfo, ip)
				continue
			}
		}
	}
	return Marshal(intInfo)
}

func EOSBackup(srs []*scraper.SSHRequest) []byte {
	var backup []Backup
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(EOSCommands["backup"]) {
			log.Printf("failed to retrieve the backup for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		data := StripFirstLines(sr.Responses[0], 2) //First 2 lines are unnecessary and have variable data
		backup = append(backup, Backup{
			Hostname:   sr.Hostname,
			DeviceType: sr.Netdev.OperatingSystem,
			Data:       data,
			Hash:       GetHash(data)})
	}
	return Marshal(backup)
}

func EOSDevInfo(srs []*scraper.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(EOSCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var newDevInfo DevInfo
		newDevInfo.Name = sr.Hostname
		newDevInfo.ManagementIP = sr.IPAddress
		newDevInfo.Vendor = "Arista"
		newDevInfo.Serial = sr.Netdev.SerialNumber
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.HasPrefix(line, "Arista") {
				field := strings.Split(line, " ")[1]
				platform := strings.Trim(field, " \t")
				newDevInfo.Platform = platform
			}
			if strings.HasPrefix(line, "Software image version:") {
				field := strings.Split(line, "Software image version:")[1]
				version := strings.Trim(field, " \t")
				newDevInfo.Version = version
			}
		}
		deviceInfo = append(deviceInfo, newDevInfo)
	}
	return Marshal(deviceInfo)
}

func EOSGetNTP(srs []*scraper.SSHRequest) []byte {
	var ntp []NTP
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(EOSCommands["getntp"]) {
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
