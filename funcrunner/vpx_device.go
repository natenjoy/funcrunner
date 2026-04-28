package funcrunner

import (
	"log"
	"strings"

	"github.com/natenjoy/funcrunner/netdevs"
)

var BackupDirectory = "/opt/local/netdevops/backups"

var VPXCommands = map[string][]string{
	"arpinfo": []string{"exit"},
	"backup":  []string{"show ns runningConfig", "shell cat /nsconfig/ZebOS.conf"},
	"devinfo": []string{"show ns hardware", "show ns version", "shell grep avail.memory /var/nslog/dmesg.boot", "shell grep CPUs /var/nslog/dmesg.boot"},
	"intinfo": []string{"show ns ip"},
	"ifindex": []string{"exit"},
}

var VPXProcess = map[string]func([]*netdevs.SSHRequest) []byte{
	"arpinfo": VPXArpInfo,
	"backup":  VPXBackup,
	"devinfo": VPXDevInfo,
	"intinfo": VPXIntInfo,
	"ifindex": VPXIFIndex,
}

func VPXIntInfo(srs []*netdevs.SSHRequest) []byte {
	var intInfo []IntInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(VPXCommands["intinfo"]) {
			log.Printf("failed to retrieve the interface statistics for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		var i = IntInfo{Hostname: sr.Hostname, IPInfo: make([]IPInfo, 0)}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Enabled") {
				fields := strings.Fields(line)
				var ip = IPInfo{Arp: make(map[string]string, 0)}
				ip.Address = fields[1]
				ip.Bits = 25
				ip.Network = GetSubnet(ip.Address, "255.255.255.128")
				i.Driver = fields[3]
				i.Description = fields[3]
				i.Name = strings.Trim(fields[0], ")")
				i.IPInfo = append(i.IPInfo, ip)
				intInfo = append(intInfo, i)
				i = IntInfo{Hostname: sr.Hostname}
			}
		}
	}
	return Marshal(intInfo)
}

func VPXBackup(srs []*netdevs.SSHRequest) []byte {
	var backup []Backup
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(VPXCommands["backup"]) {
			log.Printf("failed to retrieve the backup for %s: %s", sr.Hostname, sr.Error)
			continue
		}
		stripped := StripFirstLines(sr.Responses[0], 2)           //First 2 lines are unnecessary and have variable data
		data := StripLineMatches(stripped, []string{"encrypted"}) // encrypted line codes change every call
		data += "\n\n--ZebOS.conf--" + sr.Responses[1]
		backup = append(backup, Backup{
			Hostname:   sr.Hostname,
			DeviceType: sr.Netdev.OperatingSystem,
			Data:       data,
			Hash:       GetHash(data)})
	}
	return Marshal(backup)
}

func VPXDevInfo(srs []*netdevs.SSHRequest) []byte {
	var deviceInfo []DevInfo
	for _, sr := range srs {
		if sr.Error != nil || len(sr.Responses) != len(VPXCommands["devinfo"]) {
			log.Printf("Error collecting device info for %s: %s\n", sr.Hostname, sr.Error)
			continue
		}
		var d = DevInfo{
			Name:         sr.Hostname,
			ManagementIP: sr.IPAddress,
			Vendor:       "Citrix",
			Serial:       sr.Netdev.SerialNumber,
			Parent:       sr.Netdev.Parent}
		for _, line := range strings.Split(sr.Responses[0], "\n") {
			if strings.Contains(line, "Platform:") {
				field := strings.Split(line, "Platform:")[1]
				platform := strings.Trim(field, " \t")
				d.Platform = platform
			}
			if strings.Contains(line, "Netscaler UUID:") {
				d.UUID = strings.Fields(line)[2]
			}
		}
		for _, line := range strings.Split(sr.Responses[1], "\n") {
			if strings.Contains(line, "NetScaler") {
				field := strings.Split(line, ",")[0]
				version := strings.Trim(field, " \t")
				d.Version = version
			}
		}

		//Get ram and cpu
		ram := strings.Fields(strings.Split(sr.Responses[2], "\n")[0])
		d.RAM = strings.Trim(ram[len(ram)-2], "(") + "MB"
		cpu := strings.Fields(strings.Split(sr.Responses[3], "\n")[0])
		d.CPU = cpu[len(cpu)-2]

		deviceInfo = append(deviceInfo, d)
	}
	return Marshal(deviceInfo)
}

// Not applicable
func VPXArpInfo(srs []*netdevs.SSHRequest) []byte {
	var arpInfo = []ArpInfo{}
	return Marshal(arpInfo)
}

func VPXIFIndex(srs []*netdevs.SSHRequest) []byte {
	var ifindex = []IFIndex{}
	return Marshal(ifindex)
}
