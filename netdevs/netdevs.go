// Package netdevs provides basic tooling for managing
// basic network devices, pdus,firewalls, console
// servers and load balancers.
// A netdev provides unique identification to a manageable
// device to aid monitoring, management, automation
package netdevs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/scrapli/scrapligo/driver/generic"
	"github.com/scrapli/scrapligo/driver/options"
	"gopkg.in/yaml.v2"

	"github.com/natenjoy/funcrunner/netauth"
)

// Netdev is the base unit for a netops managed device
type Netdev struct {
	Hostname              string    `json:"hostname" yaml:"hostname"`
	IPAddress             string    `json:"ip_address" yaml:"ip_address"`
	OperatingSystem       string    `json:"operating_system" yaml:"operating_system"`
	SerialNumber          string    `json:"serial_number" yaml:"serial_number"`
	SerialNumberSecondary string    `json:"serial_number_secondary" yaml:"serial_number_secondary"`
	SSHPort               string    `json:"ssh_port" yaml:"ssh_port"`
	Parent                string    `json:"parent,omitempty" yaml:"parent"`
	LastSeen              time.Time `json:"last_seen,omitempty" yaml:"last_seen"`
}

type Netdevs []Netdev

// SortByHost sorts the Netdev slice by hostname
func (nds Netdevs) SortByHost() {
	sort.Slice(nds, func(i, j int) bool {
		return nds[i].Hostname < nds[j].Hostname
	})
}

// Include returns Netdevs including all matches in either Operating System or Hostname
func (nds Netdevs) Include(matches []string) Netdevs {
	var matchingNDS Netdevs
	for _, nd := range nds {
		var skip bool
		for _, match := range matches {
			if !strings.Contains(nd.Hostname, match) && !strings.Contains(nd.OperatingSystem, match) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		matchingNDS = append(matchingNDS, nd)
	}

	return matchingNDS
}

// Exclude return Netdevs excluding those with matches in OperatingSystem or Hostname
func (nds Netdevs) Exclude(matches []string) Netdevs {
	var matchingNDS Netdevs
	for _, nd := range nds {
		var skip bool
		for _, match := range matches {
			if strings.Contains(nd.Hostname, match) || strings.Contains(nd.OperatingSystem, match) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		matchingNDS = append(matchingNDS, nd)
	}

	return matchingNDS
}

// Returns Netdevs of a specific OS type due to idiotic naming of vpxs
// If the match is "", just return everything
func (nds Netdevs) OS(match string) Netdevs {
	if match == "" {
		return nds
	}
	var matchingNDS Netdevs
	for _, nd := range nds {
		if match == nd.OperatingSystem {
			matchingNDS = append(matchingNDS, nd)
		}
	}
	return matchingNDS
}

// Removes duplicate host entries due to multiple IPs responding.  First host wins
func (nds Netdevs) Dedupe() Netdevs {
	var deduped Netdevs
	hosts := make(map[string]bool)
	for _, nd := range nds {
		if hosts[nd.Hostname] {
			continue
		} else {
			hosts[nd.Hostname] = true
			deduped = append(deduped, nd)
		}
	}
	return deduped
}

// HostnameFromIP returns the hostname for a netdev with ip, else ""
func (nds Netdevs) HostnameFromIP(ipaddr string) string {
	for _, nd := range nds {
		if nd.IPAddress == ipaddr {
			return nd.Hostname
		}
	}
	return ""
}

func (nds Netdevs) SelectNetdev() Netdev {
	if len(nds) == 0 {
		fmt.Println("No matching hosts")
		os.Exit(0)
	}
	if len(nds) == 1 {
		return nds[0]
	}

	for i, nd := range nds {
		fmt.Printf("[%d] %s\n", i, nd.Hostname)
	}
	fmt.Print("Select your host(q to quit): ")

	var s string
	_, err := fmt.Scanf("%s\n", &s)
	if err != nil {
		os.Exit(0)
	}
	num, err := strconv.Atoi(s)
	if err != nil || num >= len(nds) {
		os.Exit(0)
	}
	return nds[num]
}

func NetdevsToHostHash(nds Netdevs) map[string]Netdev {
	hash := make(map[string]Netdev)
	for _, nd := range nds {
		hash[nd.Hostname] = nd
	}
	return hash
}

func NetdevsFromJsonFile(filename string) (Netdevs, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failure reading from file: %s", err)
	}

	var nds Netdevs
	err = json.Unmarshal(bs, &nds)
	if err != nil {
		return nil, fmt.Errorf("failure unmarshalling data: %s", err)
	}
	nds.SortByHost()

	return nds, nil
}

func NetdevsToJsonFile(nds Netdevs, filename string) error {
	bs, err := json.Marshal(nds)
	if err != nil {
		return fmt.Errorf("failure marshalling data: %s", err)
	}

	err = os.WriteFile(filename, bs, 0666)
	if err != nil {
		return fmt.Errorf("failure writing file: %s", err)
	}

	return nil
}

func NetdevsFromYamlFile(filename string) (Netdevs, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failure opening yaml file: %s", err)
	}

	var nds Netdevs
	err = yaml.Unmarshal(data, &nds)
	if err != nil {
		return nil, fmt.Errorf("failure unmarshaling yaml: %s", err)
	}

	nds.SortByHost()

	return nds, nil
}

func NetdevsToYamlFile(nds Netdevs, filename string) error {
	bs, err := yaml.Marshal(nds)
	if err != nil {
		return fmt.Errorf("failure marshalling data: %s", err)
	}

	err = os.WriteFile(filename, bs, 0666)
	if err != nil {
		return fmt.Errorf("failure writing file: %s", err)
	}

	return nil
}

func (nds Netdevs) Dump() {
	for _, nd := range nds {
		fmt.Printf("%+v\n", nd)
	}
	return
}

func NetdevsToRedis(nds Netdevs, ipPort string) error {
	return nil
}

func NetdevsFromRedis(ipPort string) (Netdevs, error) {

	rdb := redis.NewClient(&redis.Options{
		Addr:     ipPort,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer rdb.Close()

	ctx := context.Background()
	val, err := rdb.Get(ctx, "netdevs").Result()
	if err != nil {
		log.Printf("Error retrieving netdevs from redis: %s\n", err)
		log.Printf("Attempting to retrieve netdevs from local cache\n")
		return NetdevsFromJsonFile("/opt/local/netdevops/caches/netdevs.json")
	}

	var nds Netdevs
	err = json.Unmarshal([]byte(val), &nds)
	if err != nil {
		log.Printf("Error unmarshalling inventory from redis\n")
		log.Printf("Attempting to retrieve netdevs from local cache\n")
		return NetdevsFromJsonFile("/opt/local/netdevops/caches/netdevs.json")
	}
	nds.SortByHost()

	return nds, nil
}

func NewSSHRequest(nd Netdev) *SSHRequest {
	creds := netauth.GetCredentials(nd.Hostname, nd.OperatingSystem)
	port, err := strconv.Atoi(nd.SSHPort)
	//Default to 22 if strconv fails
	if err != nil {
		port = 22
	}

	preamble := getPreamble(nd.OperatingSystem)
	prompt := getPrompt(nd.Hostname, nd.OperatingSystem)

	return &SSHRequest{
		Hostname:  nd.Hostname,
		IPAddress: nd.IPAddress,
		Port:      port,
		User:      creds.Username,
		Password:  creds.Password,
		Prompt:    prompt,
		SSHFile:   "/etc/ssh/ssh_config",
		Preamble:  preamble,
		Netdev:    nd,
	}
}

type SSHRequest struct {
	Hostname  string
	IPAddress string
	Port      int
	User      string
	Password  string
	Prompt    string
	SSHFile   string
	Commands  []string
	Responses []string
	Preamble  []string
	Timeout   int
	Error     error
	Netdev    Netdev
}

func (s *SSHRequest) Execute(commands []string) {
	re := regexp.MustCompile(s.Prompt)
	driver, err := generic.NewDriver(
		s.IPAddress,
		options.WithAuthNoStrictKey(),
		options.WithAuthUsername(s.User),
		options.WithAuthPassword(s.Password),
		options.WithTransportType("system"),
		options.WithSSHConfigFile(s.SSHFile),
		options.WithPromptPattern(re),
		options.WithPort(s.Port),
	)
	if err != nil {
		s.Error = fmt.Errorf("failed to create driver; error: %v", err)
		return
	}

	err = driver.Open()
	if err != nil {
		s.Error = fmt.Errorf("failed to open driver; error: %v", err)
		return
	}
	defer driver.Close()

	//Set terminal length, environment settings
	for _, command := range s.Preamble {
		response, err := driver.SendCommand(command)
		if err != nil {
			s.Error = fmt.Errorf("failed to send command in preamble; error: %v", err)
			return
		}
		if response.Failed != nil {
			s.Error = fmt.Errorf("response objects indicates failure in preamble: %v", response.Failed)
			return
		}
	}

	//Run user provided commands
	for _, command := range commands {
		s.Commands = append(s.Commands, command)
		response, err := driver.SendCommand(command)
		if err != nil {
			s.Error = fmt.Errorf("failed to send command; error: %v", err)
			return
		}
		if response.Failed != nil {
			s.Error = fmt.Errorf("response objects indicates failure: %v", response.Failed)
			return
		}
		s.Responses = append(s.Responses, response.Result)
	}
	return
}

// BulkSSHRequest takes netdevs and commands and returns a slice or *SSHRequest after execution
// after executing commands.  Response/Errors can be evaluated caller
// Depending on the system, you generally should try to keep the number of requests
// under 150 to avoid starving the local system of resources
func BulkSSHRequest(nds Netdevs, commands []string) []*SSHRequest {
	// if len(nds) == 0, nothing to do here
	if len(nds) == 0 {
		log.Printf("Netdevs slice is empty\n")
		return []*SSHRequest{}
	}

	// netdevs with "NOACCESS" as a serial number are not accessible
	var nds1 Netdevs
	for _, nd := range nds {
		if nd.SerialNumber != "NOACCESS" {
			nds1 = append(nds1, nd)
		} else {
			log.Printf("%s will be skipped.  Netops has no valid credentials for this host\n", nd.Hostname)
		}
	}

	// Create SSHRequest slice
	var srs []*SSHRequest
	for _, nd := range nds1 {
		srs = append(srs, NewSSHRequest(nd))
	}

	// Run concurrently
	wg := new(sync.WaitGroup)
	for i := range srs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			srs[i].Execute(commands)
		}(i)
	}
	wg.Wait()

	return srs
}

func getPrompt(hostname, os string) string {
	switch os {
	case "eos", "ftos", "ios", "junos":
		return string("\n.*"+hostname[:12]) + ".+[#>]"
	case "sdx":
		return "\n>"
	case "vpx":
		return "\njoyroot>"
	case "sentry":
		return "\nSwitched PDU:"
	case "apc":
		return "\napc>"
	case "opengear":
		return "\n\\$"
	}
	return "\n.+[#,>]"
}

func getPreamble(os string) []string {
	switch os {
	case "eos", "ios":
		return []string{"terminal length 0", "terminal width 300"}
	case "ftos":
		return []string{"terminal length 0"}
	case "junos":
		return []string{"set cli screen-length 0", "set cli screen-width 300"}
	}
	return []string{}
}
