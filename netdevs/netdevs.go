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
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v2"
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
	return
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

func (nds Netdevs) Compare(onds Netdevs) {
	return
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
	bs, err := ioutil.ReadFile(filename)
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

	err = ioutil.WriteFile(filename, bs, 0666)
	if err != nil {
		return fmt.Errorf("failure writing file: %s", err)
	}

	return nil
}

func NetdevsFromYamlFile(filename string) (Netdevs, error) {
	data, err := ioutil.ReadFile(filename)
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

	err = ioutil.WriteFile(filename, bs, 0666)
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
