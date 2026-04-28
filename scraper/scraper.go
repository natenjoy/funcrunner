package scraper

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"sync"

	"github.com/natenjoy/runcrunner/netauth"
	"github.com/natenjoy/runcrunner/netdevs"
	"github.com/scrapli/scrapligo/driver/generic"
	"github.com/scrapli/scrapligo/driver/options"
)

func NewSSHRequest(nd netdevs.Netdev) *SSHRequest {
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
	Netdev	  netdevs.Netdev
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
func BulkSSHRequest(nds netdevs.Netdevs, commands []string) []*SSHRequest {
	// if len(nds) == 0, nothing to do here
	if len(nds) == 0 {
		log.Printf("Netdevs slice is empty\n")
		return []*SSHRequest{}
	}

	// netdevs with "NOACCESS" as a serial number are not accessible
	var nds1 netdevs.Netdevs
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
