package funcrunner

import (
	"fmt"

	"github.com/natenjoy/funcrunner/netdevs"
	"github.com/natenjoy/funcrunner/scraper"
)

// Functions supported by devices
var fns = map[string]bool{
	"arpinfo": true,
	"backup":  true,
	"devinfo": true,
	"intinfo": true,
	"ifindex": true,
	"getntp":  true,
	"getsnmp": true,
}

// GetOS gets the OS of the netdevs, returns errors if there are multiple OS types
// or if the netdevs slice is empty
func GetOS(nds netdevs.Netdevs) (string, error) {
	m := map[string]bool{}
	for _, nd := range nds {
		m[nd.OperatingSystem] = true
	}
	switch len(m) {
	case 0:
		return "", fmt.Errorf("failure to process, empty set")
	case 1:
		return nds[0].OperatingSystem, nil
	default:
		return "", fmt.Errorf("failure to process, all netdevs should be same OS type: %v", m)
	}
}

// GetCommands returns the appropriate commands based on operating system and function
func GetCommands(opsys, fn string) []string {
	switch opsys {
	case "sdx":
		return SDXCommands[fn]
	case "vpx":
		return VPXCommands[fn]
	case "eos":
		return EOSCommands[fn]
	case "ftos":
		return FTOSCommands[fn]
	case "ios":
		return IOSCommands[fn]
	case "junos":
		return JUNOSCommands[fn]
	case "apc":
		return APCCommands[fn]
	case "sentry":
		return SENTRYCommands[fn]
	default:
		return []string{}
	}
}

// GetProcessor returns the function associated with the device type
func GetProcessor(opsys, fn string) (func([]*scraper.SSHRequest) []byte, error) {
	switch opsys {
	case "sdx":
		return SDXProcess[fn], nil
	case "vpx":
		return VPXProcess[fn], nil
	case "eos":
		return EOSProcess[fn], nil
	case "ftos":
		return FTOSProcess[fn], nil
	case "ios":
		return IOSProcess[fn], nil
	case "junos":
		return JUNOSProcess[fn], nil
	case "apc":
		return APCProcess[fn], nil
	case "sentry":
		return SENTRYProcess[fn], nil
	default:
		err := fmt.Errorf("%s does not support the %s function", opsys, fn)
		return nil, err
	}
}

// FuncRun processes the device/function request
func FuncRun(nds netdevs.Netdevs, fn string) ([]byte, error) {
	// Verify netdevs are supported and of a single type
	opsys, err := GetOS(nds)
	if err != nil {
		e := fmt.Errorf("netdevices are inconsistent: %s", err)
		return nil, e
	}

	// Verify function exists for the devices
	if !fns[fn] {
		err := fmt.Errorf("function %s is not a valid function", fn)
		return nil, err
	}

	// Get commands to run for netdevs
	commands := GetCommands(opsys, fn)
	if len(commands) == 0 {
		err := fmt.Errorf("invalid function '%s' for operating system '%s'", fn, opsys)
		return nil, err
	}

	// Gets the appropriate function to run for device type and task
	processor, err := GetProcessor(opsys, fn)
	if err != nil {
		return nil, err
	}

	// Runs the commands on the netdevs and gets slice of ssh requests fulfilled
	requests := scraper.BulkSSHRequest(nds, commands)

	bs := processor(requests)

	return bs, nil
}
