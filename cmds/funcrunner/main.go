package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/natenjoy/funcrunner/funcrunner"
	"github.com/natenjoy/funcrunner/netdevs"
	"github.com/redis/go-redis/v9"
)

func unmarshal(bs []byte, stype string) any {
	switch stype {
	case "devinfo":
		var dev []funcrunner.DevInfo
		err := json.Unmarshal(bs, &dev)
		if err != nil {
			log.Fatalf("failure to unmarshal into %s: %s\n", stype, err)
		}
		return dev
	case "arpinfo":
		var arp []funcrunner.ArpInfo
		err := json.Unmarshal(bs, &arp)
		if err != nil {
			log.Fatalf("failure to unmarshal into %s: %s\n", stype, err)
		}
		return arp
	case "intinfo":
		var intf []funcrunner.IntInfo
		err := json.Unmarshal(bs, &intf)
		if err != nil {
			log.Fatalf("failure to unmarshal into %s: %s\n", stype, err)
		}
		return intf
	case "ifindex":
		var indices []funcrunner.IFIndex
		err := json.Unmarshal(bs, &indices)
		if err != nil {
			log.Fatalf("failure to unmarshal into %s: %s\n", stype, err)
		}
		return indices
	case "backup":
		var backup []funcrunner.Backup
		err := json.Unmarshal(bs, &backup)
		if err != nil {
			log.Fatalf("failure to unmarshal into %s: %s\n", stype, err)
		}
		return backup
	case "inventory":
		var inventory map[string]Inventory
		err := json.Unmarshal(bs, &inventory)
		if err != nil {
			log.Fatalf("failure to unmarshal into %s: %s\n", stype, err)
		}
		return inventory
	default:
		log.Fatalf("%s is not a valid device method\n", stype)
	}
	return nil
}

type Inventory struct {
	DevInfo funcrunner.DevInfo            `json:"devinfo"`
	IntInfo map[string]funcrunner.IntInfo `json:"intinfo"`
}

func getInventoryJson(devs []funcrunner.DevInfo, intfs []funcrunner.IntInfo, arps []funcrunner.ArpInfo, indices []funcrunner.IFIndex) map[string]Inventory {
	m := map[string]Inventory{}
	for _, dev := range devs {
		ii := map[string]funcrunner.IntInfo{}
		m[dev.Name] = Inventory{DevInfo: dev, IntInfo: ii}
		if dev.Name2 != "" {
			m[dev.Name2] = Inventory{DevInfo: dev, IntInfo: ii}
		}
	}
	for _, intf := range intfs {
		if _, ok := m[intf.Hostname]; ok {
			m[intf.Hostname].IntInfo[intf.Name] = intf
		}
	}
	for _, arp := range arps {
		if _, ok := m[arp.Hostname]; !ok {
			continue
		}
		if _, ok := m[arp.Hostname].IntInfo[arp.Intf]; !ok {
			continue
		}
		intf := m[arp.Hostname].IntInfo[arp.Intf]
		for _, ip := range intf.IPInfo {
			if funcrunner.IPInNetwork(arp.IPAddress, ip.Network, ip.Bits) {
				ip.Arp[arp.IPAddress] = arp.Mac
				continue
			}
		}
	}
	for _, index := range indices {
		if _, ok := m[index.Hostname]; !ok {
			continue
		}
		if _, ok := m[index.Hostname].IntInfo[index.IFName]; !ok {
			continue
		}
		ii := m[index.Hostname].IntInfo[index.IFName] //.SNMPIndex = index.IFIndex
		ii.SNMPIndex = index.IFIndex
		m[index.Hostname].IntInfo[index.IFName] = ii
	}
	return m
}

func getInventory(nds netdevs.Netdevs) map[string]Inventory {
	// Get the raw data from funcrunner
	dev, err := funcrunner.FuncRun(nds, "devinfo")
	if err != nil {
		log.Fatalf("FuncRun error: %s\n", err)
	}

	intf, err := funcrunner.FuncRun(nds, "intinfo")
	if err != nil {
		log.Fatalf("FuncRun error: %s\n", err)
	}

	arp, err := funcrunner.FuncRun(nds, "arpinfo")
	if err != nil {
		log.Fatalf("FuncRun error: %s\n", err)
	}

	index, err := funcrunner.FuncRun(nds, "ifindex")
	if err != nil {
		log.Fatalf("FuncRun error: %s\n", err)
	}

	// Unmarshal the data
	arps := unmarshal(arp, "arpinfo")
	devs := unmarshal(dev, "devinfo")
	intfs := unmarshal(intf, "intinfo")
	indices := unmarshal(index, "ifindex")

	// Assert the data
	d, ok := devs.([]funcrunner.DevInfo)
	if !ok {
		log.Fatalf("DevInfo failed assertion\n")
	}
	i, ok := intfs.([]funcrunner.IntInfo)
	if !ok {
		log.Fatalf("IntInfo failed assertion\n")
	}
	a, ok := arps.([]funcrunner.ArpInfo)
	if !ok {
		log.Fatalf("ArpInfo failed assertion\n")
	}
	idx, ok := indices.([]funcrunner.IFIndex)
	if !ok {
		log.Fatalf("IFIndex failed assertion\n")
	}

	inv := getInventoryJson(d, i, a, idx)
	return inv
}

func getIFIndex(nds netdevs.Netdevs) []byte {
	indices, err := funcrunner.FuncRun(nds, "ifindex")
	if err != nil {
		log.Fatalf("FuncRun error: %s\n", err)
	}

	ifIndices := unmarshal(indices, "ifindex")
	_, ok := ifIndices.([]funcrunner.IFIndex)
	if !ok {
		log.Fatalf("ArpInfo failed assertion\n")
	}
	return indices
}

func getAllInventory() map[string]Inventory {
	m := map[string]Inventory{}

	for _, reg := range []string{"ams", "icn"} {
		for _, az := range []string{"1", "2", "3"} {
			loc := reg + az
			log.Printf("Collecting EOS Inventory for %s\n", loc)
			eosNDS := getNetDevs([]string{loc}, []string{}, "eos")
			eosInv := getInventory(eosNDS)
			maps.Copy(m, eosInv)
		}
	}

	return m
}

func getHash(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	bs := hash.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func updateBackup(b funcrunner.Backup) {
	fname := ""
	if b.DeviceType == "vpx" {
		fname = backupDirectory + "vpxs/" + b.Hostname
	} else {
		fname = backupDirectory + string(b.Hostname[:4]) + "/" + b.Hostname
	}
	hash := ""
	bs, err := os.ReadFile(fname)
	if err != nil {
		log.Printf("First time backup for %s\n", fname)
	} else {
		hash = getHash(string(bs))
	}
	if hash != b.Hash {
		fmt.Printf("Configuration for %s has changed.  Overwriting backup\n", b.Hostname)
		err = os.WriteFile(fname, []byte(b.Data), os.FileMode(int(0777)))
		if err != nil {
			log.Printf("Error writing backup file: %s\n", err)
		}
	}
}

func backupAll() {
	// FTOS
	fmt.Println("Backing up all FTOS devices")
	ftosNDS := getNetDevs([]string{}, []string{}, "ftos")
	backups, err := funcrunner.FuncRun(ftosNDS, "backup")
	if err != nil {
		log.Fatalf("FuncRun Backup error: %s\n", err)
	}
	backupSlice := unmarshal(backups, "backup")
	bkups, ok := backupSlice.([]funcrunner.Backup)
	if !ok {
		log.Fatalf("Backup failed assertion\n")
	}
	for _, b := range bkups {
		updateBackup(b)
	}

	// IOS
	fmt.Println("Backing up all IOS devices")
	iosNDS := getNetDevs([]string{}, []string{}, "ios")
	backups, err = funcrunner.FuncRun(iosNDS, "backup")
	if err != nil {
		log.Fatalf("FuncRun Backup error: %s\n", err)
	}
	backupSlice = unmarshal(backups, "backup")
	bkups, ok = backupSlice.([]funcrunner.Backup)
	if !ok {
		log.Fatalf("Backup failed assertion\n")
	}
	for _, b := range bkups {
		updateBackup(b)
	}

	// JUNOS
	fmt.Println("Backing up all JUNOS devices")
	junosNDS := getNetDevs([]string{}, []string{}, "junos")
	backups, err = funcrunner.FuncRun(junosNDS, "backup")
	if err != nil {
		log.Fatalf("FuncRun Backup error: %s\n", err)
	}
	backupSlice = unmarshal(backups, "backup")
	bkups, ok = backupSlice.([]funcrunner.Backup)
	if !ok {
		log.Fatalf("Backup failed assertion\n")
	}
	for _, b := range bkups {
		updateBackup(b)
	}

	// VPXs
	fmt.Println("Backing up all VPX devices")
	vpxNDS := getNetDevs([]string{}, []string{}, "vpx")
	backups, err = funcrunner.FuncRun(vpxNDS, "backup")
	if err != nil {
		log.Fatalf("FuncRun Backup error: %s\n", err)
	}
	backupSlice = unmarshal(backups, "backup")
	bkups, ok = backupSlice.([]funcrunner.Backup)
	if !ok {
		log.Fatalf("Backup failed assertion\n")
	}
	for _, b := range bkups {
		updateBackup(b)
	}

	// EOS
	for _, reg := range []string{"ams", "iad", "icn", "sin"} {
		fmt.Printf("Backing up all EOS devices in %s\n", reg)
		eosNDS := getNetDevs([]string{reg}, []string{}, "eos")
		backups, err = funcrunner.FuncRun(eosNDS, "backup")
		if err != nil {
			log.Fatalf("FuncRun Backup error: %s\n", err)
		}
		backupSlice = unmarshal(backups, "backup")
		bkups, ok = backupSlice.([]funcrunner.Backup)
		if !ok {
			log.Fatalf("Backup failed assertion\n")
		}
		for _, b := range bkups {
			updateBackup(b)
		}
	}
}

func getNetDevs(include, exclude []string, opSys string) netdevs.Netdevs {
	allnds, err := netdevs.NetdevsFromRedis("127.0.0.1:6379")
	if err != nil {
		log.Fatalf("failure loading netdevs from file %s: %s\n", ndsCache, err)
	}
	nds := allnds.Include(include).Exclude(exclude).OS(opSys)
	return nds
}

var ndsCache = "/opt/local/netdevops/caches/netdevs.json"
var allInventory bool
var allBackup bool
var include string
var exclude string
var opersys string
var nds netdevs.Netdevs
var backupDirectory = "/data/config-backups/"

func init() {
	flag.StringVar(&include, "m", "XXXXXXX", "required: comma delimited string of desired matches: -c 'sentry,iad1' to match pdus in iad1")
	flag.StringVar(&exclude, "e", "XXXXXXX", "comma delimited string of desired exclusion term: -e 'sdx' to exclude sdxs'")
	flag.StringVar(&opersys, "o", "", "filter for operating system(eos,ios,ftos,junos,sdx,vpx,apc,sentry): -o sdx for only sdx os")
	flag.BoolVar(&allInventory, "a", false, "Collects all inventory(Takes 10 minutes)")
	flag.BoolVar(&allBackup, "b", false, "Backs up all routers, firewalls, vpxs (Takes 10 minutes)")
	flag.Parse()
	i := strings.Split(include, ",")
	e := strings.Split(exclude, ",")
	o := opersys
	nds = getNetDevs(i, e, o)
}

func timeString() string {
	t := time.Now()
	s := fmt.Sprintf("%s", t)
	s1 := strings.Split(s, ".")[0]
	s2 := strings.Replace(s1, " ", "_", -1)
	return s2
}

func saveInventoryToRedis(key string, data []byte) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer rdb.Close()

	ctx := context.Background()
	err := rdb.Set(ctx, key, data, 0).Err()
	if err != nil {
		log.Fatalf("Error backing up inventory to redis: %s\n", err)
	}
}

// func getInventoryFromRedis(key string) map[string]Inventory {
// 	rdb := redis.NewClient(&redis.Options{
// 		Addr:     "localhost:6379",
// 		Password: "", // no password set
// 		DB:       0,  // use default DB
// 	})
// 	defer rdb.Close()

// 	ctx := context.Background()
// 	val, err := rdb.Get(ctx, "inventory").Result()
// 	if err != nil {
// 		log.Fatalf("Error retrieving inventory from redis: %s\n", err)
// 	}

// 	retInterface := unmarshal([]byte(val), "inventory")
// 	ret, ok := retInterface.(map[string]Inventory)
// 	if !ok {
// 		log.Fatalf("Error unmarshalling inventory from redis\n")
// 	}
// 	return ret
// }

func main() {
	if allInventory {
		//lastInventory := GetInventoryFromRedis("inventory")
		currentInventory := getAllInventory()
		inventoryBytes := funcrunner.Marshal(currentInventory)
		saveInventoryToRedis("inventory_test", inventoryBytes)
		//saveInventoryToRedis("inventory_"+timeString(), inventoryBytes)
		//compareInventory(lastInventory, currentInventory)
	}
	if allBackup {
		fmt.Println("Backing up devices")
		backupAll()
	}
}
