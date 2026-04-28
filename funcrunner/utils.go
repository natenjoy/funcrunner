package funcrunner

import (
	"crypto/sha256"
	"fmt"
	"log"
	"strconv"
	"strings"
)

func StripFirstLines(s string, num int) string {
	lines := strings.Split(s, "\n")
	if len(lines) < num {
		return s
	}
	return strings.Join(lines[num:], "\n")
}

func GetHash(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	bs := hash.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func StripLineMatches(s string, matches []string) string {
	lines := strings.Split(s, "\n")
	var clean []string
	for _, line := range lines {
		add := true
		for _, match := range matches {
			if strings.Contains(line, match) {
				add = false
			}
		}
		if add {
			clean = append(clean, line)
		}
	}
	return strings.Join(clean, "\n")
}

// Converts ip string to integer: e.g. "10.64.241.123" => 172028283
func IPToInt(ip string) int {
	var ipInt int
	for _, b := range strings.Split(ip, ".") {
		ipInt *= 256
		n, err := strconv.Atoi(b)
		if err != nil {
			log.Printf("failure to convert ip address (%s) to int: %s\n", ip, err)
			return 0
		}
		ipInt += n
	}
	return ipInt
}

// Converts integer to ip string: e.g. 172028283 => "10.64.241.123"
func IntToIP(n int) string {
	var subnet []string
	for i := 0; i < 4; i++ {
		subnet = append(subnet, strconv.Itoa(n%256))
		n /= 256
	}
	// Reverse array
	subnet[0], subnet[1], subnet[2], subnet[3] = subnet[3], subnet[2], subnet[1], subnet[0]
	return strings.Join(subnet, ".")
}

// Takes 10.46.231.77 netmask 255.255.255.0 and returns 10.46.231.0
func GetSubnet(ip, mask string) string {
	snInt := IPToInt(ip) & IPToInt(mask)
	return IntToIP(snInt)
}

// Checks to see if ip is part of network
func IPInNetwork(ip, network string, bits int) bool {
	mask := BitsToMask(bits)
	ipNet := GetSubnet(ip, mask)
	return ipNet == network
}

// Takes 255.255.252.0 and returns 22
func CountBits(netmask string) int {
	nmInt := IPToInt(netmask)
	var bits int
	for i := 0; i < 32; i++ {
		bits += nmInt % 2
		nmInt /= 2
	}
	return bits
}

func BitsToMask(n int) string {
	ipInt := 0
	toAdd := 2147483648 // 2**31
	for i := 0; i < n; i++ {
		ipInt += toAdd
		toAdd /= 2
	}
	return IntToIP(ipInt)
}

func ConvertMacAddress(s string) string {
	// Matches APC
	if len(s) == 17 && strings.Contains(s, "_") {
		r := strings.Replace(s, "_", ":", -1)
		l := strings.ToLower(r)
		return l
	}
	// Matches Sentry
	if len(s) == 17 && strings.Contains(s, "-") {
		r := strings.Replace(s, "-", ":", -1)
		l := strings.ToLower(r)
		return l
	}
	// Matches SDX: e.g. 02c47ac9b1e8
	if len(s) == 12 {
		mslice := []string{
			string(s[0:2]),
			string(s[2:4]),
			string(s[4:6]),
			string(s[6:8]),
			string(s[8:10]),
			string(s[10:12]),
		}
		return strings.Join(mslice, ":")
	}
	// Matches EOS style: e.g. 7483.ef0b.5f64
	if len(s) == 14 && strings.Contains(s, ".") {
		mslice := []string{
			string(s[0:2]),
			string(s[2:4]),
			string(s[5:7]),
			string(s[7:9]),
			string(s[10:12]),
			string(s[12:14]),
		}
		return strings.Join(mslice, ":")
	}
	// Matches colon delimited output: e.g. 9c:cc:83:8c:f1:c6
	if len(s) == 17 && strings.Count(s, ":") == 5 {
		return s
	}
	// Default to empty string
	return ""
}
