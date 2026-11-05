package rule

import (
	"encoding/json"
	"net"
	"os"
)

var NetworkAliases = make(map[string][]string)
var AliasIPCache = make(map[string][]*net.IPNet)

// DefaultAliases mirrors daemon/data/network_aliases.json. They are used when
// the aliases file is missing (some distributions don't install it), so that
// rules created by the UI with "LAN" or "MULTICAST" as destination still
// compile instead of failing with "CIDR parsing error: invalid CIDR address".
var DefaultAliases = map[string][]string{
	"LAN": {
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	},
	"MULTICAST": {
		"224.0.0.0/4",
		"ff00::/8",
	},
}

func loadAliasMap(aliases map[string][]string) {
	for alias, networks := range aliases {
		var ipNets []*net.IPNet
		for _, network := range networks {
			_, ipNet, err := net.ParseCIDR(network)
			if err != nil {
				// a bare IP (e.g. "::1") is accepted as a /32 or /128
				if ip := net.ParseIP(network); ip != nil {
					bits := 32
					if ip.To4() == nil {
						bits = 128
					}
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
				} else {
					continue
				}
			}
			ipNets = append(ipNets, ipNet)
		}
		AliasIPCache[alias] = ipNets
	}
}

// LoadAliases loads network aliases from filename, falling back to
// DefaultAliases when the file is missing or invalid. The returned error
// (if any) describes why the file could not be used.
func LoadAliases(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		loadAliasMap(DefaultAliases)
		return err
	}

	var aliases map[string][]string
	if err := json.Unmarshal(data, &aliases); err != nil {
		loadAliasMap(DefaultAliases)
		return err
	}

	loadAliasMap(aliases)

	// fmt.Println("Network aliases successfully loaded into the cache.")
	return nil
}

func GetAliasByIP(ip string) string {
	ipAddr := net.ParseIP(ip)
	for alias, ipNets := range AliasIPCache {
		for _, ipNet := range ipNets {
			if ipNet.Contains(ipAddr) {
				// fmt.Printf("Alias '%s' found for IP address: %s in network %s\n", alias, ip, ipNet.String())
				return alias
			}
		}
	}
	// fmt.Printf("No alias found for IP: %s\n", ip)
	return ""
}

func (o *Operator) SerializeData() string {
	alias := GetAliasByIP(o.Data)
	if alias != "" {
		return alias
	}
	return o.Data
}
