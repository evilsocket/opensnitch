package rule

import (
	"encoding/json"
	"net"
	"os"
)

var NetworkAliases = make(map[string][]string)
var AliasIPCache = make(map[string][]*net.IPNet)

func LoadAliases(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var aliases map[string][]string
	if err := json.Unmarshal(data, &aliases); err != nil {
		return err
	}

	for alias, networks := range aliases {
		var ipNets []*net.IPNet
		for _, network := range networks {
			_, ipNet, err := net.ParseCIDR(network)
			if err != nil {
				// fmt.Printf("Error parsing CIDR for %s: %v\n", network, err)
				continue
			}
			ipNets = append(ipNets, ipNet)
		}
		AliasIPCache[alias] = ipNets
		// fmt.Printf("Alias '%s' loaded with the following networks: %v\n", alias, networks)
	}

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
