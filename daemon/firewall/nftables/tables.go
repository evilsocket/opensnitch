package nftables

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
)

func getTable(name, family string) *nftables.Table {
	return sysTables[getTableKey(name, family)]
}

func getTableKey(name string, family interface{}) string {
	return fmt.Sprint(name, "-", family)
}

func (n *Nft) addInterceptionTables() error {
	n.AddTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
	n.AddTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
	return nil
}

// Contrary to iptables, in nftables there're no predefined rules.
// Convention is though to use the iptables names by default.
// We need at least: mangle and filter tables, inet family (IPv4 and IPv6).
func (n *Nft) addSystemTables() {
	n.AddTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
	n.AddTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
}

// AddTable adds a new table to nftables.
func (n *Nft) AddTable(name, family string) *nftables.Table {
	famCode := getFamilyCode(family)
	tbl := &nftables.Table{
		Family: famCode,
		Name:   name,
	}
	n.conn.AddTable(tbl)

	if !n.Commit() {
		log.Error("%s error adding system firewall table: %s, family: %s (%d)", logTag, name, family, famCode)
		return nil
	}
	key := getTableKey(name, family)
	sysTables[key] = tbl
	return tbl
}

// FIXME: if the user configured chains policies to drop and disables the firewall,
// the policy is not restored.
func (n *Nft) delSystemTables() {
	for _, tbl := range sysTables {
		n.conn.DelTable(tbl)
		delete(sysTables, tbl.Name)
	}
	if len(sysTables) > 0 {
		if !n.Commit() {
			log.Warning("error deleting system tables")
		}
	}
}
