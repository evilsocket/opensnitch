package nftables_test

import (
	"testing"

	nftb "github.com/evilsocket/opensnitch/daemon/firewall/nftables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
)

func tableExists(t *testing.T, conn *nftables.Conn, origtbl *nftables.Table, family string) bool {
	tables, err := conn.ListTablesOfFamily(
		nftb.GetFamilyCode(family),
	)
	if err != nil {
		return false
	}
	found := false
	for _, tbl := range tables {
		if origtbl != nil && tbl.Name == origtbl.Name {
			found = true
			break
		}
	}
	return found
}

func TestAddTable(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	t.Run("inet family", func(t *testing.T) {
		tblxxx, err := nftest.Fw.AddTable("xxx", exprs.NFT_FAMILY_INET)
		if err != nil {
			t.Error("table xxx-inet not added:", err)
		}
		if tableExists(t, nftest.Fw.Conn, tblxxx, exprs.NFT_FAMILY_INET) == false {
			t.Error("table xxx-inet not in the list")
		}

		nftest.Fw.DelSystemTables()
		if tableExists(t, nftest.Fw.Conn, tblxxx, exprs.NFT_FAMILY_INET) {
			t.Error("table xxx-inet still exists")
		}
	})

	t.Run("ip family", func(t *testing.T) {
		tblxxx, err := nftest.Fw.AddTable("xxx", exprs.NFT_FAMILY_IP)
		if err != nil {
			t.Error("table xxx-ip not added:", err)
		}
		if tableExists(t, nftest.Fw.Conn, tblxxx, exprs.NFT_FAMILY_IP) == false {
			t.Error("table xxx-ip not in the list")
		}

		nftest.Fw.DelSystemTables()
		if tableExists(t, nftest.Fw.Conn, tblxxx, exprs.NFT_FAMILY_IP) {
			t.Errorf("table xxx-ip still exists:") // %+v", sysTables)
		}
	})

	t.Run("ip6 family", func(t *testing.T) {
		tblxxx, err := nftest.Fw.AddTable("xxx", exprs.NFT_FAMILY_IP6)
		if err != nil {
			t.Error("table xxx-ip6 not added:", err)
		}
		if tableExists(t, nftest.Fw.Conn, tblxxx, exprs.NFT_FAMILY_IP6) == false {
			t.Error("table xxx-ip6 not in the list")
		}

		nftest.Fw.DelSystemTables()
		if tableExists(t, nftest.Fw.Conn, tblxxx, exprs.NFT_FAMILY_IP6) {
			t.Errorf("table xxx-ip6 still exists:") // %+v", sysTables)
		}
	})
}

// TestAddInterceptionTables checks if the needed tables have been created.
// We use 2: mangle-inet for intercepting outbound connections, and filter-inet for DNS responses interception
func TestAddInterceptionTables(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	if err := nftest.Fw.AddInterceptionTables(); err != nil {
		t.Errorf("addInterceptionTables() error: %s", err)
	}

	t.Run("mangle-inet", func(t *testing.T) {
		tblmangle := nftest.Fw.GetTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
		if tblmangle == nil {
			t.Error("interception table mangle-inet not in the list")
		}
		if tableExists(t, nftest.Fw.Conn, tblmangle, exprs.NFT_FAMILY_INET) == false {
			t.Error("table mangle-inet not in the list")
		}
	})
	t.Run("filter-inet", func(t *testing.T) {
		tblfilter := nftest.Fw.GetTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("interception table filter-inet not in the list")
		}
		if tableExists(t, nftest.Fw.Conn, tblfilter, exprs.NFT_FAMILY_INET) == false {
			t.Error("table filter-inet not in the list")
		}
	})
}
