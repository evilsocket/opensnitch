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
// We use opensnitch-inet for intercepting outbound connections (chain mangle_output) and DNS responses (chain filter_input)
func TestAddInterceptionTables(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	if err := nftest.Fw.AddInterceptionTables(); err != nil {
		t.Errorf("addInterceptionTables() error: %s", err)
	}

	t.Run("opensnitch-inet", func(t *testing.T) {
		tbl := nftest.Fw.GetTable(exprs.TABLE_OPENSNITCH, exprs.NFT_FAMILY_INET)
		if tbl == nil {
			t.Error("interception table opensnitch-inet not in the list")
		}
		if tableExists(t, nftest.Fw.Conn, tbl, exprs.NFT_FAMILY_INET) == false {
			t.Error("table opensnitch-inet not in the list")
		}
	})
}
