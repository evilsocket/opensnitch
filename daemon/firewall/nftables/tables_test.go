package nftables

import (
	"runtime"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

var (
	conn  *nftables.Conn
	newNS netns.NsHandle

	nft, _ = Fw()
)

func init() {
	initMapsStore()
}

// https://github.com/google/nftables/blob/8f2d395e1089dea4966c483fbeae7e336917c095/internal/nftest/system_conn.go#L15
func OpenSystemConn(t *testing.T) (*nftables.Conn, netns.NsHandle) {
	t.Helper()
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in nftest.CleanupSystemConn().
	runtime.LockOSThread()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New() failed: %v", err)
	}
	t.Log("OpenSystemConn() with NS:", ns)
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}
	return c, ns
}

func CleanupSystemConn(t *testing.T, newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
}

func tableExists(t *testing.T, origtbl *nftables.Table, family string) bool {
	tables, err := conn.ListTablesOfFamily(
		getFamilyCode(family),
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
	conn, newNS = OpenSystemConn(t)
	defer CleanupSystemConn(t, newNS)
	nft.conn = conn

	t.Run("inet family", func(t *testing.T) {
		tblxxx, err := nft.AddTable("xxx", exprs.NFT_FAMILY_INET)
		if err != nil {
			t.Error("table xxx-inet not added:", err)
		}
		if tableExists(t, tblxxx, exprs.NFT_FAMILY_INET) == false {
			t.Error("table xxx-inet not in the list")
		}

		nft.delSystemTables()
		if tableExists(t, tblxxx, exprs.NFT_FAMILY_INET) {
			t.Errorf("table xxx-inet still exists: %+v", sysTables)
		}
	})

	t.Run("ip family", func(t *testing.T) {
		tblxxx, err := nft.AddTable("xxx", exprs.NFT_FAMILY_IP)
		if err != nil {
			t.Error("table xxx-ip not added:", err)
		}
		if tableExists(t, tblxxx, exprs.NFT_FAMILY_IP) == false {
			t.Error("table xxx-ip not in the list")
		}

		nft.delSystemTables()
		if tableExists(t, tblxxx, exprs.NFT_FAMILY_IP) {
			t.Errorf("table xxx-ip still exists: %+v", sysTables)
		}
	})

	t.Run("ip6 family", func(t *testing.T) {
		tblxxx, err := nft.AddTable("xxx", exprs.NFT_FAMILY_IP6)
		if err != nil {
			t.Error("table xxx-ip6 not added:", err)
		}
		if tableExists(t, tblxxx, exprs.NFT_FAMILY_IP6) == false {
			t.Error("table xxx-ip6 not in the list")
		}

		nft.delSystemTables()
		if tableExists(t, tblxxx, exprs.NFT_FAMILY_IP6) {
			t.Errorf("table xxx-ip6 still exists: %+v", sysTables)
		}
	})
}

// TestAddInterceptionTables checks if the needed tables have been created.
// We use 2: mangle-inet for intercepting outbound connections, and filter-inet for DNS responses interception
func TestAddInterceptionTables(t *testing.T) {
	conn, newNS = OpenSystemConn(t)
	defer CleanupSystemConn(t, newNS)
	nft.conn = conn

	if err := nft.addInterceptionTables(); err != nil {
		t.Errorf("addInterceptionTables() error: %s", err)
	}

	t.Run("mangle-inet", func(t *testing.T) {
		tblmangle := nft.getTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
		if tblmangle == nil {
			t.Error("interception table mangle-inet not in the list")
		}
		if tableExists(t, tblmangle, exprs.NFT_FAMILY_INET) == false {
			t.Error("table mangle-inet not in the list")
		}
	})
	t.Run("filter-inet", func(t *testing.T) {
		tblfilter := nft.getTable(exprs.NFT_CHAIN_FILTER, exprs.NFT_FAMILY_INET)
		if tblfilter == nil {
			t.Error("interception table filter-inet not in the list")
		}
		if tableExists(t, tblfilter, exprs.NFT_FAMILY_INET) == false {
			t.Error("table filter-inet not in the list")
		}
	})
}
