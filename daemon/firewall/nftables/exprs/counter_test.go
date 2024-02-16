package exprs_test

import (
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/nftest"
	"github.com/google/nftables"
)

func TestExprNamedCounter(t *testing.T) {
	nftest.SkipIfNotPrivileged(t)

	conn, newNS := nftest.OpenSystemConn(t)
	defer nftest.CleanupSystemConn(t, newNS)
	nftest.Fw.Conn = conn

	// we must create the table before the counter object.
	tbl, _ := nftest.Fw.AddTable("yyy", exprs.NFT_FAMILY_INET)

	nftest.Fw.Conn.AddObj(
		&nftables.CounterObj{
			Table: &nftables.Table{
				Name:   "yyy",
				Family: nftables.TableFamilyINet,
			},
			Name:    "xxx-counter",
			Bytes:   0,
			Packets: 0,
		},
	)

	r, _ := nftest.AddTestRule(t, conn, exprs.NewExprCounter("xxx-counter"))
	if r == nil {
		t.Error("Error adding counter rule")
		return
	}

	objs, err := nftest.Fw.Conn.GetObjects(tbl)
	if err != nil {
		t.Errorf("Error retrieving objects from table %s: %s", tbl.Name, err)
	}
	if len(objs) != 1 {
		t.Errorf("%d objects found, expected 1", len(objs))
	}
	counter, ok := objs[0].(*nftables.CounterObj)
	if !ok {
		t.Errorf("returned Obj is not CounterObj: %+v", objs[0])
	}
	if counter.Name != "xxx-counter" {
		t.Errorf("CounterObj name differs: %s, expected 'xxx-counter'", counter.Name)
	}
}
