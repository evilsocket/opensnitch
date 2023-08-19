// +build linux

package netlink

import (
	"testing"

	"github.com/vishvananda/netlink/nl"
)

func TestXfrmMonitorExpire(t *testing.T) {
	defer setUpNetlinkTest(t)()

	ch := make(chan XfrmMsg)
	done := make(chan struct{})
	defer close(done)
	errChan := make(chan error)
	if err := XfrmMonitor(ch, nil, errChan, nl.XFRM_MSG_EXPIRE); err != nil {
		t.Fatal(err)
	}

	// Program state with limits
	state := getBaseState()
	state.Limits.TimeHard = 2
	state.Limits.TimeSoft = 1
	if err := XfrmStateAdd(state); err != nil {
		t.Fatal(err)
	}

	hardFound := false
	softFound := false

	msg := (<-ch).(*XfrmMsgExpire)
	if msg.XfrmState.Spi != state.Spi {
		t.Fatal("Received unexpected msg, spi does not match")
	}
	hardFound = msg.Hard || hardFound
	softFound = !msg.Hard || softFound

	msg = (<-ch).(*XfrmMsgExpire)
	if msg.XfrmState.Spi != state.Spi {
		t.Fatal("Received unexpected msg, spi does not match")
	}
	hardFound = msg.Hard || hardFound
	softFound = !msg.Hard || softFound

	if !hardFound || !softFound {
		t.Fatal("Missing expire msg: hard found:", hardFound, "soft found:", softFound)
	}
}
