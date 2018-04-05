package netfilter

import (
	"testing"
	"time"
)

var stopCh = make(chan struct{})

func serve(t *testing.T, queueNum uint16) {
	nfq, err := NewNFQueue(queueNum, 100, NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		t.Skipf("Skipping the test due to %s", err)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	t.Logf("Starting (NFQ %d)..", queueNum)
	for true {
		select {
		case p := <-packets:
			t.Logf("Accepting %s", p.Packet)
			p.SetVerdict(NF_ACCEPT)
		case <-stopCh:
			t.Logf("Exiting..")
			return
		}
	}
}

// very dumb test, but enough for testing golang/go#14210
func TestNetfilter(t *testing.T) {
	queueNum := 42
	go serve(t, uint16(queueNum))
	wait := 3 * time.Second
	t.Logf("Sleeping for %s", wait)
	time.Sleep(wait)
	close(stopCh)
}
