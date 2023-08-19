// +build linux

package netlink

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type arpEntry struct {
	ip  net.IP
	mac net.HardwareAddr
}

type proxyEntry struct {
	ip  net.IP
	dev int
}

func parseMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func dumpContains(dump []Neigh, e arpEntry) bool {
	for _, n := range dump {
		if n.IP.Equal(e.ip) && (n.State&NUD_INCOMPLETE) == 0 {
			return true
		}
	}
	return false
}

func dumpContainsNeigh(dump []Neigh, ne Neigh) bool {
	for _, n := range dump {
		if n.IP.Equal(ne.IP) && n.LLIPAddr.Equal(ne.LLIPAddr) {
			return true
		}
	}
	return false
}

func dumpContainsState(dump []Neigh, e arpEntry, s uint16) bool {
	for _, n := range dump {
		if n.IP.Equal(e.ip) && uint16(n.State) == s {
			return true
		}
	}
	return false
}

func dumpContainsProxy(dump []Neigh, p proxyEntry) bool {
	for _, n := range dump {
		if n.IP.Equal(p.ip) && (n.LinkIndex == p.dev) && (n.Flags&NTF_PROXY) == NTF_PROXY {
			return true
		}
	}
	return false
}

func TestNeighAddDelLLIPAddr(t *testing.T) {
	setUpNetlinkTestWithKModule(t, "ip_gre")

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	dummy := Gretun{
		LinkAttrs: LinkAttrs{Name: "neigh0"},
		Local:     net.IPv4(127, 0, 0, 1),
		IKey:      1234,
		OKey:      1234}
	if err := LinkAdd(&dummy); err != nil {
		t.Errorf("Failed to create link: %v", err)
	}
	ensureIndex(dummy.Attrs())

	entry := Neigh{
		LinkIndex: dummy.Index,
		State:     NUD_PERMANENT,
		IP:        net.IPv4(198, 51, 100, 2),
		LLIPAddr:  net.IPv4(198, 51, 100, 1),
	}

	err := NeighAdd(&entry)
	if err != nil {
		t.Errorf("Failed to NeighAdd: %v", err)
	}

	// Dump and see that all added entries are there
	dump, err := NeighList(dummy.Index, 0)
	if err != nil {
		t.Errorf("Failed to NeighList: %v", err)
	}

	if !dumpContainsNeigh(dump, entry) {
		t.Errorf("Dump does not contain: %v: %v", entry, dump)
	}

	// Delete the entry
	err = NeighDel(&entry)
	if err != nil {
		t.Errorf("Failed to NeighDel: %v", err)
	}

	if err := LinkDel(&dummy); err != nil {
		t.Fatal(err)
	}
}

func TestNeighAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	dummy := Dummy{LinkAttrs{Name: "neigh0"}}
	if err := LinkAdd(&dummy); err != nil {
		t.Fatal(err)
	}

	ensureIndex(dummy.Attrs())

	arpTable := []arpEntry{
		{net.ParseIP("10.99.0.1"), parseMAC("aa:bb:cc:dd:00:01")},
		{net.ParseIP("10.99.0.2"), parseMAC("aa:bb:cc:dd:00:02")},
		{net.ParseIP("10.99.0.3"), parseMAC("aa:bb:cc:dd:00:03")},
		{net.ParseIP("10.99.0.4"), parseMAC("aa:bb:cc:dd:00:04")},
		{net.ParseIP("10.99.0.5"), parseMAC("aa:bb:cc:dd:00:05")},
	}

	// Add the arpTable
	for _, entry := range arpTable {
		err := NeighAdd(&Neigh{
			LinkIndex:    dummy.Index,
			State:        NUD_REACHABLE,
			IP:           entry.ip,
			HardwareAddr: entry.mac,
		})

		if err != nil {
			t.Errorf("Failed to NeighAdd: %v", err)
		}
	}

	// Dump and see that all added entries are there
	dump, err := NeighList(dummy.Index, 0)
	if err != nil {
		t.Errorf("Failed to NeighList: %v", err)
	}

	for _, entry := range arpTable {
		if !dumpContains(dump, entry) {
			t.Errorf("Dump does not contain: %v", entry)
		}
	}

	// Delete the arpTable
	for _, entry := range arpTable {
		err := NeighDel(&Neigh{
			LinkIndex:    dummy.Index,
			IP:           entry.ip,
			HardwareAddr: entry.mac,
		})

		if err != nil {
			t.Errorf("Failed to NeighDel: %v", err)
		}
	}

	// TODO: seems not working because of cache
	//// Dump and see that none of deleted entries are there
	//dump, err = NeighList(dummy.Index, 0)
	//if err != nil {
	//t.Errorf("Failed to NeighList: %v", err)
	//}

	//for _, entry := range arpTable {
	//if dumpContains(dump, entry) {
	//t.Errorf("Dump contains: %v", entry)
	//}
	//}

	if err := LinkDel(&dummy); err != nil {
		t.Fatal(err)
	}
}

func TestNeighAddDelProxy(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	dummy := Dummy{LinkAttrs{Name: "neigh0"}}
	if err := LinkAdd(&dummy); err != nil {
		t.Fatal(err)
	}

	ensureIndex(dummy.Attrs())

	proxyTable := []proxyEntry{
		{net.ParseIP("10.99.0.1"), dummy.Index},
		{net.ParseIP("10.99.0.2"), dummy.Index},
		{net.ParseIP("10.99.0.3"), dummy.Index},
		{net.ParseIP("10.99.0.4"), dummy.Index},
		{net.ParseIP("10.99.0.5"), dummy.Index},
	}

	// Add the proxyTable
	for _, entry := range proxyTable {
		err := NeighAdd(&Neigh{
			LinkIndex: dummy.Index,
			Flags:     NTF_PROXY,
			IP:        entry.ip,
		})

		if err != nil {
			t.Errorf("Failed to NeighAdd: %v", err)
		}
	}

	// Dump and see that all added entries are there
	dump, err := NeighProxyList(dummy.Index, 0)
	if err != nil {
		t.Errorf("Failed to NeighList: %v", err)
	}

	for _, entry := range proxyTable {
		if !dumpContainsProxy(dump, entry) {
			t.Errorf("Dump does not contain: %v", entry)
		}
	}

	// Delete the proxyTable
	for _, entry := range proxyTable {
		err := NeighDel(&Neigh{
			LinkIndex: dummy.Index,
			Flags:     NTF_PROXY,
			IP:        entry.ip,
		})

		if err != nil {
			t.Errorf("Failed to NeighDel: %v", err)
		}
	}

	// Dump and see that none of deleted entries are there
	dump, err = NeighProxyList(dummy.Index, 0)
	if err != nil {
		t.Errorf("Failed to NeighList: %v", err)
	}

	for _, entry := range proxyTable {
		if dumpContainsProxy(dump, entry) {
			t.Errorf("Dump contains: %v", entry)
		}
	}

	if err := LinkDel(&dummy); err != nil {
		t.Fatal(err)
	}
}

// expectNeighUpdate returns whether the expected updates are received within one second.
func expectNeighUpdate(ch <-chan NeighUpdate, expected []NeighUpdate) bool {
	for {
		timeout := time.After(time.Second)
		select {
		case update := <-ch:
			var toDelete []int
			for index, elem := range expected {
				if update.Type == elem.Type &&
					update.Neigh.State == elem.Neigh.State &&
					update.Neigh.IP != nil &&
					update.Neigh.IP.Equal(elem.Neigh.IP) {
					toDelete = append(toDelete, index)
				}
			}
			for done, index := range toDelete {
				expected = append(expected[:index-done], expected[index-done+1:]...)
			}
			if len(expected) == 0 {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestNeighSubscribe(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	dummy := &Dummy{LinkAttrs{Name: "neigh0"}}
	if err := LinkAdd(dummy); err != nil {
		t.Errorf("Failed to create link: %v", err)
	}
	ensureIndex(dummy.Attrs())
	defer func() {
		if err := LinkDel(dummy); err != nil {
			t.Fatal(err)
		}
	}()

	ch := make(chan NeighUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := NeighSubscribe(ch, done); err != nil {
		t.Fatal(err)
	}

	entry := &Neigh{
		LinkIndex:    dummy.Index,
		State:        NUD_REACHABLE,
		IP:           net.IPv4(10, 99, 0, 1),
		HardwareAddr: parseMAC("aa:bb:cc:dd:00:01"),
	}

	if err := NeighAdd(entry); err != nil {
		t.Errorf("Failed to NeighAdd: %v", err)
	}
	if !expectNeighUpdate(ch, []NeighUpdate{NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: *entry,
	}}) {
		t.Fatalf("Add update not received as expected")
	}
	if err := NeighDel(entry); err != nil {
		t.Fatal(err)
	}
	if !expectNeighUpdate(ch, []NeighUpdate{NeighUpdate{
		Type: unix.RTM_NEWNEIGH,
		Neigh: Neigh{
			State: NUD_FAILED,
			IP:    entry.IP},
	}}) {
		t.Fatalf("Del update not received as expected")
	}
}

func TestNeighSubscribeWithOptions(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan NeighUpdate)
	done := make(chan struct{})
	defer close(done)
	var lastError error
	defer func() {
		if lastError != nil {
			t.Fatalf("Fatal error received during subscription: %v", lastError)
		}
	}()
	if err := NeighSubscribeWithOptions(ch, done, NeighSubscribeOptions{
		ErrorCallback: func(err error) {
			lastError = err
		},
	}); err != nil {
		t.Fatal(err)
	}

	dummy := &Dummy{LinkAttrs{Name: "neigh0"}}
	if err := LinkAdd(dummy); err != nil {
		t.Errorf("Failed to create link: %v", err)
	}
	ensureIndex(dummy.Attrs())
	defer func() {
		if err := LinkDel(dummy); err != nil {
			t.Fatal(err)
		}
	}()

	entry := &Neigh{
		LinkIndex:    dummy.Index,
		State:        NUD_REACHABLE,
		IP:           net.IPv4(10, 99, 0, 1),
		HardwareAddr: parseMAC("aa:bb:cc:dd:00:01"),
	}

	err := NeighAdd(entry)
	if err != nil {
		t.Errorf("Failed to NeighAdd: %v", err)
	}
	if !expectNeighUpdate(ch, []NeighUpdate{NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: *entry,
	}}) {
		t.Fatalf("Add update not received as expected")
	}
}

func TestNeighSubscribeAt(t *testing.T) {
	skipUnlessRoot(t)

	// Create an handle on a custom netns
	newNs, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer newNs.Close()

	nh, err := NewHandleAt(newNs)
	if err != nil {
		t.Fatal(err)
	}
	defer nh.Delete()

	// Subscribe for Neigh events on the custom netns
	ch := make(chan NeighUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := NeighSubscribeAt(newNs, ch, done); err != nil {
		t.Fatal(err)
	}

	dummy := &Dummy{LinkAttrs{Name: "neigh0"}}
	if err := nh.LinkAdd(dummy); err != nil {
		t.Errorf("Failed to create link: %v", err)
	}
	ensureIndex(dummy.Attrs())
	defer func() {
		if err := nh.LinkDel(dummy); err != nil {
			t.Fatal(err)
		}
	}()

	entry := &Neigh{
		LinkIndex:    dummy.Index,
		State:        NUD_REACHABLE,
		IP:           net.IPv4(198, 51, 100, 1),
		HardwareAddr: parseMAC("aa:bb:cc:dd:00:01"),
	}

	err = nh.NeighAdd(entry)
	if err != nil {
		t.Errorf("Failed to NeighAdd: %v", err)
	}
	if !expectNeighUpdate(ch, []NeighUpdate{NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: *entry,
	}}) {
		t.Fatalf("Add update not received as expected")
	}
}

func TestNeighSubscribeListExisting(t *testing.T) {
	skipUnlessRoot(t)

	// Create an handle on a custom netns
	newNs, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer newNs.Close()

	nh, err := NewHandleAt(newNs)
	if err != nil {
		t.Fatal(err)
	}
	defer nh.Delete()

	dummy := &Dummy{LinkAttrs{Name: "neigh0"}}
	if err := nh.LinkAdd(dummy); err != nil {
		t.Errorf("Failed to create link: %v", err)
	}
	ensureIndex(dummy.Attrs())
	defer func() {
		if err := nh.LinkDel(dummy); err != nil {
			t.Fatal(err)
		}
	}()

	vxlani := &Vxlan{LinkAttrs: LinkAttrs{Name: "neigh1"}, VxlanId: 1}
	if err := nh.LinkAdd(vxlani); err != nil {
		t.Errorf("Failed to create link: %v", err)
	}
	ensureIndex(vxlani.Attrs())
	defer func() {
		if err := nh.LinkDel(vxlani); err != nil {
			t.Fatal(err)
		}
	}()

	entry1 := &Neigh{
		LinkIndex:    dummy.Index,
		State:        NUD_REACHABLE,
		IP:           net.IPv4(198, 51, 100, 1),
		HardwareAddr: parseMAC("aa:bb:cc:dd:00:01"),
	}

	entryBr := &Neigh{
		Family:       syscall.AF_BRIDGE,
		LinkIndex:    vxlani.Index,
		State:        NUD_PERMANENT,
		Flags:        NTF_SELF,
		IP:           net.IPv4(198, 51, 100, 3),
		HardwareAddr: parseMAC("aa:bb:cc:dd:00:03"),
	}

	err = nh.NeighAdd(entry1)
	if err != nil {
		t.Errorf("Failed to NeighAdd: %v", err)
	}
	err = nh.NeighAppend(entryBr)
	if err != nil {
		t.Errorf("Failed to NeighAdd: %v", err)
	}

	// Subscribe for Neigh events including existing neighbors
	ch := make(chan NeighUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := NeighSubscribeWithOptions(ch, done, NeighSubscribeOptions{
		Namespace:    &newNs,
		ListExisting: true},
	); err != nil {
		t.Fatal(err)
	}

	if !expectNeighUpdate(ch, []NeighUpdate{
		NeighUpdate{
			Type:  unix.RTM_NEWNEIGH,
			Neigh: *entry1,
		},
		NeighUpdate{
			Type:  unix.RTM_NEWNEIGH,
			Neigh: *entryBr,
		},
	}) {
		t.Fatalf("Existing add update not received as expected")
	}

	entry2 := &Neigh{
		LinkIndex:    dummy.Index,
		State:        NUD_PERMANENT,
		IP:           net.IPv4(198, 51, 100, 2),
		HardwareAddr: parseMAC("aa:bb:cc:dd:00:02"),
	}

	err = nh.NeighAdd(entry2)
	if err != nil {
		t.Errorf("Failed to NeighAdd: %v", err)
	}

	if !expectNeighUpdate(ch, []NeighUpdate{NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: *entry2,
	}}) {
		t.Fatalf("Existing add update not received as expected")
	}
}

func TestNeighListExecuteStateFilter(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// Create dummy iface
	dummy := Dummy{LinkAttrs{Name: "neigh0"}}
	if err := LinkAdd(&dummy); err != nil {
		t.Fatal(err)
	}

	ensureIndex(dummy.Attrs())

	// Define some entries
	reachArpTable := []arpEntry{
		{net.ParseIP("198.51.100.1"), parseMAC("44:bb:cc:dd:00:01")},
		{net.ParseIP("2001:db8::1"), parseMAC("66:bb:cc:dd:00:02")},
	}

	staleArpTable := []arpEntry{
		{net.ParseIP("198.51.100.10"), parseMAC("44:bb:cc:dd:00:10")},
		{net.ParseIP("2001:db8::10"), parseMAC("66:bb:cc:dd:00:10")},
	}

	entries := append(reachArpTable, staleArpTable...)

	// Add reachable neigh entries
	for _, entry := range reachArpTable {
		err := NeighAdd(&Neigh{
			LinkIndex:    dummy.Index,
			State:        NUD_REACHABLE,
			IP:           entry.ip,
			HardwareAddr: entry.mac,
		})

		if err != nil {
			t.Errorf("Failed to NeighAdd: %v", err)
		}
	}
	// Add stale neigh entries
	for _, entry := range staleArpTable {
		err := NeighAdd(&Neigh{
			LinkIndex:    dummy.Index,
			State:        NUD_STALE,
			IP:           entry.ip,
			HardwareAddr: entry.mac,
		})

		if err != nil {
			t.Errorf("Failed to NeighAdd: %v", err)
		}
	}

	// Dump reachable and see that all added reachable entries are present and there are no stale entries
	dump, err := NeighListExecute(Ndmsg{
		Index: uint32(dummy.Index),
		State: NUD_REACHABLE,
	})
	if err != nil {
		t.Errorf("Failed to NeighListExecute: %v", err)
	}

	for _, entry := range reachArpTable {
		if !dumpContainsState(dump, entry, NUD_REACHABLE) {
			t.Errorf("Dump does not contains: %v", entry)
		}
	}
	for _, entry := range staleArpTable {
		if dumpContainsState(dump, entry, NUD_STALE) {
			t.Errorf("Dump contains: %v", entry)
		}
	}

	// Delete all neigh entries
	for _, entry := range entries {
		err := NeighDel(&Neigh{
			LinkIndex:    dummy.Index,
			IP:           entry.ip,
			HardwareAddr: entry.mac,
		})

		if err != nil {
			t.Errorf("Failed to NeighDel: %v", err)
		}
	}
}
