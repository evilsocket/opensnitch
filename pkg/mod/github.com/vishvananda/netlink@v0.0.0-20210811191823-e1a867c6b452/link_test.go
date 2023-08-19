// +build linux

package netlink

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	testTxQLen    int = 100
	defaultTxQLen int = 1000
	testTxQueues  int = 4
	testRxQueues  int = 8
)

func testLinkAddDel(t *testing.T, link Link) {
	links, err := LinkList()
	if err != nil {
		t.Fatal(err)
	}

	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	base := link.Attrs()

	result, err := LinkByName(base.Name)
	if err != nil {
		t.Fatal(err)
	}

	rBase := result.Attrs()

	if base.Index != 0 {
		if base.Index != rBase.Index {
			t.Fatalf("index is %d, should be %d", rBase.Index, base.Index)
		}
	}

	if base.Group > 0 {
		if base.Group != rBase.Group {
			t.Fatalf("group is %d, should be %d", rBase.Group, base.Group)
		}
	}

	if vlan, ok := link.(*Vlan); ok {
		other, ok := result.(*Vlan)
		if !ok {
			t.Fatal("Result of create is not a vlan")
		}
		if vlan.VlanId != other.VlanId {
			t.Fatal("Link.VlanId id doesn't match")
		}
	}

	if veth, ok := result.(*Veth); ok {
		if rBase.TxQLen != base.TxQLen {
			t.Fatalf("qlen is %d, should be %d", rBase.TxQLen, base.TxQLen)
		}

		if rBase.NumTxQueues != base.NumTxQueues {
			t.Fatalf("txQueues is %d, should be %d", rBase.NumTxQueues, base.NumTxQueues)
		}

		if rBase.NumRxQueues != base.NumRxQueues {
			t.Fatalf("rxQueues is %d, should be %d", rBase.NumRxQueues, base.NumRxQueues)
		}

		if rBase.MTU != base.MTU {
			t.Fatalf("MTU is %d, should be %d", rBase.MTU, base.MTU)
		}

		if original, ok := link.(*Veth); ok {
			if original.PeerName != "" {
				var peer *Veth
				other, err := LinkByName(original.PeerName)
				if err != nil {
					t.Fatalf("Peer %s not created", veth.PeerName)
				}
				if peer, ok = other.(*Veth); !ok {
					t.Fatalf("Peer %s is incorrect type", veth.PeerName)
				}
				if peer.TxQLen != testTxQLen {
					t.Fatalf("TxQLen of peer is %d, should be %d", peer.TxQLen, testTxQLen)
				}
				if peer.NumTxQueues != testTxQueues {
					t.Fatalf("NumTxQueues of peer is %d, should be %d", peer.NumTxQueues, testTxQueues)
				}
				if peer.NumRxQueues != testRxQueues {
					t.Fatalf("NumRxQueues of peer is %d, should be %d", peer.NumRxQueues, testRxQueues)
				}
				if !bytes.Equal(peer.Attrs().HardwareAddr, original.PeerHardwareAddr) {
					t.Fatalf("Peer MAC addr is %s, should be %s", peer.Attrs().HardwareAddr, original.PeerHardwareAddr)
				}
			}
		}
	} else {
		// recent kernels set the parent index for veths in the response
		if rBase.ParentIndex == 0 && base.ParentIndex != 0 {
			t.Fatalf("Created link doesn't have parent %d but it should", base.ParentIndex)
		} else if rBase.ParentIndex != 0 && base.ParentIndex == 0 {
			t.Fatalf("Created link has parent %d but it shouldn't", rBase.ParentIndex)
		} else if rBase.ParentIndex != 0 && base.ParentIndex != 0 {
			if rBase.ParentIndex != base.ParentIndex {
				t.Fatalf("Link.ParentIndex doesn't match %d != %d", rBase.ParentIndex, base.ParentIndex)
			}
		}
	}

	if _, ok := link.(*Wireguard); ok {
		_, ok := result.(*Wireguard)
		if !ok {
			t.Fatal("Result of create is not a wireguard")
		}
	}

	if vxlan, ok := link.(*Vxlan); ok {
		other, ok := result.(*Vxlan)
		if !ok {
			t.Fatal("Result of create is not a vxlan")
		}
		compareVxlan(t, vxlan, other)
	}

	if ipv, ok := link.(*IPVlan); ok {
		other, ok := result.(*IPVlan)
		if !ok {
			t.Fatal("Result of create is not a ipvlan")
		}
		if ipv.Mode != other.Mode {
			t.Fatalf("Got unexpected mode: %d, expected: %d", other.Mode, ipv.Mode)
		}
		if ipv.Flag != other.Flag {
			t.Fatalf("Got unexpected flag: %d, expected: %d", other.Flag, ipv.Flag)
		}
	}

	if macv, ok := link.(*Macvlan); ok {
		other, ok := result.(*Macvlan)
		if !ok {
			t.Fatal("Result of create is not a macvlan")
		}
		if macv.Mode != other.Mode {
			t.Fatalf("Got unexpected mode: %d, expected: %d", other.Mode, macv.Mode)
		}
	}

	if macv, ok := link.(*Macvtap); ok {
		other, ok := result.(*Macvtap)
		if !ok {
			t.Fatal("Result of create is not a macvtap")
		}
		if macv.Mode != other.Mode {
			t.Fatalf("Got unexpected mode: %d, expected: %d", other.Mode, macv.Mode)
		}
	}

	if _, ok := link.(*Vti); ok {
		_, ok := result.(*Vti)
		if !ok {
			t.Fatal("Result of create is not a vti")
		}
	}

	if bond, ok := link.(*Bond); ok {
		other, ok := result.(*Bond)
		if !ok {
			t.Fatal("Result of create is not a bond")
		}
		if bond.Mode != other.Mode {
			t.Fatalf("Got unexpected mode: %d, expected: %d", other.Mode, bond.Mode)
		}
		if bond.ArpIpTargets != nil {
			if other.ArpIpTargets == nil {
				t.Fatalf("Got unexpected ArpIpTargets: nil")
			}

			if len(bond.ArpIpTargets) != len(other.ArpIpTargets) {
				t.Fatalf("Got unexpected ArpIpTargets len: %d, expected: %d",
					len(other.ArpIpTargets), len(bond.ArpIpTargets))
			}

			for i := range bond.ArpIpTargets {
				if !bond.ArpIpTargets[i].Equal(other.ArpIpTargets[i]) {
					t.Fatalf("Got unexpected ArpIpTargets: %s, expected: %s",
						other.ArpIpTargets[i], bond.ArpIpTargets[i])
				}
			}
		}

		// Mode specific checks
		if os.Getenv("TRAVIS_BUILD_DIR") != "" {
			t.Log("Kernel in travis is too old for this check")
		} else {
			switch mode := bondModeToString[bond.Mode]; mode {
			case "802.3ad":
				if bond.AdSelect != other.AdSelect {
					t.Fatalf("Got unexpected AdSelect: %d, expected: %d", other.AdSelect, bond.AdSelect)
				}
				if bond.AdActorSysPrio != other.AdActorSysPrio {
					t.Fatalf("Got unexpected AdActorSysPrio: %d, expected: %d", other.AdActorSysPrio, bond.AdActorSysPrio)
				}
				if bond.AdUserPortKey != other.AdUserPortKey {
					t.Fatalf("Got unexpected AdUserPortKey: %d, expected: %d", other.AdUserPortKey, bond.AdUserPortKey)
				}
				if bytes.Compare(bond.AdActorSystem, other.AdActorSystem) != 0 {
					t.Fatalf("Got unexpected AdActorSystem: %d, expected: %d", other.AdActorSystem, bond.AdActorSystem)
				}
			case "balance-tlb":
				if bond.TlbDynamicLb != other.TlbDynamicLb {
					t.Fatalf("Got unexpected TlbDynamicLb: %d, expected: %d", other.TlbDynamicLb, bond.TlbDynamicLb)
				}
			}
		}
	}

	if _, ok := link.(*Iptun); ok {
		_, ok := result.(*Iptun)
		if !ok {
			t.Fatal("Result of create is not a iptun")
		}
	}

	if _, ok := link.(*Ip6tnl); ok {
		_, ok := result.(*Ip6tnl)
		if !ok {
			t.Fatal("Result of create is not a ip6tnl")
		}
	}

	if _, ok := link.(*Sittun); ok {
		_, ok := result.(*Sittun)
		if !ok {
			t.Fatal("Result of create is not a sittun")
		}
	}

	if geneve, ok := link.(*Geneve); ok {
		other, ok := result.(*Geneve)
		if !ok {
			t.Fatal("Result of create is not a Geneve")
		}
		compareGeneve(t, geneve, other)
	}

	if gretap, ok := link.(*Gretap); ok {
		other, ok := result.(*Gretap)
		if !ok {
			t.Fatal("Result of create is not a Gretap")
		}
		compareGretap(t, gretap, other)
	}

	if gretun, ok := link.(*Gretun); ok {
		other, ok := result.(*Gretun)
		if !ok {
			t.Fatal("Result of create is not a Gretun")
		}
		compareGretun(t, gretun, other)
	}

	if xfrmi, ok := link.(*Xfrmi); ok {
		other, ok := result.(*Xfrmi)
		if !ok {
			t.Fatal("Result of create is not a xfrmi")
		}
		compareXfrmi(t, xfrmi, other)
	}

	if tuntap, ok := link.(*Tuntap); ok {
		other, ok := result.(*Tuntap)
		if !ok {
			t.Fatal("Result of create is not a tuntap")
		}
		compareTuntap(t, tuntap, other)
	}

	if err = LinkDel(link); err != nil {
		t.Fatal(err)
	}

	links, err = LinkList()
	if err != nil {
		t.Fatal(err)
	}

	for _, l := range links {
		if l.Attrs().Name == link.Attrs().Name {
			t.Fatal("Link not removed properly")
		}
	}
}

func compareGeneve(t *testing.T, expected, actual *Geneve) {
	if actual.ID != expected.ID {
		t.Fatalf("Geneve.ID doesn't match: %d %d", actual.ID, expected.ID)
	}

	// set the Dport to 6081 (the linux default) if it wasn't specified at creation
	if expected.Dport == 0 {
		expected.Dport = 6081
	}

	if actual.Dport != expected.Dport {
		t.Fatal("Geneve.Dport doesn't match")
	}

	if actual.Ttl != expected.Ttl {
		t.Fatal("Geneve.Ttl doesn't match")
	}

	if actual.Tos != expected.Tos {
		t.Fatal("Geneve.Tos doesn't match")
	}

	if !actual.Remote.Equal(expected.Remote) {
		t.Fatalf("Geneve.Remote is not equal: %s!=%s", actual.Remote, expected.Remote)
	}

	// TODO: we should implement the rest of the geneve methods
}

func compareGretap(t *testing.T, expected, actual *Gretap) {
	if actual.IKey != expected.IKey {
		t.Fatal("Gretap.IKey doesn't match")
	}

	if actual.OKey != expected.OKey {
		t.Fatal("Gretap.OKey doesn't match")
	}

	if actual.EncapSport != expected.EncapSport {
		t.Fatal("Gretap.EncapSport doesn't match")
	}

	if actual.EncapDport != expected.EncapDport {
		t.Fatal("Gretap.EncapDport doesn't match")
	}

	if expected.Local != nil && !actual.Local.Equal(expected.Local) {
		t.Fatal("Gretap.Local doesn't match")
	}

	if expected.Remote != nil && !actual.Remote.Equal(expected.Remote) {
		t.Fatal("Gretap.Remote doesn't match")
	}

	if actual.IFlags != expected.IFlags {
		t.Fatal("Gretap.IFlags doesn't match")
	}

	if actual.OFlags != expected.OFlags {
		t.Fatal("Gretap.OFlags doesn't match")
	}

	if actual.PMtuDisc != expected.PMtuDisc {
		t.Fatal("Gretap.PMtuDisc doesn't match")
	}

	if actual.Ttl != expected.Ttl {
		t.Fatal("Gretap.Ttl doesn't match")
	}

	if actual.Tos != expected.Tos {
		t.Fatal("Gretap.Tos doesn't match")
	}

	if actual.EncapType != expected.EncapType {
		t.Fatal("Gretap.EncapType doesn't match")
	}

	if actual.EncapFlags != expected.EncapFlags {
		t.Fatal("Gretap.EncapFlags doesn't match")
	}

	if actual.Link != expected.Link {
		t.Fatal("Gretap.Link doesn't match")
	}

	/*
		 * NOTE: setting the FlowBased flag doesn't seem to work, but by lack of
		 * a proper way to debug this, this test is disabled for now

		 if actual.FlowBased != expected.FlowBased {
			t.Fatal("Gretap.FlowBased doesn't match")
		 }
	*/
}

func compareGretun(t *testing.T, expected, actual *Gretun) {
	if actual.Link != expected.Link {
		t.Fatal("Gretun.Link doesn't match")
	}

	if actual.IFlags != expected.IFlags {
		t.Fatal("Gretun.IFlags doesn't match")
	}

	if actual.OFlags != expected.OFlags {
		t.Fatal("Gretun.OFlags doesn't match")
	}

	if actual.IKey != expected.IKey {
		t.Fatal("Gretun.IKey doesn't match")
	}

	if actual.OKey != expected.OKey {
		t.Fatal("Gretun.OKey doesn't match")
	}

	if expected.Local != nil && !actual.Local.Equal(expected.Local) {
		t.Fatal("Gretun.Local doesn't match")
	}

	if expected.Remote != nil && !actual.Remote.Equal(expected.Remote) {
		t.Fatal("Gretun.Remote doesn't match")
	}

	if actual.Ttl != expected.Ttl {
		t.Fatal("Gretun.Ttl doesn't match")
	}

	if actual.Tos != expected.Tos {
		t.Fatal("Gretun.Tos doesn't match")
	}

	if actual.PMtuDisc != expected.PMtuDisc {
		t.Fatal("Gretun.PMtuDisc doesn't match")
	}

	if actual.EncapType != expected.EncapType {
		t.Fatal("Gretun.EncapType doesn't match")
	}

	if actual.EncapFlags != expected.EncapFlags {
		t.Fatal("Gretun.EncapFlags doesn't match")
	}

	if actual.EncapSport != expected.EncapSport {
		t.Fatal("Gretun.EncapSport doesn't match")
	}

	if actual.EncapDport != expected.EncapDport {
		t.Fatal("Gretun.EncapDport doesn't match")
	}
}

func compareVxlan(t *testing.T, expected, actual *Vxlan) {

	if actual.VxlanId != expected.VxlanId {
		t.Fatal("Vxlan.VxlanId doesn't match")
	}
	if expected.SrcAddr != nil && !actual.SrcAddr.Equal(expected.SrcAddr) {
		t.Fatal("Vxlan.SrcAddr doesn't match")
	}
	if expected.Group != nil && !actual.Group.Equal(expected.Group) {
		t.Fatal("Vxlan.Group doesn't match")
	}
	if expected.TTL != -1 && actual.TTL != expected.TTL {
		t.Fatal("Vxlan.TTL doesn't match")
	}
	if expected.TOS != -1 && actual.TOS != expected.TOS {
		t.Fatal("Vxlan.TOS doesn't match")
	}
	if actual.Learning != expected.Learning {
		t.Fatal("Vxlan.Learning doesn't match")
	}
	if actual.Proxy != expected.Proxy {
		t.Fatal("Vxlan.Proxy doesn't match")
	}
	if actual.RSC != expected.RSC {
		t.Fatal("Vxlan.RSC doesn't match")
	}
	if actual.L2miss != expected.L2miss {
		t.Fatal("Vxlan.L2miss doesn't match")
	}
	if actual.L3miss != expected.L3miss {
		t.Fatal("Vxlan.L3miss doesn't match")
	}
	if actual.GBP != expected.GBP {
		t.Fatal("Vxlan.GBP doesn't match")
	}
	if actual.FlowBased != expected.FlowBased {
		t.Fatal("Vxlan.FlowBased doesn't match")
	}
	if actual.UDP6ZeroCSumTx != expected.UDP6ZeroCSumTx {
		t.Fatal("Vxlan.UDP6ZeroCSumTx doesn't match")
	}
	if actual.UDP6ZeroCSumRx != expected.UDP6ZeroCSumRx {
		t.Fatal("Vxlan.UDP6ZeroCSumRx doesn't match")
	}
	if expected.NoAge {
		if !actual.NoAge {
			t.Fatal("Vxlan.NoAge doesn't match")
		}
	} else if expected.Age > 0 && actual.Age != expected.Age {
		t.Fatal("Vxlan.Age doesn't match")
	}
	if expected.Limit > 0 && actual.Limit != expected.Limit {
		t.Fatal("Vxlan.Limit doesn't match")
	}
	if expected.Port > 0 && actual.Port != expected.Port {
		t.Fatal("Vxlan.Port doesn't match")
	}
	if expected.PortLow > 0 || expected.PortHigh > 0 {
		if actual.PortLow != expected.PortLow {
			t.Fatal("Vxlan.PortLow doesn't match")
		}
		if actual.PortHigh != expected.PortHigh {
			t.Fatal("Vxlan.PortHigh doesn't match")
		}
	}
}

func compareXfrmi(t *testing.T, expected, actual *Xfrmi) {
	if expected.Ifid != actual.Ifid {
		t.Fatal("Xfrmi.Ifid doesn't match")
	}
}

func compareTuntap(t *testing.T, expected, actual *Tuntap) {
	if expected.Mode != actual.Mode {
		t.Fatalf("Tuntap.Mode doesn't match: expected : %+v, got %+v", expected.Mode, actual.Mode)
	}

	if expected.Owner != actual.Owner {
		t.Fatal("Tuntap.Owner doesn't match")
	}

	if expected.Group != actual.Group {
		t.Fatal("Tuntap.Group doesn't match")
	}

	if expected.NonPersist != actual.NonPersist {
		t.Fatal("Tuntap.Group doesn't match")
	}
}

func TestLinkAddDelWithIndex(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Dummy{LinkAttrs{Index: 1000, Name: "foo"}})
}

func TestLinkAddDelDummy(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Dummy{LinkAttrs{Name: "foo"}})
}

func TestLinkAddDelDummyWithGroup(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Dummy{LinkAttrs{Name: "foo", Group: 42}})
}

func TestLinkModify(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	linkName := "foo"
	originalMTU := 1500
	updatedMTU := 1442

	link := &Dummy{LinkAttrs{Name: linkName, MTU: originalMTU}}
	base := link.Attrs()

	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	link.MTU = updatedMTU
	if err := pkgHandle.LinkModify(link); err != nil {
		t.Fatal(err)
	}

	result, err := LinkByName(linkName)
	if err != nil {
		t.Fatal(err)
	}

	rBase := result.Attrs()
	if rBase.MTU != updatedMTU {
		t.Fatalf("MTU is %d, should be %d", rBase.MTU, base.MTU)
	}
}

func TestLinkAddDelIfb(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Ifb{LinkAttrs{Name: "foo"}})
}

func TestLinkAddDelBridge(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Bridge{LinkAttrs: LinkAttrs{Name: "foo", MTU: 1400}})
}

func TestLinkAddDelGeneve(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Geneve{
		LinkAttrs: LinkAttrs{Name: "foo4", EncapType: "geneve"},
		ID:        0x1000,
		Remote:    net.IPv4(127, 0, 0, 1)})

	testLinkAddDel(t, &Geneve{
		LinkAttrs: LinkAttrs{Name: "foo6", EncapType: "geneve"},
		ID:        0x1000,
		Remote:    net.ParseIP("2001:db8:ef33::2")})
}

func TestGeneveCompareToIP(t *testing.T) {
	ns, tearDown := setUpNamedNetlinkTest(t)
	defer tearDown()

	expected := &Geneve{
		ID:     0x764332, // 23 bits
		Remote: net.ParseIP("1.2.3.4"),
		Dport:  6081,
	}

	// Create interface
	cmd := exec.Command("ip", "netns", "exec", ns,
		"ip", "link", "add", "gen0",
		"type", "geneve",
		"vni", fmt.Sprint(expected.ID),
		"remote", expected.Remote.String(),
		// TODO: unit tests are currently done on ubuntu 16, and the version of iproute2 there doesn't support dstport
		// We can still do most of the testing by verifying that we do read the default port
		// "dstport", fmt.Sprint(expected.Dport),
	)
	out := &bytes.Buffer{}
	cmd.Stdout = out
	cmd.Stderr = out

	if rc := cmd.Run(); rc != nil {
		t.Fatal("failed creating link:", rc, out.String())
	}

	link, err := LinkByName("gen0")
	if err != nil {
		t.Fatal("Failed getting link: ", err)
	}
	actual, ok := link.(*Geneve)
	if !ok {
		t.Fatalf("resulted interface is not geneve: %T", link)
	}
	compareGeneve(t, expected, actual)
}

func TestLinkAddDelGretap(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Gretap{
		LinkAttrs: LinkAttrs{Name: "foo4"},
		IKey:      0x101,
		OKey:      0x101,
		PMtuDisc:  1,
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})

	testLinkAddDel(t, &Gretap{
		LinkAttrs: LinkAttrs{Name: "foo6"},
		IKey:      0x101,
		OKey:      0x101,
		Local:     net.ParseIP("2001:db8:abcd::1"),
		Remote:    net.ParseIP("2001:db8:ef33::2")})
}

func TestLinkAddDelGretun(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Gretun{
		LinkAttrs: LinkAttrs{Name: "foo4"},
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})

	testLinkAddDel(t, &Gretun{
		LinkAttrs: LinkAttrs{Name: "foo6"},
		Local:     net.ParseIP("2001:db8:abcd::1"),
		Remote:    net.ParseIP("2001:db8:ef33::2")})
}

func TestLinkAddDelGretunPointToMultiPoint(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Gretun{
		LinkAttrs: LinkAttrs{Name: "foo"},
		Local:     net.IPv4(127, 0, 0, 1),
		IKey:      1234,
		OKey:      1234})

	testLinkAddDel(t, &Gretun{
		LinkAttrs: LinkAttrs{Name: "foo6"},
		Local:     net.ParseIP("2001:db8:1234::4"),
		IKey:      5678,
		OKey:      7890})
}

func TestLinkAddDelGretapFlowBased(t *testing.T) {
	minKernelRequired(t, 4, 3)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Gretap{
		LinkAttrs: LinkAttrs{Name: "foo"},
		FlowBased: true})
}

func TestLinkAddDelVlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	testLinkAddDel(t, &Vlan{LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index}, 900, VLAN_PROTOCOL_8021Q})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelMacvlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	testLinkAddDel(t, &Macvlan{
		LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
		Mode:      MACVLAN_MODE_PRIVATE,
	})

	testLinkAddDel(t, &Macvlan{
		LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
		Mode:      MACVLAN_MODE_BRIDGE,
	})

	testLinkAddDel(t, &Macvlan{
		LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
		Mode:      MACVLAN_MODE_VEPA,
	})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelMacvtap(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	testLinkAddDel(t, &Macvtap{
		Macvlan: Macvlan{
			LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
			Mode:      MACVLAN_MODE_PRIVATE,
		},
	})

	testLinkAddDel(t, &Macvtap{
		Macvlan: Macvlan{
			LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
			Mode:      MACVLAN_MODE_BRIDGE,
		},
	})

	testLinkAddDel(t, &Macvtap{
		Macvlan: Macvlan{
			LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
			Mode:      MACVLAN_MODE_VEPA,
		},
	})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelVeth(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	peerMAC, _ := net.ParseMAC("00:12:34:56:78:02")

	veth := &Veth{
		LinkAttrs: LinkAttrs{
			Name:        "foo",
			TxQLen:      testTxQLen,
			MTU:         1400,
			NumTxQueues: testTxQueues,
			NumRxQueues: testRxQueues,
		},
		PeerName:         "bar",
		PeerHardwareAddr: peerMAC,
	}
	testLinkAddDel(t, veth)
}

func TestLinkAddDelBond(t *testing.T) {
	minKernelRequired(t, 3, 13)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	modes := []string{"802.3ad", "balance-tlb"}
	for _, mode := range modes {
		bond := NewLinkBond(LinkAttrs{Name: "foo"})
		bond.Mode = StringToBondModeMap[mode]
		switch mode {
		case "802.3ad":
			bond.AdSelect = BondAdSelect(BOND_AD_SELECT_BANDWIDTH)
			bond.AdActorSysPrio = 1
			bond.AdUserPortKey = 1
			bond.AdActorSystem, _ = net.ParseMAC("06:aa:bb:cc:dd:ee")
			bond.ArpIpTargets = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.2")}
		case "balance-tlb":
			bond.TlbDynamicLb = 1
			bond.ArpIpTargets = []net.IP{net.ParseIP("1.1.1.2"), net.ParseIP("1.1.1.1")}
		}
		testLinkAddDel(t, bond)
	}
}

func TestLinkAddVethWithDefaultTxQLen(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	la := NewLinkAttrs()
	la.Name = "foo"

	veth := &Veth{LinkAttrs: la, PeerName: "bar"}
	if err := LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := link.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != defaultTxQLen {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, defaultTxQLen)
		}
	}
	peer, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := peer.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != defaultTxQLen {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, defaultTxQLen)
		}
	}
}

func TestLinkAddVethWithZeroTxQLen(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	la := NewLinkAttrs()
	la.Name = "foo"
	la.TxQLen = 0

	veth := &Veth{LinkAttrs: la, PeerName: "bar"}
	if err := LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := link.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != 0 {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, 0)
		}
	}
	peer, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := peer.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != 0 {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, 0)
		}
	}
}

func TestLinkAddDelDummyWithGSO(t *testing.T) {
	const (
		gsoMaxSegs = 16
		gsoMaxSize = 1 << 14
	)
	minKernelRequired(t, 4, 16)
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	dummy := &Dummy{LinkAttrs: LinkAttrs{Name: "foo", GSOMaxSize: gsoMaxSize, GSOMaxSegs: gsoMaxSegs}}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	dummy, ok := link.(*Dummy)
	if !ok {
		t.Fatalf("unexpected link type: %T", link)
	}

	if dummy.GSOMaxSize != gsoMaxSize {
		t.Fatalf("GSOMaxSize is %d, should be %d", dummy.GSOMaxSize, gsoMaxSize)
	}
	if dummy.GSOMaxSegs != gsoMaxSegs {
		t.Fatalf("GSOMaxSeg is %d, should be %d", dummy.GSOMaxSegs, gsoMaxSegs)
	}
}

func TestLinkAddDummyWithTxQLen(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	la := NewLinkAttrs()
	la.Name = "foo"
	la.TxQLen = 1500

	dummy := &Dummy{LinkAttrs: la}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if dummy, ok := link.(*Dummy); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if dummy.TxQLen != 1500 {
			t.Fatalf("TxQLen is %d, should be %d", dummy.TxQLen, 1500)
		}
	}
}

func TestLinkAddDelBridgeMaster(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Bridge{LinkAttrs: LinkAttrs{Name: "foo"}}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}
	testLinkAddDel(t, &Dummy{LinkAttrs{Name: "bar", MasterIndex: master.Attrs().Index}})

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func testLinkSetUnsetResetMaster(t *testing.T, master, newmaster Link) {
	slave := &Dummy{LinkAttrs{Name: "baz"}}
	if err := LinkAdd(slave); err != nil {
		t.Fatal(err)
	}

	nonexistsmaster := &Bridge{LinkAttrs: LinkAttrs{Name: "foobar"}}

	if err := LinkSetMaster(slave, nonexistsmaster); err == nil {
		t.Fatal("error expected")
	}

	if err := LinkSetMaster(slave, master); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MasterIndex != master.Attrs().Index {
		t.Fatal("Master not set properly")
	}

	if err := LinkSetMaster(slave, newmaster); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MasterIndex != newmaster.Attrs().Index {
		t.Fatal("Master not reset properly")
	}

	if err := LinkSetNoMaster(slave); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MasterIndex != 0 {
		t.Fatal("Master not unset properly")
	}
	if err := LinkDel(slave); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetUnsetResetMaster(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Bridge{LinkAttrs: LinkAttrs{Name: "foo"}}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}

	newmaster := &Bridge{LinkAttrs: LinkAttrs{Name: "bar"}}
	if err := LinkAdd(newmaster); err != nil {
		t.Fatal(err)
	}

	testLinkSetUnsetResetMaster(t, master, newmaster)

	if err := LinkDel(newmaster); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetUnsetResetMasterBond(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := NewLinkBond(LinkAttrs{Name: "foo"})
	master.Mode = BOND_MODE_BALANCE_RR
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}

	newmaster := NewLinkBond(LinkAttrs{Name: "bar"})
	newmaster.Mode = BOND_MODE_BALANCE_RR
	if err := LinkAdd(newmaster); err != nil {
		t.Fatal(err)
	}

	testLinkSetUnsetResetMaster(t, master, newmaster)

	if err := LinkDel(newmaster); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetNs(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	basens, err := netns.Get()
	if err != nil {
		t.Fatal("Failed to get basens")
	}
	defer basens.Close()

	newns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns")
	}
	defer newns.Close()

	link := &Veth{LinkAttrs{Name: "foo"}, "bar", nil, nil}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	peer, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	LinkSetNsFd(peer, int(basens))
	if err != nil {
		t.Fatal("Failed to set newns for link")
	}

	_, err = LinkByName("bar")
	if err == nil {
		t.Fatal("Link bar is still in newns")
	}

	err = netns.Set(basens)
	if err != nil {
		t.Fatal("Failed to set basens")
	}

	peer, err = LinkByName("bar")
	if err != nil {
		t.Fatal("Link is not in basens")
	}

	if err := LinkDel(peer); err != nil {
		t.Fatal(err)
	}

	err = netns.Set(newns)
	if err != nil {
		t.Fatal("Failed to set newns")
	}

	_, err = LinkByName("foo")
	if err == nil {
		t.Fatal("Other half of veth pair not deleted")
	}

}

func TestLinkAddDelWireguard(t *testing.T) {
	minKernelRequired(t, 5, 6)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Wireguard{LinkAttrs: LinkAttrs{Name: "wg0"}})
}

func TestVethPeerNs(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	basens, err := netns.Get()
	if err != nil {
		t.Fatal("Failed to get basens")
	}
	defer basens.Close()

	newns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns")
	}
	defer newns.Close()

	link := &Veth{LinkAttrs{Name: "foo"}, "bar", nil, NsFd(basens)}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	_, err = LinkByName("bar")
	if err == nil {
		t.Fatal("Link bar is in newns")
	}

	err = netns.Set(basens)
	if err != nil {
		t.Fatal("Failed to set basens")
	}

	_, err = LinkByName("bar")
	if err != nil {
		t.Fatal("Link bar is not in basens")
	}

	err = netns.Set(newns)
	if err != nil {
		t.Fatal("Failed to set newns")
	}

	_, err = LinkByName("foo")
	if err != nil {
		t.Fatal("Link foo is not in newns")
	}
}

func TestVethPeerNs2(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	basens, err := netns.Get()
	if err != nil {
		t.Fatal("Failed to get basens")
	}
	defer basens.Close()

	onens, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns")
	}
	defer onens.Close()

	twons, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create twons")
	}
	defer twons.Close()

	link := &Veth{LinkAttrs{Name: "foo", Namespace: NsFd(onens)}, "bar", nil, NsFd(basens)}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	_, err = LinkByName("foo")
	if err == nil {
		t.Fatal("Link foo is in twons")
	}

	_, err = LinkByName("bar")
	if err == nil {
		t.Fatal("Link bar is in twons")
	}

	err = netns.Set(basens)
	if err != nil {
		t.Fatal("Failed to set basens")
	}

	_, err = LinkByName("bar")
	if err != nil {
		t.Fatal("Link bar is not in basens")
	}

	err = netns.Set(onens)
	if err != nil {
		t.Fatal("Failed to set onens")
	}

	_, err = LinkByName("foo")
	if err != nil {
		t.Fatal("Link foo is not in onens")
	}
}

func TestLinkAddDelVxlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{
		LinkAttrs{Name: "foo"},
	}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	vxlan := Vxlan{
		LinkAttrs: LinkAttrs{
			Name: "bar",
		},
		VxlanId:      10,
		VtepDevIndex: parent.Index,
		Learning:     true,
		L2miss:       true,
		L3miss:       true,
	}

	testLinkAddDel(t, &vxlan)
	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelVxlanUdpCSum6(t *testing.T) {
	minKernelRequired(t, 3, 16)
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{
		LinkAttrs{Name: "foo"},
	}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	vxlan := Vxlan{
		LinkAttrs: LinkAttrs{
			Name: "bar",
		},
		VxlanId:        10,
		VtepDevIndex:   parent.Index,
		Learning:       true,
		L2miss:         true,
		L3miss:         true,
		UDP6ZeroCSumTx: true,
		UDP6ZeroCSumRx: true,
	}

	testLinkAddDel(t, &vxlan)
	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelVxlanGbp(t *testing.T) {
	minKernelRequired(t, 4, 0)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{
		LinkAttrs{Name: "foo"},
	}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	vxlan := Vxlan{
		LinkAttrs: LinkAttrs{
			Name: "bar",
		},
		VxlanId:        10,
		VtepDevIndex:   parent.Index,
		Learning:       true,
		L2miss:         true,
		L3miss:         true,
		UDP6ZeroCSumTx: true,
		UDP6ZeroCSumRx: true,
		GBP:            true,
	}

	testLinkAddDel(t, &vxlan)
	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelVxlanFlowBased(t *testing.T) {
	minKernelRequired(t, 4, 3)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	vxlan := Vxlan{
		LinkAttrs: LinkAttrs{
			Name: "foo",
		},
		Learning:  false,
		FlowBased: true,
	}

	testLinkAddDel(t, &vxlan)
}

func TestLinkAddDelIPVlanL2(t *testing.T) {
	minKernelRequired(t, 4, 2)
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	ipv := IPVlan{
		LinkAttrs: LinkAttrs{
			Name:        "bar",
			ParentIndex: parent.Index,
		},
		Mode: IPVLAN_MODE_L2,
	}

	testLinkAddDel(t, &ipv)
}

func TestLinkAddDelIPVlanL3(t *testing.T) {
	minKernelRequired(t, 4, 2)
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	ipv := IPVlan{
		LinkAttrs: LinkAttrs{
			Name:        "bar",
			ParentIndex: parent.Index,
		},
		Mode: IPVLAN_MODE_L3,
	}

	testLinkAddDel(t, &ipv)
}

func TestLinkAddDelIPVlanVepa(t *testing.T) {
	minKernelRequired(t, 4, 15)
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	ipv := IPVlan{
		LinkAttrs: LinkAttrs{
			Name:        "bar",
			ParentIndex: parent.Index,
		},
		Mode: IPVLAN_MODE_L3,
		Flag: IPVLAN_FLAG_VEPA,
	}

	testLinkAddDel(t, &ipv)
}

func TestLinkAddDelIPVlanNoParent(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ipv := IPVlan{
		LinkAttrs: LinkAttrs{
			Name: "bar",
		},
		Mode: IPVLAN_MODE_L3,
	}
	err := LinkAdd(&ipv)
	if err == nil {
		t.Fatal("Add should fail if ipvlan creating without ParentIndex")
	}
	if err.Error() != "Can't create ipvlan link without ParentIndex" {
		t.Fatalf("Error should be about missing ParentIndex, got %q", err)
	}
}

func TestLinkByIndex(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	dummy := &Dummy{LinkAttrs{Name: "dummy"}}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}

	found, err := LinkByIndex(dummy.Index)
	if err != nil {
		t.Fatal(err)
	}

	if found.Attrs().Index != dummy.Attrs().Index {
		t.Fatalf("Indices don't match: %v != %v", found.Attrs().Index, dummy.Attrs().Index)
	}

	LinkDel(dummy)

	// test not found
	_, err = LinkByIndex(dummy.Attrs().Index)
	if err == nil {
		t.Fatalf("LinkByIndex(%v) found deleted link", err)
	}
}

func TestLinkSet(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	iface := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(iface); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	err = LinkSetName(link, "bar")
	if err != nil {
		t.Fatalf("Could not change interface name: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatalf("Interface name not changed: %v", err)
	}

	err = LinkSetMTU(link, 1400)
	if err != nil {
		t.Fatalf("Could not set MTU: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MTU != 1400 {
		t.Fatal("MTU not changed")
	}

	err = LinkSetTxQLen(link, 500)
	if err != nil {
		t.Fatalf("Could not set txqlen: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().TxQLen != 500 {
		t.Fatal("txqlen not changed")
	}

	addr, err := net.ParseMAC("00:12:34:56:78:AB")
	if err != nil {
		t.Fatal(err)
	}

	err = LinkSetHardwareAddr(link, addr)
	if err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(link.Attrs().HardwareAddr, addr) {
		t.Fatalf("hardware address not changed")
	}

	err = LinkSetAlias(link, "barAlias")
	if err != nil {
		t.Fatalf("Could not set alias: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().Alias != "barAlias" {
		t.Fatalf("alias not changed")
	}

	link, err = LinkByAlias("barAlias")
	if err != nil {
		t.Fatal(err)
	}

	err = LinkSetGroup(link, 42)
	if err != nil {
		t.Fatalf("Could not set group: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().Group != 42 {
		t.Fatal("Link group not changed")
	}
}

func TestLinkSetARP(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	iface := &Veth{LinkAttrs: LinkAttrs{Name: "foo", TxQLen: testTxQLen, MTU: 1500}, PeerName: "banana"}
	if err := LinkAdd(iface); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	err = LinkSetARPOff(link)
	if err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().RawFlags&unix.IFF_NOARP != uint32(unix.IFF_NOARP) {
		t.Fatalf("NOARP was not set")
	}

	err = LinkSetARPOn(link)
	if err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().RawFlags&unix.IFF_NOARP != 0 {
		t.Fatalf("NOARP is still set")
	}
}

func expectLinkUpdate(ch <-chan LinkUpdate, ifaceName string, up bool) bool {
	for {
		timeout := time.After(time.Minute)
		select {
		case update := <-ch:
			if ifaceName == update.Link.Attrs().Name && (update.IfInfomsg.Flags&unix.IFF_UP != 0) == up {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestLinkSubscribe(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := LinkSubscribe(ch, done); err != nil {
		t.Fatal(err)
	}

	link := &Veth{LinkAttrs{Name: "foo", TxQLen: testTxQLen, MTU: 1400}, "bar", nil, nil}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "foo", false) {
		t.Fatal("Add update not received as expected")
	}

	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "foo", true) {
		t.Fatal("Link Up update not received as expected")
	}

	if err := LinkDel(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "foo", false) {
		t.Fatal("Del update not received as expected")
	}
}

func TestLinkSubscribeWithOptions(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	var lastError error
	defer func() {
		if lastError != nil {
			t.Fatalf("Fatal error received during subscription: %v", lastError)
		}
	}()
	if err := LinkSubscribeWithOptions(ch, done, LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			lastError = err
		},
	}); err != nil {
		t.Fatal(err)
	}

	link := &Veth{LinkAttrs{Name: "foo", TxQLen: testTxQLen, MTU: 1400}, "bar", nil, nil}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "foo", false) {
		t.Fatal("Add update not received as expected")
	}
}

func TestLinkSubscribeAt(t *testing.T) {
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

	// Subscribe for Link events on the custom netns
	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := LinkSubscribeAt(newNs, ch, done); err != nil {
		t.Fatal(err)
	}

	link := &Veth{LinkAttrs{Name: "test", TxQLen: testTxQLen, MTU: 1400}, "bar", nil, nil}
	if err := nh.LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", false) {
		t.Fatal("Add update not received as expected")
	}

	if err := nh.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", true) {
		t.Fatal("Link Up update not received as expected")
	}

	if err := nh.LinkDel(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", false) {
		t.Fatal("Del update not received as expected")
	}
}

func TestLinkSubscribeListExisting(t *testing.T) {
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

	link := &Veth{LinkAttrs{Name: "test", TxQLen: testTxQLen, MTU: 1400}, "bar", nil, nil}
	if err := nh.LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	// Subscribe for Link events on the custom netns
	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := LinkSubscribeWithOptions(ch, done, LinkSubscribeOptions{
		Namespace:    &newNs,
		ListExisting: true},
	); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", false) {
		t.Fatal("Add update not received as expected")
	}

	if err := nh.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", true) {
		t.Fatal("Link Up update not received as expected")
	}

	if err := nh.LinkDel(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", false) {
		t.Fatal("Del update not received as expected")
	}
}

func TestLinkStats(t *testing.T) {
	defer setUpNetlinkTest(t)()

	// Create a veth pair and verify the cross-stats once both
	// ends are brought up and some ICMPv6 packets are exchanged
	v0 := "v0"
	v1 := "v1"

	vethLink := &Veth{LinkAttrs: LinkAttrs{Name: v0}, PeerName: v1}
	if err := LinkAdd(vethLink); err != nil {
		t.Fatal(err)
	}

	veth0, err := LinkByName(v0)
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(veth0); err != nil {
		t.Fatal(err)
	}

	veth1, err := LinkByName(v1)
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(veth1); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	// verify statistics
	veth0, err = LinkByName(v0)
	if err != nil {
		t.Fatal(err)
	}
	veth1, err = LinkByName(v1)
	if err != nil {
		t.Fatal(err)
	}
	v0Stats := veth0.Attrs().Statistics
	v1Stats := veth1.Attrs().Statistics
	if v0Stats.RxPackets != v1Stats.TxPackets || v0Stats.TxPackets != v1Stats.RxPackets ||
		v0Stats.RxBytes != v1Stats.TxBytes || v0Stats.TxBytes != v1Stats.RxBytes {
		t.Fatalf("veth ends counters differ:\n%v\n%v", v0Stats, v1Stats)
	}
}

func TestLinkXdp(t *testing.T) {
	links, err := LinkList()
	if err != nil {
		t.Fatal(err)
	}
	var testXdpLink Link
	for _, link := range links {
		if link.Attrs().Xdp != nil && !link.Attrs().Xdp.Attached {
			testXdpLink = link
			break
		}
	}
	if testXdpLink == nil {
		t.Skipf("No link supporting XDP found")
	}
	fd, err := loadSimpleBpf(BPF_PROG_TYPE_XDP, 2 /*XDP_PASS*/)
	if err != nil {
		t.Skipf("Loading bpf program failed: %s", err)
	}
	if err := LinkSetXdpFd(testXdpLink, fd); err != nil {
		t.Fatal(err)
	}
	if err := LinkSetXdpFdWithFlags(testXdpLink, fd, nl.XDP_FLAGS_UPDATE_IF_NOEXIST); err != unix.EBUSY {
		t.Fatal(err)
	}
	if err := LinkSetXdpFd(testXdpLink, -1); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelIptun(t *testing.T) {
	minKernelRequired(t, 4, 9)
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Iptun{
		LinkAttrs: LinkAttrs{Name: "iptunfoo"},
		PMtuDisc:  1,
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})
}

func TestLinkAddDelIp6tnl(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Ip6tnl{
		LinkAttrs: LinkAttrs{Name: "ip6tnltest"},
		Local:     net.ParseIP("2001:db8::100"),
		Remote:    net.ParseIP("2001:db8::200"),
	})
}

func TestLinkAddDelSittun(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Sittun{
		LinkAttrs: LinkAttrs{Name: "sittunfoo"},
		PMtuDisc:  1,
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})
}

func TestLinkAddDelVti(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Vti{
		LinkAttrs: LinkAttrs{Name: "vtifoo"},
		IKey:      0x101,
		OKey:      0x101,
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})

	testLinkAddDel(t, &Vti{
		LinkAttrs: LinkAttrs{Name: "vtibar"},
		IKey:      0x101,
		OKey:      0x101,
		Local:     net.IPv6loopback,
		Remote:    net.IPv6loopback})
}

func TestBridgeCreationWithMulticastSnooping(t *testing.T) {
	minKernelRequired(t, 4, 4)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	bridgeWithDefaultMcastSnoopName := "foo"
	bridgeWithDefaultMcastSnoop := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithDefaultMcastSnoopName}}
	if err := LinkAdd(bridgeWithDefaultMcastSnoop); err != nil {
		t.Fatal(err)
	}
	expectMcastSnooping(t, bridgeWithDefaultMcastSnoopName, true)
	if err := LinkDel(bridgeWithDefaultMcastSnoop); err != nil {
		t.Fatal(err)
	}

	mcastSnoop := true
	bridgeWithMcastSnoopOnName := "bar"
	bridgeWithMcastSnoopOn := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithMcastSnoopOnName}, MulticastSnooping: &mcastSnoop}
	if err := LinkAdd(bridgeWithMcastSnoopOn); err != nil {
		t.Fatal(err)
	}
	expectMcastSnooping(t, bridgeWithMcastSnoopOnName, true)
	if err := LinkDel(bridgeWithMcastSnoopOn); err != nil {
		t.Fatal(err)
	}

	mcastSnoop = false
	bridgeWithMcastSnoopOffName := "foobar"
	bridgeWithMcastSnoopOff := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithMcastSnoopOffName}, MulticastSnooping: &mcastSnoop}
	if err := LinkAdd(bridgeWithMcastSnoopOff); err != nil {
		t.Fatal(err)
	}
	expectMcastSnooping(t, bridgeWithMcastSnoopOffName, false)
	if err := LinkDel(bridgeWithMcastSnoopOff); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeSetMcastSnoop(t *testing.T) {
	minKernelRequired(t, 4, 4)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	bridgeName := "foo"
	bridge := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeName}}
	if err := LinkAdd(bridge); err != nil {
		t.Fatal(err)
	}
	expectMcastSnooping(t, bridgeName, true)

	if err := BridgeSetMcastSnoop(bridge, false); err != nil {
		t.Fatal(err)
	}
	expectMcastSnooping(t, bridgeName, false)

	if err := BridgeSetMcastSnoop(bridge, true); err != nil {
		t.Fatal(err)
	}
	expectMcastSnooping(t, bridgeName, true)

	if err := LinkDel(bridge); err != nil {
		t.Fatal(err)
	}
}

func expectMcastSnooping(t *testing.T, linkName string, expected bool) {
	bridge, err := LinkByName(linkName)
	if err != nil {
		t.Fatal(err)
	}

	if actual := *bridge.(*Bridge).MulticastSnooping; actual != expected {
		t.Fatalf("expected %t got %t", expected, actual)
	}
}

func TestBridgeSetVlanFiltering(t *testing.T) {
	minKernelRequired(t, 4, 4)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	bridgeName := "foo"
	bridge := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeName}}
	if err := LinkAdd(bridge); err != nil {
		t.Fatal(err)
	}
	expectVlanFiltering(t, bridgeName, false)

	if err := BridgeSetVlanFiltering(bridge, true); err != nil {
		t.Fatal(err)
	}
	expectVlanFiltering(t, bridgeName, true)

	if err := BridgeSetVlanFiltering(bridge, false); err != nil {
		t.Fatal(err)
	}
	expectVlanFiltering(t, bridgeName, false)

	if err := LinkDel(bridge); err != nil {
		t.Fatal(err)
	}
}

func expectVlanFiltering(t *testing.T, linkName string, expected bool) {
	bridge, err := LinkByName(linkName)
	if err != nil {
		t.Fatal(err)
	}

	if actual := *bridge.(*Bridge).VlanFiltering; actual != expected {
		t.Fatalf("expected %t got %t", expected, actual)
	}
}

func TestBridgeCreationWithAgeingTime(t *testing.T) {
	minKernelRequired(t, 3, 18)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	bridgeWithSpecifiedAgeingTimeName := "foo"
	ageingTime := uint32(20000)
	bridgeWithSpecifiedAgeingTime := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithSpecifiedAgeingTimeName}, AgeingTime: &ageingTime}
	if err := LinkAdd(bridgeWithSpecifiedAgeingTime); err != nil {
		t.Fatal(err)
	}

	retrievedBridge, err := LinkByName(bridgeWithSpecifiedAgeingTimeName)
	if err != nil {
		t.Fatal(err)
	}

	actualAgeingTime := *retrievedBridge.(*Bridge).AgeingTime
	if actualAgeingTime != ageingTime {
		t.Fatalf("expected %d got %d", ageingTime, actualAgeingTime)
	}
	if err := LinkDel(bridgeWithSpecifiedAgeingTime); err != nil {
		t.Fatal(err)
	}

	bridgeWithDefaultAgeingTimeName := "bar"
	bridgeWithDefaultAgeingTime := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithDefaultAgeingTimeName}}
	if err := LinkAdd(bridgeWithDefaultAgeingTime); err != nil {
		t.Fatal(err)
	}

	retrievedBridge, err = LinkByName(bridgeWithDefaultAgeingTimeName)
	if err != nil {
		t.Fatal(err)
	}

	actualAgeingTime = *retrievedBridge.(*Bridge).AgeingTime
	if actualAgeingTime != 30000 {
		t.Fatalf("expected %d got %d", 30000, actualAgeingTime)
	}
	if err := LinkDel(bridgeWithDefaultAgeingTime); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeCreationWithHelloTime(t *testing.T) {
	minKernelRequired(t, 3, 18)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	bridgeWithSpecifiedHelloTimeName := "foo"
	helloTime := uint32(300)
	bridgeWithSpecifiedHelloTime := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithSpecifiedHelloTimeName}, HelloTime: &helloTime}
	if err := LinkAdd(bridgeWithSpecifiedHelloTime); err != nil {
		t.Fatal(err)
	}

	retrievedBridge, err := LinkByName(bridgeWithSpecifiedHelloTimeName)
	if err != nil {
		t.Fatal(err)
	}

	actualHelloTime := *retrievedBridge.(*Bridge).HelloTime
	if actualHelloTime != helloTime {
		t.Fatalf("expected %d got %d", helloTime, actualHelloTime)
	}
	if err := LinkDel(bridgeWithSpecifiedHelloTime); err != nil {
		t.Fatal(err)
	}

	bridgeWithDefaultHelloTimeName := "bar"
	bridgeWithDefaultHelloTime := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithDefaultHelloTimeName}}
	if err := LinkAdd(bridgeWithDefaultHelloTime); err != nil {
		t.Fatal(err)
	}

	retrievedBridge, err = LinkByName(bridgeWithDefaultHelloTimeName)
	if err != nil {
		t.Fatal(err)
	}

	actualHelloTime = *retrievedBridge.(*Bridge).HelloTime
	if actualHelloTime != 200 {
		t.Fatalf("expected %d got %d", 200, actualHelloTime)
	}
	if err := LinkDel(bridgeWithDefaultHelloTime); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeCreationWithVlanFiltering(t *testing.T) {
	minKernelRequired(t, 3, 18)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	bridgeWithVlanFilteringEnabledName := "foo"
	vlanFiltering := true
	bridgeWithVlanFilteringEnabled := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithVlanFilteringEnabledName}, VlanFiltering: &vlanFiltering}
	if err := LinkAdd(bridgeWithVlanFilteringEnabled); err != nil {
		t.Fatal(err)
	}

	retrievedBridge, err := LinkByName(bridgeWithVlanFilteringEnabledName)
	if err != nil {
		t.Fatal(err)
	}

	retrievedVlanFilteringState := *retrievedBridge.(*Bridge).VlanFiltering
	if retrievedVlanFilteringState != vlanFiltering {
		t.Fatalf("expected %t got %t", vlanFiltering, retrievedVlanFilteringState)
	}
	if err := LinkDel(bridgeWithVlanFilteringEnabled); err != nil {
		t.Fatal(err)
	}

	bridgeWithDefaultVlanFilteringName := "bar"
	bridgeWIthDefaultVlanFiltering := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeWithDefaultVlanFilteringName}}
	if err := LinkAdd(bridgeWIthDefaultVlanFiltering); err != nil {
		t.Fatal(err)
	}

	retrievedBridge, err = LinkByName(bridgeWithDefaultVlanFilteringName)
	if err != nil {
		t.Fatal(err)
	}

	retrievedVlanFilteringState = *retrievedBridge.(*Bridge).VlanFiltering
	if retrievedVlanFilteringState != false {
		t.Fatalf("expected %t got %t", false, retrievedVlanFilteringState)
	}
	if err := LinkDel(bridgeWIthDefaultVlanFiltering); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSubscribeWithProtinfo(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Bridge{LinkAttrs: LinkAttrs{Name: "foo"}}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}

	slave := &Veth{
		LinkAttrs: LinkAttrs{
			Name:        "bar",
			TxQLen:      testTxQLen,
			MTU:         1400,
			MasterIndex: master.Attrs().Index,
		},
		PeerName: "bar-peer",
	}
	if err := LinkAdd(slave); err != nil {
		t.Fatal(err)
	}

	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := LinkSubscribe(ch, done); err != nil {
		t.Fatal(err)
	}

	if err := LinkSetHairpin(slave, true); err != nil {
		t.Fatal(err)
	}

	select {
	case update := <-ch:
		if !(update.Attrs().Name == "bar" && update.Attrs().Protinfo != nil &&
			update.Attrs().Protinfo.Hairpin) {
			t.Fatal("Hairpin update not received as expected")
		}
	case <-time.After(time.Minute):
		t.Fatal("Hairpin update timed out")
	}

	if err := LinkDel(slave); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func testGTPLink(t *testing.T) *GTP {
	conn1, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 3386,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 2152,
	})
	if err != nil {
		t.Fatal(err)
	}
	fd1, _ := conn1.File()
	fd2, _ := conn2.File()
	return &GTP{
		LinkAttrs: LinkAttrs{
			Name: "gtp0",
		},
		FD0: int(fd1.Fd()),
		FD1: int(fd2.Fd()),
	}
}

func TestLinkAddDelGTP(t *testing.T) {
	tearDown := setUpNetlinkTestWithKModule(t, "gtp")
	defer tearDown()
	gtp := testGTPLink(t)
	testLinkAddDel(t, gtp)
}

func TestLinkAddDelXfrmi(t *testing.T) {
	minKernelRequired(t, 4, 19)
	defer setUpNetlinkTest(t)()

	lo, _ := LinkByName("lo")

	testLinkAddDel(t, &Xfrmi{
		LinkAttrs: LinkAttrs{Name: "xfrm123", ParentIndex: lo.Attrs().Index},
		Ifid:      123})
}

func TestLinkAddDelXfrmiNoId(t *testing.T) {
	minKernelRequired(t, 4, 19)
	defer setUpNetlinkTest(t)()

	lo, _ := LinkByName("lo")

	testLinkAddDel(t, &Xfrmi{
		LinkAttrs: LinkAttrs{Name: "xfrm0", ParentIndex: lo.Attrs().Index}})
}

func TestLinkByNameWhenLinkIsNotFound(t *testing.T) {
	_, err := LinkByName("iammissing")
	if err == nil {
		t.Fatal("Link not expected to found")
	}

	_, ok := err.(LinkNotFoundError)
	if !ok {
		t.Errorf("Error returned expected to of LinkNotFoundError type: %v", err)
	}
}

func TestLinkByAliasWhenLinkIsNotFound(t *testing.T) {
	_, err := LinkByAlias("iammissing")
	if err == nil {
		t.Fatal("Link not expected to found")
	}

	_, ok := err.(LinkNotFoundError)
	if !ok {
		t.Errorf("Error returned expected to of LinkNotFoundError type: %v", err)
	}
}

func TestLinkAddDelTuntap(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// Mount sysfs so that sysfs gets the namespace tag of the current network namespace
	// This is necessary so that /sys shows the network interfaces of the current namespace.
	if err := syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_RDONLY, ""); err != nil {
		t.Fatal("Cannot mount sysfs")
	}

	defer func() {
		if err := syscall.Unmount("/sys", 0); err != nil {
			t.Fatal("Cannot umount /sys")
		}
	}()

	testLinkAddDel(t, &Tuntap{
		LinkAttrs: LinkAttrs{Name: "foo"},
		Mode:      TUNTAP_MODE_TAP})
}

func TestLinkAddDelTuntapMq(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	if err := syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_RDONLY, ""); err != nil {
		t.Fatal("Cannot mount sysfs")
	}

	defer func() {
		if err := syscall.Unmount("/sys", 0); err != nil {
			t.Fatal("Cannot umount /sys")
		}
	}()

	testLinkAddDel(t, &Tuntap{
		LinkAttrs: LinkAttrs{Name: "foo"},
		Mode:      TUNTAP_MODE_TAP,
		Queues:    4})

	testLinkAddDel(t, &Tuntap{
		LinkAttrs: LinkAttrs{Name: "foo"},
		Mode:      TUNTAP_MODE_TAP,
		Queues:    4,
		Flags:     TUNTAP_MULTI_QUEUE_DEFAULTS | TUNTAP_VNET_HDR})
}

func TestLinkAddDelTuntapOwnerGroup(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	if err := syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_RDONLY, ""); err != nil {
		t.Fatal("Cannot mount sysfs")
	}

	defer func() {
		if err := syscall.Unmount("/sys", 0); err != nil {
			t.Fatal("Cannot umount /sys")
		}
	}()

	testLinkAddDel(t, &Tuntap{
		LinkAttrs: LinkAttrs{Name: "foo"},
		Mode:      TUNTAP_MODE_TAP,
		Owner:     0,
		Group:     0,
	})
}

func TestVethPeerIndex(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	const (
		vethPeer1 = "vethOne"
		vethPeer2 = "vethTwo"
	)

	link := &Veth{
		LinkAttrs: LinkAttrs{
			Name:  vethPeer1,
			MTU:   1500,
			Flags: net.FlagUp,
		},
		PeerName: vethPeer2,
	}

	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	linkOne, err := LinkByName("vethOne")
	if err != nil {
		t.Fatal(err)
	}

	linkTwo, err := LinkByName("vethTwo")
	if err != nil {
		t.Fatal(err)
	}

	peerIndexOne, err := VethPeerIndex(&Veth{LinkAttrs: *linkOne.Attrs()})
	if err != nil {
		t.Fatal(err)
	}

	peerIndexTwo, err := VethPeerIndex(&Veth{LinkAttrs: *linkTwo.Attrs()})
	if err != nil {
		t.Fatal(err)
	}

	if peerIndexOne != linkTwo.Attrs().Index {
		t.Errorf("VethPeerIndex(%s) mismatch %d != %d", linkOne.Attrs().Name, peerIndexOne, linkTwo.Attrs().Index)
	}

	if peerIndexTwo != linkOne.Attrs().Index {
		t.Errorf("VethPeerIndex(%s) mismatch %d != %d", linkTwo.Attrs().Name, peerIndexTwo, linkOne.Attrs().Index)
	}
}

func TestLinkSlaveBond(t *testing.T) {
	minKernelRequired(t, 3, 13)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	const (
		bondName  = "foo"
		slaveName = "fooFoo"
	)

	bond := NewLinkBond(LinkAttrs{Name: bondName})
	bond.Mode = BOND_MODE_BALANCE_RR
	if err := LinkAdd(bond); err != nil {
		t.Fatal(err)
	}
	defer LinkDel(bond)

	slaveDummy := &Dummy{LinkAttrs{Name: slaveName}}
	if err := LinkAdd(slaveDummy); err != nil {
		t.Fatal(err)
	}
	defer LinkDel(slaveDummy)

	if err := LinkSetBondSlave(slaveDummy, bond); err != nil {
		t.Fatal(err)
	}

	slaveLink, err := LinkByName(slaveName)
	if err != nil {
		t.Fatal(err)
	}

	slave := slaveLink.Attrs().Slave
	if slave == nil {
		t.Errorf("for %s expected slave is not nil.", slaveName)
	}

	if slaveType := slave.SlaveType(); slaveType != "bond" {
		t.Errorf("for %s expected slave type is 'bond', but '%s'", slaveName, slaveType)
	}
}

func TestLinkSetBondSlaveQueueId(t *testing.T) {
	minKernelRequired(t, 3, 13)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	const (
		bondName   = "foo"
		slave1Name = "fooFoo"
	)

	bond := NewLinkBond(LinkAttrs{Name: bondName})
	if err := LinkAdd(bond); err != nil {
		t.Fatal(err)
	}
	defer LinkDel(bond)

	slave := &Dummy{LinkAttrs{Name: slave1Name}}
	if err := LinkAdd(slave); err != nil {
		t.Fatal(err)
	}
	defer LinkDel(slave)

	if err := LinkSetBondSlave(slave, bond); err != nil {
		t.Fatal(err)
	}

	if err := pkgHandle.LinkSetBondSlaveQueueId(slave, 1); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetBondSlave(t *testing.T) {
	minKernelRequired(t, 3, 13)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	const (
		bondName     = "foo"
		slaveOneName = "fooFoo"
		slaveTwoName = "fooBar"
	)

	bond := NewLinkBond(LinkAttrs{Name: bondName})
	bond.Mode = StringToBondModeMap["802.3ad"]
	bond.AdSelect = BondAdSelect(BOND_AD_SELECT_BANDWIDTH)
	bond.AdActorSysPrio = 1
	bond.AdUserPortKey = 1
	bond.AdActorSystem, _ = net.ParseMAC("06:aa:bb:cc:dd:ee")

	if err := LinkAdd(bond); err != nil {
		t.Fatal(err)
	}

	bondLink, err := LinkByName(bondName)
	if err != nil {
		t.Fatal(err)
	}
	defer LinkDel(bondLink)

	if err := LinkAdd(&Dummy{LinkAttrs{Name: slaveOneName}}); err != nil {
		t.Fatal(err)
	}

	slaveOneLink, err := LinkByName(slaveOneName)
	if err != nil {
		t.Fatal(err)
	}
	defer LinkDel(slaveOneLink)

	if err := LinkAdd(&Dummy{LinkAttrs{Name: slaveTwoName}}); err != nil {
		t.Fatal(err)
	}
	slaveTwoLink, err := LinkByName(slaveTwoName)
	if err != nil {
		t.Fatal(err)
	}
	defer LinkDel(slaveTwoLink)

	if err := LinkSetBondSlave(slaveOneLink, &Bond{LinkAttrs: *bondLink.Attrs()}); err != nil {
		t.Fatal(err)
	}

	if err := LinkSetBondSlave(slaveTwoLink, &Bond{LinkAttrs: *bondLink.Attrs()}); err != nil {
		t.Fatal(err)
	}

	// Update info about interfaces
	slaveOneLink, err = LinkByName(slaveOneName)
	if err != nil {
		t.Fatal(err)
	}

	slaveTwoLink, err = LinkByName(slaveTwoName)
	if err != nil {
		t.Fatal(err)
	}

	if slaveOneLink.Attrs().MasterIndex != bondLink.Attrs().Index {
		t.Errorf("For %s expected %s to be master", slaveOneLink.Attrs().Name, bondLink.Attrs().Name)
	}

	if slaveTwoLink.Attrs().MasterIndex != bondLink.Attrs().Index {
		t.Errorf("For %s expected %s to be master", slaveTwoLink.Attrs().Name, bondLink.Attrs().Name)
	}
}

func TestLinkSetAllmulticast(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	iface := &Veth{LinkAttrs: LinkAttrs{Name: "foo"}, PeerName: "bar"}
	if err := LinkAdd(iface); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if err := LinkSetAllmulticastOn(link); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().Allmulti != 1 {
		t.Fatal("IFF_ALLMULTI was not set")
	}

	if err := LinkSetAllmulticastOff(link); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().Allmulti != 0 {
		t.Fatal("IFF_ALLMULTI is still set")
	}
}

func TestLinkSetMulticast(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	iface := &Veth{LinkAttrs: LinkAttrs{Name: "foo"}, PeerName: "bar"}
	if err := LinkAdd(iface); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if err := LinkSetMulticastOn(link); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().Multi != 1 {
		t.Fatal("IFF_MULTICAST was not set")
	}

	if err := LinkSetMulticastOff(link); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().Multi != 0 {
		t.Fatal("IFF_MULTICAST is still set")
	}
}

func TestLinkSetMacvlanMode(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	const (
		parentName  = "foo"
		macvlanName = "fooFoo"
		macvtapName = "fooBar"
	)

	parent := &Dummy{LinkAttrs{Name: parentName}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}
	defer LinkDel(parent)

	testMacvlanMode := func(link Link, mode MacvlanMode) {
		if err := LinkSetMacvlanMode(link, mode); err != nil {
			t.Fatal(err)
		}

		name := link.Attrs().Name
		result, err := LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}

		var actual MacvlanMode
		switch l := result.(type) {
		case *Macvlan:
			actual = l.Mode
		case *Macvtap:
			actual = l.Macvlan.Mode
		}

		if actual != mode {
			t.Fatalf("expected %v got %v for %+v", mode, actual, link)
		}
	}

	macvlan := &Macvlan{
		LinkAttrs: LinkAttrs{Name: macvlanName, ParentIndex: parent.Attrs().Index},
		Mode:      MACVLAN_MODE_BRIDGE,
	}
	if err := LinkAdd(macvlan); err != nil {
		t.Fatal(err)
	}
	defer LinkDel(macvlan)

	testMacvlanMode(macvlan, MACVLAN_MODE_VEPA)
	testMacvlanMode(macvlan, MACVLAN_MODE_PRIVATE)
	testMacvlanMode(macvlan, MACVLAN_MODE_SOURCE)
	testMacvlanMode(macvlan, MACVLAN_MODE_BRIDGE)

	macvtap := &Macvtap{
		Macvlan: Macvlan{
			LinkAttrs: LinkAttrs{Name: macvtapName, ParentIndex: parent.Attrs().Index},
			Mode:      MACVLAN_MODE_BRIDGE,
		},
	}
	if err := LinkAdd(macvtap); err != nil {
		t.Fatal(err)
	}
	defer LinkDel(macvtap)

	testMacvlanMode(macvtap, MACVLAN_MODE_VEPA)
	testMacvlanMode(macvtap, MACVLAN_MODE_PRIVATE)
	testMacvlanMode(macvtap, MACVLAN_MODE_SOURCE)
	testMacvlanMode(macvtap, MACVLAN_MODE_BRIDGE)
}
