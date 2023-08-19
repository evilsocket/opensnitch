package netlink

import (
	"bytes"
	"github.com/vishvananda/netlink/nl"
	"io/ioutil"
	"net"
	"testing"
)

func TestParseIpsetProtocolResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_protocol_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.Protocol != 6 {
		t.Errorf("expected msg.Protocol to equal 6, got %d", msg.Protocol)
	}
}

func TestParseIpsetListResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_list_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.SetName != "clients" {
		t.Errorf(`expected SetName to equal "clients", got %q`, msg.SetName)
	}
	if msg.TypeName != "hash:mac" {
		t.Errorf(`expected TypeName to equal "hash:mac", got %q`, msg.TypeName)
	}
	if msg.Protocol != 6 {
		t.Errorf("expected Protocol to equal 6, got %d", msg.Protocol)
	}
	if msg.References != 0 {
		t.Errorf("expected References to equal 0, got %d", msg.References)
	}
	if msg.NumEntries != 2 {
		t.Errorf("expected NumEntries to equal 2, got %d", msg.NumEntries)
	}
	if msg.HashSize != 1024 {
		t.Errorf("expected HashSize to equal 1024, got %d", msg.HashSize)
	}
	if *msg.Timeout != 3600 {
		t.Errorf("expected Timeout to equal 3600, got %d", *msg.Timeout)
	}
	if msg.MaxElements != 65536 {
		t.Errorf("expected MaxElements to equal 65536, got %d", msg.MaxElements)
	}
	if msg.CadtFlags != nl.IPSET_FLAG_WITH_COMMENT|nl.IPSET_FLAG_WITH_COUNTERS {
		t.Error("expected CadtFlags to be IPSET_FLAG_WITH_COMMENT and IPSET_FLAG_WITH_COUNTERS")
	}
	if len(msg.Entries) != 2 {
		t.Fatalf("expected 2 Entries, got %d", len(msg.Entries))
	}

	// first entry
	ent := msg.Entries[0]
	if int(*ent.Timeout) != 3577 {
		t.Errorf("expected Timeout for first entry to equal 3577, got %d", *ent.Timeout)
	}
	if int(*ent.Bytes) != 4121 {
		t.Errorf("expected Bytes for first entry to equal 4121, got %d", *ent.Bytes)
	}
	if int(*ent.Packets) != 42 {
		t.Errorf("expected Packets for first entry to equal 42, got %d", *ent.Packets)
	}
	if ent.Comment != "foo bar" {
		t.Errorf("unexpected Comment for first entry: %q", ent.Comment)
	}
	expectedMAC := net.HardwareAddr{0xde, 0xad, 0x0, 0x0, 0xbe, 0xef}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for first entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}

	// second entry
	ent = msg.Entries[1]
	expectedMAC = net.HardwareAddr{0x1, 0x2, 0x3, 0x0, 0x1, 0x2}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for second entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}
}

func TestIpsetCreateListAddDelDestroy(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	timeout := uint32(3)
	err := IpsetCreate("my-test-ipset-1", "hash:ip", IpsetCreateOptions{
		Replace:  true,
		Timeout:  &timeout,
		Counters: true,
		Comments: false,
		Skbinfo:  false,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = IpsetCreate("my-test-ipset-2", "hash:net", IpsetCreateOptions{
		Replace:  true,
		Timeout:  &timeout,
		Counters: false,
		Comments: true,
		Skbinfo:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := IpsetListAll()

	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 IPSets to be created, got %d", len(results))
	}

	if results[0].SetName != "my-test-ipset-1" {
		t.Errorf("expected name to be 'my-test-ipset-1', but got '%s'", results[0].SetName)
	}

	if results[1].SetName != "my-test-ipset-2" {
		t.Errorf("expected name to be 'my-test-ipset-2', but got '%s'", results[1].SetName)
	}

	if results[0].TypeName != "hash:ip" {
		t.Errorf("expected type to be 'hash:ip', but got '%s'", results[0].TypeName)
	}

	if results[1].TypeName != "hash:net" {
		t.Errorf("expected type to be 'hash:net', but got '%s'", results[1].TypeName)
	}

	if *results[0].Timeout != 3 {
		t.Errorf("expected timeout to be 3, but got '%d'", *results[0].Timeout)
	}

	err = IpsetAdd("my-test-ipset-1", &IPSetEntry{
		Comment: "test comment",
		IP:      net.ParseIP("10.99.99.99").To4(),
		Replace: false,
	})

	if err != nil {
		t.Fatal(err)
	}

	result, err := IpsetList("my-test-ipset-1")

	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry be created, got '%d'", len(result.Entries))
	}
	if result.Entries[0].IP.String() != "10.99.99.99" {
		t.Fatalf("expected entry to be '10.99.99.99', got '%s'", result.Entries[0].IP.String())
	}

	if result.Entries[0].Comment != "test comment" {
		// This is only supported in the kernel module from revision 2 or 4, so comments may be ignored.
		t.Logf("expected comment to be 'test comment', got '%s'", result.Entries[0].Comment)
	}

	err = IpsetDel("my-test-ipset-1", &IPSetEntry{
		Comment: "test comment",
		IP:      net.ParseIP("10.99.99.99").To4(),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err = IpsetList("my-test-ipset-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 0 {
		t.Fatalf("expected 0 entries to exist, got %d", len(result.Entries))
	}

	err = IpsetDestroy("my-test-ipset-1")
	if err != nil {
		t.Fatal(err)
	}

	err = IpsetDestroy("my-test-ipset-2")
	if err != nil {
		t.Fatal(err)
	}
}
