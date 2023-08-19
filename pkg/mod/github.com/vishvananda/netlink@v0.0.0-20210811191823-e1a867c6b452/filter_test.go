// +build linux

package netlink

import (
	"net"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFilterAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Ingress)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	classId := MakeHandle(1, 1)
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  unix.ETH_P_IP,
		},
		RedirIndex: redir.Attrs().Index,
		ClassId:    classId,
	}
	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}
	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	u32, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}
	if u32.ClassId != classId {
		t.Fatalf("ClassId of the filter is the wrong value")
	}
	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}
	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterReplace(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}

	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  unix.ETH_P_IP,
		},
		RedirIndex: redir.Attrs().Index,
		ClassId:    MakeHandle(1, 1),
	}

	if err := FilterReplace(filter); err != nil {
		t.Fatal(err)
	}
	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed replace filter")
	}

	if err := FilterReplace(filter); err != nil {
		t.Fatal(err)
	}
}

func TestAdvancedFilterAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "baz"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	index := link.Attrs().Index

	qdiscHandle := MakeHandle(0x1, 0x0)
	qdiscAttrs := QdiscAttrs{
		LinkIndex: index,
		Handle:    qdiscHandle,
		Parent:    HANDLE_ROOT,
	}

	qdisc := NewHtb(qdiscAttrs)
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Htb)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	classId := MakeHandle(0x1, 0x46cb)
	classAttrs := ClassAttrs{
		LinkIndex: index,
		Parent:    qdiscHandle,
		Handle:    classId,
	}
	htbClassAttrs := HtbClassAttrs{
		Rate:   512 * 1024,
		Buffer: 32 * 1024,
	}
	htbClass := NewHtbClass(classAttrs, htbClassAttrs)
	if err = ClassReplace(htbClass); err != nil {
		t.Fatalf("Failed to add a HTB class: %v", err)
	}
	classes, err := SafeClassList(link, qdiscHandle)
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 {
		t.Fatal("Failed to add class")
	}
	_, ok = classes[0].(*HtbClass)
	if !ok {
		t.Fatal("Class is the wrong type")
	}

	htid := MakeHandle(0x0010, 0000)
	divisor := uint32(1)
	hashTable := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: index,
			Handle:    htid,
			Parent:    qdiscHandle,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Divisor: divisor,
	}
	cHashTable := *hashTable
	if err := FilterAdd(hashTable); err != nil {
		t.Fatal(err)
	}
	// Check if the hash table is identical before and after FilterAdd.
	if !reflect.DeepEqual(cHashTable, *hashTable) {
		t.Fatalf("Hash table %v and %v are not equal", cHashTable, *hashTable)
	}

	u32SelKeys := []TcU32Key{
		{
			Mask:    0xff,
			Val:     80,
			Off:     20,
			OffMask: 0,
		},
		{
			Mask:    0xffff,
			Val:     0x146ca,
			Off:     32,
			OffMask: 0,
		},
	}

	handle := MakeHandle(0x0000, 0001)
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: index,
			Handle:    handle,
			Parent:    qdiscHandle,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Sel: &TcU32Sel{
			Keys:  u32SelKeys,
			Flags: TC_U32_TERMINAL,
		},
		ClassId: classId,
		Hash:    htid,
		Actions: []Action{},
	}
	// Copy filter.
	cFilter := *filter
	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}
	// Check if the filter is identical before and after FilterAdd.
	if !reflect.DeepEqual(cFilter, *filter) {
		t.Fatalf("U32 %v and %v are not equal", cFilter, *filter)
	}

	filters, err := FilterList(link, qdiscHandle)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}

	u32, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}
	// Endianness checks
	if u32.Sel.Offmask != filter.Sel.Offmask {
		t.Fatal("The endianness of TcU32Key.Sel.Offmask is wrong")
	}
	if u32.Sel.Hmask != filter.Sel.Hmask {
		t.Fatal("The endianness of TcU32Key.Sel.Hmask is wrong")
	}
	for i, key := range u32.Sel.Keys {
		if key.Mask != filter.Sel.Keys[i].Mask {
			t.Fatal("The endianness of TcU32Key.Mask is wrong")
		}
		if key.Val != filter.Sel.Keys[i].Val {
			t.Fatal("The endianness of TcU32Key.Val is wrong")
		}
	}
	if u32.Handle != (handle | htid) {
		t.Fatalf("The handle is wrong. expected %v but actually %v",
			(handle | htid), u32.Handle)
	}
	if u32.Hash != htid {
		t.Fatal("The hash table ID is wrong")
	}

	if err := FilterDel(u32); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, qdiscHandle)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err = ClassDel(htbClass); err != nil {
		t.Fatalf("Failed to delete a HTP class: %v", err)
	}
	classes, err = SafeClassList(link, qdiscHandle)
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 0 {
		t.Fatal("Failed to remove class")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterFwAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(0xffff, 0),
		Parent:    HANDLE_ROOT,
	}
	qdisc := NewHtb(attrs)
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Htb)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	classattrs := ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    MakeHandle(0xffff, 0),
		Handle:    MakeHandle(0xffff, 2),
	}

	htbclassattrs := HtbClassAttrs{
		Rate:    1234000,
		Cbuffer: 1690,
	}
	class := NewHtbClass(classattrs, htbclassattrs)
	if err := ClassAdd(class); err != nil {
		t.Fatal(err)
	}
	classes, err := SafeClassList(link, MakeHandle(0xffff, 2))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 {
		t.Fatal("Failed to add class")
	}

	filterattrs := FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    MakeHandle(0xffff, 0),
		Handle:    MakeHandle(0, 0x6),
		Priority:  1,
		Protocol:  unix.ETH_P_IP,
	}
	fwattrs := FilterFwAttrs{
		Buffer:   12345,
		Rate:     1234,
		PeakRate: 2345,
		Action:   TC_POLICE_SHOT,
		ClassId:  MakeHandle(0xffff, 2),
	}

	filter, err := NewFw(filterattrs, fwattrs)
	if err != nil {
		t.Fatal(err)
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	fw, ok := filters[0].(*Fw)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}
	if fw.Police.Rate.Rate != filter.Police.Rate.Rate {
		t.Fatal("Police Rate doesn't match")
	}
	if fw.ClassId != filter.ClassId {
		t.Fatal("ClassId doesn't match")
	}
	if fw.InDev != filter.InDev {
		t.Fatal("InDev doesn't match")
	}
	if fw.AvRate != filter.AvRate {
		t.Fatal("AvRate doesn't match")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}
	if err := ClassDel(class); err != nil {
		t.Fatal(err)
	}
	classes, err = SafeClassList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 0 {
		t.Fatal("Failed to remove class")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterU32BpfAddDel(t *testing.T) {
	t.Skipf("Fd does not match in travis")
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Ingress)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	fd, err := loadSimpleBpf(BPF_PROG_TYPE_SCHED_ACT, 1)
	if err != nil {
		t.Skipf("Loading bpf program failed: %s", err)
	}
	classId := MakeHandle(1, 1)
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		ClassId: classId,
		Actions: []Action{
			&BpfAction{Fd: fd, Name: "simple"},
			&MirredAction{
				ActionAttrs: ActionAttrs{
					Action: TC_ACT_STOLEN,
				},
				MirredAction: TCA_EGRESS_REDIR,
				Ifindex:      redir.Attrs().Index,
			},
		},
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	u32, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if len(u32.Actions) != 2 {
		t.Fatalf("Too few Actions in filter")
	}
	if u32.ClassId != classId {
		t.Fatalf("ClassId of the filter is the wrong value")
	}

	// actions can be returned in reverse order
	bpfAction, ok := u32.Actions[0].(*BpfAction)
	if !ok {
		bpfAction, ok = u32.Actions[1].(*BpfAction)
		if !ok {
			t.Fatal("Action is the wrong type")
		}
	}
	if bpfAction.Fd != fd {
		t.Fatalf("Action Fd does not match %d != %d", bpfAction.Fd, fd)
	}
	if _, ok := u32.Actions[0].(*MirredAction); !ok {
		if _, ok := u32.Actions[1].(*MirredAction); !ok {
			t.Fatal("Action is the wrong type")
		}
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterU32ConnmarkAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Ingress)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	classId := MakeHandle(1, 1)
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		ClassId: classId,
		Actions: []Action{
			&ConnmarkAction{
				ActionAttrs: ActionAttrs{
					Action: TC_ACT_PIPE,
				},
			},
			&MirredAction{
				ActionAttrs: ActionAttrs{
					Action: TC_ACT_STOLEN,
				},
				MirredAction: TCA_EGRESS_REDIR,
				Ifindex:      redir.Attrs().Index,
			},
		},
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	u32, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if len(u32.Actions) != 2 {
		t.Fatalf("Too few Actions in filter")
	}
	if u32.ClassId != classId {
		t.Fatalf("ClassId of the filter is the wrong value")
	}

	// actions can be returned in reverse order
	cma, ok := u32.Actions[0].(*ConnmarkAction)
	if !ok {
		cma, ok = u32.Actions[1].(*ConnmarkAction)
		if !ok {
			t.Fatal("Unable to find connmark action")
		}
	}

	if cma.Attrs().Action != TC_ACT_PIPE {
		t.Fatal("Connmark action isn't TC_ACT_PIPE")
	}

	mia, ok := u32.Actions[0].(*MirredAction)
	if !ok {
		mia, ok = u32.Actions[1].(*MirredAction)
		if !ok {
			t.Fatal("Unable to find mirred action")
		}
	}

	if mia.Attrs().Action != TC_ACT_STOLEN {
		t.Fatal("Mirred action isn't TC_ACT_STOLEN")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func setupLinkForTestWithQdisc(t *testing.T, linkName string) (Qdisc, Link) {
	if err := LinkAdd(&Ifb{LinkAttrs{Name: linkName}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName(linkName)
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(0xffff, 0),
		Parent:    HANDLE_CLSACT,
	}
	qdisc := &GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc", len(qdiscs))
	}
	if q, ok := qdiscs[0].(*GenericQdisc); !ok || q.Type() != "clsact" {
		t.Fatal("qdisc is the wrong type")
	}
	return qdiscs[0], link
}

func TestFilterClsActBpfAddDel(t *testing.T) {
	t.Skipf("Fd does not match in travis")
	// This feature was added in kernel 4.5
	minKernelRequired(t, 4, 5)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	qdisc, link := setupLinkForTestWithQdisc(t, "foo")
	filterattrs := FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    HANDLE_MIN_EGRESS,
		Handle:    MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	fd, err := loadSimpleBpf(BPF_PROG_TYPE_SCHED_CLS, 1)
	if err != nil {
		t.Skipf("Loading bpf program failed: %s", err)
	}
	filter := &BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           fd,
		Name:         "simple",
		DirectAction: true,
	}
	if filter.Fd < 0 {
		t.Skipf("Failed to load bpf program")
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	bpf, ok := filters[0].(*BpfFilter)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if bpf.Fd != filter.Fd {
		t.Fatal("Filter Fd does not match")
	}
	if bpf.DirectAction != filter.DirectAction {
		t.Fatal("Filter DirectAction does not match")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterMatchAllAddDel(t *testing.T) {
	// This classifier was added in kernel 4.7
	minKernelRequired(t, 4, 7)

	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	_, link := setupLinkForTestWithQdisc(t, "foo")
	_, link2 := setupLinkForTestWithQdisc(t, "bar")
	filter := &MatchAll{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    HANDLE_MIN_EGRESS,
			Priority:  32000,
			Protocol:  unix.ETH_P_ALL,
		},
		Actions: []Action{
			&MirredAction{
				ActionAttrs: ActionAttrs{
					Action: TC_ACT_STOLEN,
				},
				MirredAction: TCA_EGRESS_REDIR,
				Ifindex:      link2.Attrs().Index,
			},
		},
	}
	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	matchall, ok := filters[0].(*MatchAll)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if matchall.Priority != 32000 {
		t.Fatal("Filter priority does not match")
	}

	if len(matchall.Actions) != 1 {
		t.Fatal("Filter has no actions")
	}

	mirredAction, ok := matchall.Actions[0].(*MirredAction)
	if !ok {
		t.Fatal("Action does not match")
	}

	if mirredAction.Ifindex != link2.Attrs().Index {
		t.Fatal("Action ifindex does not match")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

}

func TestFilterU32TunnelKeyAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}

	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, v := range qdiscs {
		if _, ok := v.(*Ingress); ok {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Qdisc is the wrong type")
	}

	tunnelAct := NewTunnelKeyAction()
	tunnelAct.SrcAddr = net.IPv4(10, 10, 10, 1)
	tunnelAct.DstAddr = net.IPv4(10, 10, 10, 2)
	tunnelAct.KeyID = 0x01
	tunnelAct.Action = TCA_TUNNEL_KEY_SET
	tunnelAct.DestPort = 8472

	classId := MakeHandle(1, 1)
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		ClassId: classId,
		Actions: []Action{
			tunnelAct,
			&MirredAction{
				ActionAttrs: ActionAttrs{
					Action: TC_ACT_STOLEN,
				},
				MirredAction: TCA_EGRESS_REDIR,
				Ifindex:      redir.Attrs().Index,
			},
		},
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	u32, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if len(u32.Actions) != 2 {
		t.Fatalf("Too few Actions in filter")
	}
	if u32.ClassId != classId {
		t.Fatalf("ClassId of the filter is the wrong value")
	}

	// actions can be returned in reverse order
	tun, ok := u32.Actions[0].(*TunnelKeyAction)
	if !ok {
		tun, ok = u32.Actions[1].(*TunnelKeyAction)
		if !ok {
			t.Fatal("Unable to find tunnel action")
		}
	}

	if tun.Attrs().Action != TC_ACT_PIPE {
		t.Fatal("TunnelKey action isn't TC_ACT_PIPE")
	}
	if !tun.SrcAddr.Equal(tunnelAct.SrcAddr) {
		t.Fatal("Action SrcAddr doesn't match")
	}
	if !tun.DstAddr.Equal(tunnelAct.DstAddr) {
		t.Fatal("Action DstAddr doesn't match")
	}
	if tun.KeyID != tunnelAct.KeyID {
		t.Fatal("Action KeyID doesn't match")
	}
	if tun.DestPort != tunnelAct.DestPort {
		t.Fatal("Action DestPort doesn't match")
	}
	if tun.Action != tunnelAct.Action {
		t.Fatal("Action doesn't match")
	}

	mia, ok := u32.Actions[0].(*MirredAction)
	if !ok {
		mia, ok = u32.Actions[1].(*MirredAction)
		if !ok {
			t.Fatal("Unable to find mirred action")
		}
	}

	if mia.Attrs().Action != TC_ACT_STOLEN {
		t.Fatal("Mirred action isn't TC_ACT_STOLEN")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}

	found = false
	for _, v := range qdiscs {
		if _, ok := v.(*Ingress); ok {
			found = true
			break
		}
	}
	if found {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterU32SkbEditAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}

	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, v := range qdiscs {
		if _, ok := v.(*Ingress); ok {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Qdisc is the wrong type")
	}

	skbedit := NewSkbEditAction()
	ptype := uint16(unix.PACKET_HOST)
	skbedit.PType = &ptype
	priority := uint32(0xff)
	skbedit.Priority = &priority
	mark := uint32(0xfe)
	skbedit.Mark = &mark
	mapping := uint16(0xf)
	skbedit.QueueMapping = &mapping

	classId := MakeHandle(1, 1)
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		ClassId: classId,
		Actions: []Action{
			skbedit,
			&MirredAction{
				ActionAttrs: ActionAttrs{
					Action: TC_ACT_STOLEN,
				},
				MirredAction: TCA_EGRESS_REDIR,
				Ifindex:      redir.Attrs().Index,
			},
		},
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	u32, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if len(u32.Actions) != 2 {
		t.Fatalf("Too few Actions in filter")
	}
	if u32.ClassId != classId {
		t.Fatalf("ClassId of the filter is the wrong value")
	}

	// actions can be returned in reverse order
	edit, ok := u32.Actions[0].(*SkbEditAction)
	if !ok {
		edit, ok = u32.Actions[1].(*SkbEditAction)
		if !ok {
			t.Fatal("Unable to find tunnel action")
		}
	}

	if edit.Attrs().Action != TC_ACT_PIPE {
		t.Fatal("SkbEdit action isn't TC_ACT_PIPE")
	}
	if edit.PType == nil || *edit.PType != *skbedit.PType {
		t.Fatal("Action PType doesn't match")
	}
	if edit.QueueMapping == nil || *edit.QueueMapping != *skbedit.QueueMapping {
		t.Fatal("Action QueueMapping doesn't match")
	}
	if edit.Mark == nil || *edit.Mark != *skbedit.Mark {
		t.Fatal("Action Mark doesn't match")
	}
	if edit.Priority == nil || *edit.Priority != *skbedit.Priority {
		t.Fatal("Action Priority doesn't match")
	}

	mia, ok := u32.Actions[0].(*MirredAction)
	if !ok {
		mia, ok = u32.Actions[1].(*MirredAction)
		if !ok {
			t.Fatal("Unable to find mirred action")
		}
	}

	if mia.Attrs().Action != TC_ACT_STOLEN {
		t.Fatal("Mirred action isn't TC_ACT_STOLEN")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}

	found = false
	for _, v := range qdiscs {
		if _, ok := v.(*Ingress); ok {
			found = true
			break
		}
	}
	if found {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterU32LinkOption(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatalf("add link foo error: %v", err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatalf("add link foo error: %v", err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatalf("set foo link up error: %v", err)
	}

	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatalf("get qdisc error: %v", err)
	}

	found := false
	for _, v := range qdiscs {
		if _, ok := v.(*Ingress); ok {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Qdisc is the wrong type")
	}

	htid := uint32(10)
	size := uint32(8)
	priority := uint16(200)
	u32Table := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    htid << 20,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Divisor: size,
	}
	if err := FilterAdd(u32Table); err != nil {
		t.Fatal(err)
	}

	u32 := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Handle:    1,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Link: uint32(htid << 20),
		Sel: &TcU32Sel{
			Nkeys:    1,
			Flags:    TC_U32_TERMINAL | TC_U32_VAROFFSET,
			Hmask:    0x0000ff00,
			Hoff:     0,
			Offshift: 8,
			Keys: []TcU32Key{
				{
					Mask: 0,
					Val:  0,
					Off:  0,
				},
			},
		},
	}
	if err := FilterAdd(u32); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatalf("get filter error: %v", err)
	}

	if len(filters) != 1 {
		t.Fatalf("the count filters error, expect: 1, acutal: %d", len(filters))
	}

	ft, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if ft.LinkIndex != link.Attrs().Index {
		t.Fatal("link index error")
	}

	if ft.Link != htid<<20 {
		t.Fatal("hash table id error")
	}

	if ft.Priority != priority {
		t.Fatal("priority error")
	}

	if err := FilterDel(ft); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}

	found = false
	for _, v := range qdiscs {
		if _, ok := v.(*Ingress); ok {
			found = true
			break
		}
	}
	if found {
		t.Fatal("Failed to remove qdisc")
	}
}
