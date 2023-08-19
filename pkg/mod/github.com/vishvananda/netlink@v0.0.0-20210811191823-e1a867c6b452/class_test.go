// +build linux

package netlink

import (
	"reflect"
	"testing"
)

func SafeQdiscList(link Link) ([]Qdisc, error) {
	qdiscs, err := QdiscList(link)
	if err != nil {
		return nil, err
	}
	result := []Qdisc{}
	for _, qdisc := range qdiscs {
		// filter out pfifo_fast qdiscs because
		// older kernels don't return them
		_, pfifo := qdisc.(*PfifoFast)
		if !pfifo {
			result = append(result, qdisc)
		}
	}
	return result, nil
}

func SafeClassList(link Link, handle uint32) ([]Class, error) {
	classes, err := ClassList(link, handle)
	if err != nil {
		return nil, err
	}
	result := []Class{}
	for ind := range classes {
		double := false
		for _, class2 := range classes[ind+1:] {
			if classes[ind].Attrs().Handle == class2.Attrs().Handle {
				double = true
			}
		}
		if !double {
			result = append(result, classes[ind])
		}
	}
	return result, nil
}

func testClassStats(this, that *ClassStatistics, t *testing.T) {
	ok := reflect.DeepEqual(this, that)
	if !ok {
		t.Fatalf("%#v is expected but it actually was %#v", that, this)
	}
}

func TestClassAddDel(t *testing.T) {
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
		Prio:    2,
		Quantum: 1000,
	}
	class := NewHtbClass(classattrs, htbclassattrs)
	if err := ClassAdd(class); err != nil {
		t.Fatal(err)
	}
	classes, err := SafeClassList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 {
		t.Fatal("Failed to add class")
	}

	htb, ok := classes[0].(*HtbClass)
	if !ok {
		t.Fatal("Class is the wrong type")
	}
	if htb.Rate != class.Rate {
		t.Fatal("Rate doesn't match")
	}
	if htb.Ceil != class.Ceil {
		t.Fatal("Ceil doesn't match")
	}
	if htb.Buffer != class.Buffer {
		t.Fatal("Buffer doesn't match")
	}
	if htb.Cbuffer != class.Cbuffer {
		t.Fatal("Cbuffer doesn't match")
	}
	if htb.Prio != class.Prio {
		t.Fatal("Prio doesn't match")
	}
	if htb.Quantum != class.Quantum {
		t.Fatal("Quantum doesn't match")
	}

	testClassStats(htb.ClassAttrs.Statistics, NewClassStatistics(), t)

	qattrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(0x2, 0),
		Parent:    MakeHandle(0xffff, 2),
	}
	nattrs := NetemQdiscAttrs{
		Latency:     20000,
		Loss:        23.4,
		Duplicate:   14.3,
		LossCorr:    8.34,
		Jitter:      1000,
		DelayCorr:   12.3,
		ReorderProb: 23.4,
		CorruptProb: 10.0,
		CorruptCorr: 10,
	}
	qdiscnetem := NewNetem(qattrs, nattrs)
	if err := QdiscAdd(qdiscnetem); err != nil {
		t.Fatal(err)
	}

	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 2 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok = qdiscs[0].(*Htb)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	netem, ok := qdiscs[1].(*Netem)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	// Compare the record we got from the list with the one we created
	if netem.Loss != qdiscnetem.Loss {
		t.Fatal("Loss does not match")
	}
	if netem.Latency != qdiscnetem.Latency {
		t.Fatal("Latency does not match")
	}
	if netem.CorruptProb != qdiscnetem.CorruptProb {
		t.Fatal("CorruptProb does not match")
	}
	if netem.Jitter != qdiscnetem.Jitter {
		t.Fatal("Jitter does not match")
	}
	if netem.LossCorr != qdiscnetem.LossCorr {
		t.Fatal("Loss does not match")
	}
	if netem.DuplicateCorr != qdiscnetem.DuplicateCorr {
		t.Fatal("DuplicateCorr does not match")
	}

	// Deletion
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

func TestHtbClassAddHtbClassChangeDel(t *testing.T) {
	/**
	This test first set up a interface ans set up a Htb qdisc
	A HTB class is attach to it and a Netem qdisc is attached to that class
	Next, we test changing the HTB class in place and confirming the Netem is
	still attached. We also check that invoting ClassChange with a non-existing
	class will fail.
	Finally, we test ClassReplace. We confirm it correctly behave like
	ClassChange when the parent/handle pair exists and that it will create a
	new class if the handle is modified.
	*/
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
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
		Rate:    uint64(1<<32) + 10,
		Ceil:    uint64(1<<32) + 20,
		Cbuffer: 1690,
	}
	class := NewHtbClass(classattrs, htbclassattrs)
	if err := ClassAdd(class); err != nil {
		t.Fatal(err)
	}
	classes, err := SafeClassList(link, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 {
		t.Fatal("Failed to add class")
	}

	htb, ok := classes[0].(*HtbClass)
	if !ok {
		t.Fatal("Class is the wrong type")
	}

	testClassStats(htb.ClassAttrs.Statistics, NewClassStatistics(), t)

	qattrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(0x2, 0),
		Parent:    MakeHandle(0xffff, 2),
	}
	nattrs := NetemQdiscAttrs{
		Latency:     20000,
		Loss:        23.4,
		Duplicate:   14.3,
		LossCorr:    8.34,
		Jitter:      1000,
		DelayCorr:   12.3,
		ReorderProb: 23.4,
		CorruptProb: 10.0,
		CorruptCorr: 10,
	}
	qdiscnetem := NewNetem(qattrs, nattrs)
	if err := QdiscAdd(qdiscnetem); err != nil {
		t.Fatal(err)
	}

	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 2 {
		t.Fatal("Failed to add qdisc")
	}

	_, ok = qdiscs[1].(*Netem)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	// Change
	// For change to work, the handle and parent cannot be changed.

	// First, test it fails if we change the Handle.
	oldHandle := classattrs.Handle
	classattrs.Handle = MakeHandle(0xffff, 3)
	class = NewHtbClass(classattrs, htbclassattrs)
	if err := ClassChange(class); err == nil {
		t.Fatal("ClassChange should not work when using a different handle.")
	}
	// It should work with the same handle
	classattrs.Handle = oldHandle
	htbclassattrs.Rate = 4321000
	class = NewHtbClass(classattrs, htbclassattrs)
	if err := ClassChange(class); err != nil {
		t.Fatal(err)
	}

	classes, err = SafeClassList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 {
		t.Fatalf(
			"1 class expected, %d found",
			len(classes),
		)
	}

	htb, ok = classes[0].(*HtbClass)
	if !ok {
		t.Fatal("Class is the wrong type")
	}
	// Verify that the rate value has changed.
	if htb.Rate != class.Rate {
		t.Fatal("Rate did not get changed while changing the class.")
	}

	// Check that we still have the netem child qdisc
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}

	if len(qdiscs) != 2 {
		t.Fatalf("2 qdisc expected, %d found", len(qdiscs))
	}
	_, ok = qdiscs[0].(*Htb)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	_, ok = qdiscs[1].(*Netem)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	// Replace
	// First replace by keeping the same handle, class will be changed.
	// Then, replace by providing a new handle, n new class will be created.

	// Replace acting as Change
	class = NewHtbClass(classattrs, htbclassattrs)
	if err := ClassReplace(class); err != nil {
		t.Fatal("Failed to replace class that is existing.")
	}

	classes, err = SafeClassList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 {
		t.Fatalf(
			"1 class expected, %d found",
			len(classes),
		)
	}

	htb, ok = classes[0].(*HtbClass)
	if !ok {
		t.Fatal("Class is the wrong type")
	}
	// Verify that the rate value has changed.
	if htb.Rate != class.Rate {
		t.Fatal("Rate did not get changed while changing the class.")
	}

	// It should work with the same handle
	classattrs.Handle = MakeHandle(0xffff, 3)
	class = NewHtbClass(classattrs, htbclassattrs)
	if err := ClassReplace(class); err != nil {
		t.Fatal(err)
	}

	classes, err = SafeClassList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 2 {
		t.Fatalf(
			"2 classes expected, %d found",
			len(classes),
		)
	}

	htb, ok = classes[1].(*HtbClass)
	if !ok {
		t.Fatal("Class is the wrong type")
	}
	// Verify that the rate value has changed.
	if htb.Rate != class.Rate {
		t.Fatal("Rate did not get changed while changing the class.")
	}

	// Deletion
	for _, class := range classes {
		if err := ClassDel(class); err != nil {
			t.Fatal(err)
		}
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

func TestClassHfsc(t *testing.T) {
	// New network namespace for tests
	tearDown := setUpNetlinkTestWithKModule(t, "sch_hfsc")
	defer tearDown()

	// Set up testing link and check if succeeded
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// Adding HFSC qdisc
	qdiscAttrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(1, 0),
		Parent:    HANDLE_ROOT,
	}
	hfscQdisc := NewHfsc(qdiscAttrs)
	hfscQdisc.Defcls = 2

	err = QdiscAdd(hfscQdisc)
	if err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Hfsc)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	// Adding some HFSC classes
	classAttrs := ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    MakeHandle(1, 0),
		Handle:    MakeHandle(1, 1),
	}
	hfscClass := NewHfscClass(classAttrs)
	hfscClass.SetLS(5e6, 10, 5e6)

	err = ClassAdd(hfscClass)
	if err != nil {
		t.Fatal(err)
	}

	hfscClass2 := hfscClass
	hfscClass2.SetLS(0, 0, 0)
	hfscClass2.Attrs().Parent = MakeHandle(1, 1)
	hfscClass2.Attrs().Handle = MakeHandle(1, 2)
	hfscClass2.SetRsc(0, 0, 2e6)

	err = ClassAdd(hfscClass2)
	if err != nil {
		t.Fatal(err)
	}

	hfscClass3 := hfscClass
	hfscClass3.SetLS(0, 0, 0)
	hfscClass3.Attrs().Parent = MakeHandle(1, 1)
	hfscClass3.Attrs().Handle = MakeHandle(1, 3)

	err = ClassAdd(hfscClass3)
	if err != nil {
		t.Fatal(err)
	}

	// Check the classes
	classes, err := SafeClassList(link, MakeHandle(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 4 {
		t.Fatal("Failed to add classes")
	}
	for _, c := range classes {
		class, ok := c.(*HfscClass)
		if !ok {
			t.Fatal("Wrong type of class")
		}
		if class.ClassAttrs.Handle == hfscClass.ClassAttrs.Handle {
			if class.Fsc != hfscClass.Fsc {
				t.Fatal("HfscClass FSC don't match")
			}
			if class.Usc != hfscClass.Usc {
				t.Fatal("HfscClass USC don't match")
			}
			if class.Rsc != hfscClass.Rsc {
				t.Fatal("HfscClass RSC don't match")
			}
		}
		if class.ClassAttrs.Handle == hfscClass2.ClassAttrs.Handle {
			if class.Fsc != hfscClass2.Fsc {
				t.Fatal("HfscClass2 FSC don't match")
			}
			if class.Usc != hfscClass2.Usc {
				t.Fatal("HfscClass2 USC don't match")
			}
			if class.Rsc != hfscClass2.Rsc {
				t.Fatal("HfscClass2 RSC don't match")
			}
		}
		if class.ClassAttrs.Handle == hfscClass3.ClassAttrs.Handle {
			if class.Fsc != hfscClass3.Fsc {
				t.Fatal("HfscClass3 FSC don't match")
			}
			if class.Usc != hfscClass3.Usc {
				t.Fatal("HfscClass3 USC don't match")
			}
			if class.Rsc != hfscClass3.Rsc {
				t.Fatal("HfscClass3 RSC don't match")
			}
		}
	}

	// Terminating the leafs with fq_codel qdiscs
	fqcodelAttrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    MakeHandle(1, 2),
		Handle:    MakeHandle(2, 0),
	}
	fqcodel1 := NewFqCodel(fqcodelAttrs)
	fqcodel1.ECN = 0
	fqcodel1.Limit = 1200
	fqcodel1.Flows = 65535
	fqcodel1.Target = 5

	err = QdiscAdd(fqcodel1)
	if err != nil {
		t.Fatal(err)
	}

	fqcodel2 := fqcodel1
	fqcodel2.Attrs().Handle = MakeHandle(3, 0)
	fqcodel2.Attrs().Parent = MakeHandle(1, 3)

	err = QdiscAdd(fqcodel2)
	if err != nil {
		t.Fatal(err)
	}

	// Check the amount of qdiscs
	qdiscs, err = SafeQdiscList(link)
	if len(qdiscs) != 3 {
		t.Fatal("Failed to add qdisc")
	}
	for _, q := range qdiscs[1:] {
		_, ok = q.(*FqCodel)
		if !ok {
			t.Fatal("Qdisc is the wrong type")
		}
	}

	// removing a class
	if err := ClassDel(hfscClass3); err != nil {
		t.Fatal(err)
	}
	// Check the classes
	classes, err = SafeClassList(link, MakeHandle(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 3 {
		t.Fatal("Failed to delete classes")
	}
	// Check qdisc
	qdiscs, err = SafeQdiscList(link)
	if len(qdiscs) != 2 {
		t.Fatal("Failed to delete qdisc")
	}

	// Changing a class
	hfscClass2.SetRsc(0, 0, 0)
	hfscClass2.SetSC(5e6, 100, 1e6)
	hfscClass2.SetUL(6e6, 50, 2e6)
	hfscClass2.Attrs().Handle = MakeHandle(1, 8)
	if err := ClassChange(hfscClass2); err == nil {
		t.Fatal("Class change shouldn't work with a different handle")
	}
	hfscClass2.Attrs().Handle = MakeHandle(1, 2)
	if err := ClassChange(hfscClass2); err != nil {
		t.Fatal(err)
	}

	// Replacing a class
	// If the handle doesn't exist, create it
	hfscClass2.SetSC(6e6, 100, 2e6)
	hfscClass2.SetUL(8e6, 500, 4e6)
	hfscClass2.Attrs().Handle = MakeHandle(1, 8)
	if err := ClassReplace(hfscClass2); err != nil {
		t.Fatal(err)
	}
	// If the handle exists, replace it
	hfscClass.SetLS(5e6, 200, 1e6)
	if err := ClassChange(hfscClass); err != nil {
		t.Fatal(err)
	}

}
