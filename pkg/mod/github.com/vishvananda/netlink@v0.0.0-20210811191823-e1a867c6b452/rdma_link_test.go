// +build linux

package netlink

import (
	"github.com/vishvananda/netns"
	"io/ioutil"
	"strings"
	"testing"
)

func setupRdmaKModule(t *testing.T, name string) {
	skipUnlessRoot(t)
	file, err := ioutil.ReadFile("/proc/modules")
	if err != nil {
		t.Fatal("Failed to open /proc/modules", err)
	}
	for _, line := range strings.Split(string(file), "\n") {
		n := strings.Split(line, " ")[0]
		if n == name {
			return
		}

	}
	t.Skipf("Test requires kmodule %q.", name)
}

func TestRdmaGetRdmaLink(t *testing.T) {
	minKernelRequired(t, 4, 16)
	setupRdmaKModule(t, "ib_core")
	_, err := RdmaLinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRdmaSetRdmaLinkName(t *testing.T) {
	minKernelRequired(t, 4, 19)
	setupRdmaKModule(t, "ib_core")
	link, err := RdmaLinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	// Set new name
	err = RdmaLinkSetName(link, "bar")
	if err != nil {
		t.Fatal(err)
	}
	// Revert back to old name
	err = RdmaLinkSetName(link, "foo")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRdmaSystemGetNetnsMode(t *testing.T) {
	minKernelRequired(t, 5, 2)
	setupRdmaKModule(t, "ib_core")

	mode, err := RdmaSystemGetNetnsMode()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("rdma system netns mode =", mode)
}

func TestRdmaSystemSetNetnsMode(t *testing.T) {
	var newMode string
	var mode string
	var err error

	minKernelRequired(t, 5, 2)
	setupRdmaKModule(t, "ib_core")

	mode, err = RdmaSystemGetNetnsMode()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("current rdma system mode =", mode)

	err = RdmaSystemSetNetnsMode(mode)
	if err != nil {
		t.Fatal(err)
	}
	// Flip the mode from current mode
	if mode == "exclusive" {
		err = RdmaSystemSetNetnsMode("shared")
	} else {
		err = RdmaSystemSetNetnsMode("exclusive")
	}
	newMode, err = RdmaSystemGetNetnsMode()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("new rdma system mode =", newMode)

	// Change back to original mode
	err = RdmaSystemSetNetnsMode(mode)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRdmaLinkSetNsFd(t *testing.T) {
	minKernelRequired(t, 5, 2)
	setupRdmaKModule(t, "ib_core")

	mode, err := RdmaSystemGetNetnsMode()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("current rdma netns mode", mode)
	err = RdmaSystemSetNetnsMode("exclusive")
	if err != nil {
		t.Fatal(err)
	}
	basens, err := netns.Get()
	if err != nil {
		RdmaSystemSetNetnsMode(mode)
		t.Fatal("Failed to get basens")
	}
	defer basens.Close()

	newns, err := netns.New()
	if err != nil {
		RdmaSystemSetNetnsMode(mode)
		t.Fatal("Failed to create newns")
	}

	netns.Set(basens)
	link, err := RdmaLinkByName("foo")
	if err != nil {
		// Remove the namespace as RDMA subsystem requires
		// no namespace to exist when changing net namespace mode
		newns.Close()
		RdmaSystemSetNetnsMode(mode)
		t.Fatal(err)
	}
	t.Log("rdma link: ", link)

	err = RdmaLinkSetNsFd(link, uint32(newns))
	if err != nil {
		newns.Close()
		RdmaSystemSetNetnsMode(mode)
		t.Fatal(err)
	}

	newns.Close()
	//Set the old mode back at start of the test
	err = RdmaSystemSetNetnsMode(mode)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRdmaLinkList(t *testing.T) {
	minKernelRequired(t, 4, 16)
	setupRdmaKModule(t, "ib_core")
	links, err := RdmaLinkList()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RDMA devices:")
	for _, link := range links {
		t.Logf("%d: %s", link.Attrs.Index, link.Attrs.Name)
	}
}
