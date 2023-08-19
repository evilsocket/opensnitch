// +build linux

package netlink

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestRouteAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	dstIP := net.IPv4(192, 168, 0, 42)
	routeToDstIP, err := RouteGet(dstIP)
	if err != nil {
		t.Fatal(err)
	}

	if len(routeToDstIP) == 0 {
		t.Fatal("Default route not present")
	}
	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}

}

func TestRoute6AddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// create dummy interface
	// IPv6 route added to loopback interface will be unreachable
	la := NewLinkAttrs()
	la.Name = "dummy_route6"
	la.TxQLen = 1500
	dummy := &Dummy{LinkAttrs: la}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}

	// get dummy interface
	link, err := LinkByName("dummy_route6")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// remember number of routes before adding
	// typically one route (fe80::/64) will be created when dummy_route6 is created
	routes, err := RouteList(link, FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	nroutes := len(routes)

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.ParseIP("2001:db8::0"),
		Mask: net.CIDRMask(64, 128),
	}
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != nroutes+1 {
		t.Fatal("Route not added properly")
	}

	dstIP := net.ParseIP("2001:db8::1")
	routeToDstIP, err := RouteGet(dstIP)
	if err != nil {
		t.Fatal(err)
	}

	// cleanup route and dummy interface created for the test
	if len(routeToDstIP) == 0 {
		t.Fatal("Route not present")
	}
	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != nroutes {
		t.Fatal("Route not removed properly")
	}
	if err := LinkDel(link); err != nil {
		t.Fatal(err)
	}
}

func TestRouteReplace(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	ip = net.IPv4(127, 1, 1, 2)
	route = Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteReplace(&route); err != nil {
		t.Fatal(err)
	}

	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(routes) != 1 || !routes[0].Src.Equal(ip) {
		t.Fatal("Route not replaced properly")
	}

	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}

}

func TestRouteAppend(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	ip = net.IPv4(127, 1, 1, 2)
	route = Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAppend(&route); err != nil {
		t.Fatal(err)
	}

	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(routes) != 2 || !routes[1].Src.Equal(ip) {
		t.Fatal("Route not append properly")
	}

	if err := RouteDel(&routes[0]); err != nil {
		t.Fatal(err)
	}
	if err := RouteDel(&routes[1]); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}
}

func TestRouteAddIncomplete(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	route := Route{LinkIndex: link.Attrs().Index}
	if err := RouteAdd(&route); err == nil {
		t.Fatal("Adding incomplete route should fail")
	}
}

// expectNeighUpdate returns whether the expected updated is received within one minute.
func expectRouteUpdate(ch <-chan RouteUpdate, t uint16, dst net.IP) bool {
	for {
		timeout := time.After(time.Minute)
		select {
		case update := <-ch:
			if update.Type == t &&
				update.Route.Dst != nil &&
				update.Route.Dst.IP.Equal(dst) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestRouteSubscribe(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan RouteUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := RouteSubscribe(ch, done); err != nil {
		t.Fatal(err)
	}

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}

	if !expectRouteUpdate(ch, unix.RTM_NEWROUTE, dst.IP) {
		t.Fatal("Add update not received as expected")
	}
	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	if !expectRouteUpdate(ch, unix.RTM_DELROUTE, dst.IP) {
		t.Fatal("Del update not received as expected")
	}
}

func TestRouteSubscribeWithOptions(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan RouteUpdate)
	done := make(chan struct{})
	defer close(done)
	var lastError error
	defer func() {
		if lastError != nil {
			t.Fatalf("Fatal error received during subscription: %v", lastError)
		}
	}()
	if err := RouteSubscribeWithOptions(ch, done, RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			lastError = err
		},
	}); err != nil {
		t.Fatal(err)
	}

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}

	if !expectRouteUpdate(ch, unix.RTM_NEWROUTE, dst.IP) {
		t.Fatal("Add update not received as expected")
	}
}

func TestRouteSubscribeAt(t *testing.T) {
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

	// Subscribe for Route events on the custom netns
	ch := make(chan RouteUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := RouteSubscribeAt(newNs, ch, done); err != nil {
		t.Fatal(err)
	}

	// get loopback interface
	link, err := nh.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = nh.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 169, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 100, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := nh.RouteAdd(&route); err != nil {
		t.Fatal(err)
	}

	if !expectRouteUpdate(ch, unix.RTM_NEWROUTE, dst.IP) {
		t.Fatal("Add update not received as expected")
	}
	if err := nh.RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	if !expectRouteUpdate(ch, unix.RTM_DELROUTE, dst.IP) {
		t.Fatal("Del update not received as expected")
	}
}

func TestRouteSubscribeListExisting(t *testing.T) {
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

	// get loopback interface
	link, err := nh.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = nh.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route before subscribing
	dst10 := &net.IPNet{
		IP:   net.IPv4(10, 10, 10, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 100, 1, 1)
	route10 := Route{LinkIndex: link.Attrs().Index, Dst: dst10, Src: ip}
	if err := nh.RouteAdd(&route10); err != nil {
		t.Fatal(err)
	}

	// Subscribe for Route events including existing routes
	ch := make(chan RouteUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := RouteSubscribeWithOptions(ch, done, RouteSubscribeOptions{
		Namespace:    &newNs,
		ListExisting: true},
	); err != nil {
		t.Fatal(err)
	}

	if !expectRouteUpdate(ch, unix.RTM_NEWROUTE, dst10.IP) {
		t.Fatal("Existing add update not received as expected")
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 169, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := nh.RouteAdd(&route); err != nil {
		t.Fatal(err)
	}

	if !expectRouteUpdate(ch, unix.RTM_NEWROUTE, dst.IP) {
		t.Fatal("Add update not received as expected")
	}
	if err := nh.RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	if !expectRouteUpdate(ch, unix.RTM_DELROUTE, dst.IP) {
		t.Fatal("Del update not received as expected")
	}
	if err := nh.RouteDel(&route10); err != nil {
		t.Fatal(err)
	}
	if !expectRouteUpdate(ch, unix.RTM_DELROUTE, dst10.IP) {
		t.Fatal("Del update not received as expected")
	}
}

func TestRouteFilterAllTables(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(1, 1, 1, 1),
		Mask: net.CIDRMask(32, 32),
	}

	tables := []int{1000, 1001, 1002}
	src := net.IPv4(127, 3, 3, 3)
	for _, table := range tables {
		route := Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Src:       src,
			Scope:     unix.RT_SCOPE_LINK,
			Priority:  13,
			Table:     table,
			Type:      unix.RTN_UNICAST,
			Tos:       14,
			Hoplimit:  100,
		}
		if err := RouteAdd(&route); err != nil {
			t.Fatal(err)
		}
	}
	routes, err := RouteListFiltered(FAMILY_V4, &Route{
		Dst:      dst,
		Src:      src,
		Scope:    unix.RT_SCOPE_LINK,
		Table:    unix.RT_TABLE_UNSPEC,
		Type:     unix.RTN_UNICAST,
		Tos:      14,
		Hoplimit: 100,
	}, RT_FILTER_DST|RT_FILTER_SRC|RT_FILTER_SCOPE|RT_FILTER_TABLE|RT_FILTER_TYPE|RT_FILTER_TOS|RT_FILTER_HOPLIMIT)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 {
		t.Fatal("Routes not added properly")
	}

	for _, route := range routes {
		if route.Scope != unix.RT_SCOPE_LINK {
			t.Fatal("Invalid Scope. Route not added properly")
		}
		if route.Priority != 13 {
			t.Fatal("Invalid Priority. Route not added properly")
		}
		if !tableIDIn(tables, route.Table) {
			t.Fatalf("Invalid Table %d. Route not added properly", route.Table)
		}
		if route.Type != unix.RTN_UNICAST {
			t.Fatal("Invalid Type. Route not added properly")
		}
		if route.Tos != 14 {
			t.Fatal("Invalid Tos. Route not added properly")
		}
		if route.Hoplimit != 100 {
			t.Fatal("Invalid Hoplimit. Route not added properly")
		}
	}
}

func tableIDIn(ids []int, id int) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func TestRouteExtraFields(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(1, 1, 1, 1),
		Mask: net.CIDRMask(32, 32),
	}

	src := net.IPv4(127, 3, 3, 3)
	route := Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Src:       src,
		Scope:     unix.RT_SCOPE_LINK,
		Priority:  13,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
		Tos:       14,
		Hoplimit:  100,
	}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteListFiltered(FAMILY_V4, &Route{
		Dst:      dst,
		Src:      src,
		Scope:    unix.RT_SCOPE_LINK,
		Table:    unix.RT_TABLE_MAIN,
		Type:     unix.RTN_UNICAST,
		Tos:      14,
		Hoplimit: 100,
	}, RT_FILTER_DST|RT_FILTER_SRC|RT_FILTER_SCOPE|RT_FILTER_TABLE|RT_FILTER_TYPE|RT_FILTER_TOS|RT_FILTER_HOPLIMIT)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	if routes[0].Scope != unix.RT_SCOPE_LINK {
		t.Fatal("Invalid Scope. Route not added properly")
	}
	if routes[0].Priority != 13 {
		t.Fatal("Invalid Priority. Route not added properly")
	}
	if routes[0].Table != unix.RT_TABLE_MAIN {
		t.Fatal("Invalid Scope. Route not added properly")
	}
	if routes[0].Type != unix.RTN_UNICAST {
		t.Fatal("Invalid Type. Route not added properly")
	}
	if routes[0].Tos != 14 {
		t.Fatal("Invalid Tos. Route not added properly")
	}
	if routes[0].Hoplimit != 100 {
		t.Fatal("Invalid Hoplimit. Route not added properly")
	}
}

func TestRouteMultiPath(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	idx := link.Attrs().Index
	route := Route{Dst: dst, MultiPath: []*NexthopInfo{{LinkIndex: idx}, {LinkIndex: idx}}}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(nil, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("MultiPath Route not added properly")
	}
	if len(routes[0].MultiPath) != 2 {
		t.Fatal("MultiPath Route not added properly")
	}
}

func TestFilterDefaultRoute(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	address := &Addr{
		IPNet: &net.IPNet{
			IP:   net.IPv4(127, 0, 0, 2),
			Mask: net.CIDRMask(24, 32),
		},
	}
	if err = AddrAdd(link, address); err != nil {
		t.Fatal(err)
	}

	// Add default route
	gw := net.IPv4(127, 0, 0, 2)

	defaultRoute := Route{
		Dst: nil,
		Gw:  gw,
	}

	if err := RouteAdd(&defaultRoute); err != nil {
		t.Fatal(err)
	}

	// add an extra route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	extraRoute := Route{
		Dst: dst,
		Gw:  gw,
	}

	if err := RouteAdd(&extraRoute); err != nil {
		t.Fatal(err)
	}
	var filterTests = []struct {
		filter   *Route
		mask     uint64
		expected net.IP
	}{
		{
			&Route{Dst: nil},
			RT_FILTER_DST,
			gw,
		},
		{
			&Route{Dst: dst},
			RT_FILTER_DST,
			gw,
		},
	}

	for _, f := range filterTests {
		routes, err := RouteListFiltered(FAMILY_V4, f.filter, f.mask)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 {
			t.Fatal("Route not filtered properly")
		}
		if !routes[0].Gw.Equal(gw) {
			t.Fatal("Unexpected Gateway")
		}
	}

}

func TestMPLSRouteAddDel(t *testing.T) {
	tearDown := setUpMPLSNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	mplsDst := 100
	route := Route{
		LinkIndex: link.Attrs().Index,
		MPLSDst:   &mplsDst,
		NewDst: &MPLSDestination{
			Labels: []int{200, 300},
		},
	}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_MPLS)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_MPLS)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}

}

func TestRouteEqual(t *testing.T) {
	mplsDst := 100
	seg6encap := &SEG6Encap{Mode: nl.SEG6_IPTUN_MODE_ENCAP}
	seg6encap.Segments = []net.IP{net.ParseIP("fc00:a000::11")}
	cases := []Route{
		{
			Dst: nil,
			Gw:  net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			ILinkIndex: 21,
			LinkIndex:  20,
			Dst:        nil,
			Gw:         net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Protocol:  20,
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Priority:  20,
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Type:      20,
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Table:     200,
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Tos:       1,
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Hoplimit:  1,
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 20,
			Dst:       nil,
			Flags:     int(FLAG_ONLINK),
			Gw:        net.IPv4(1, 1, 1, 1),
		},
		{
			LinkIndex: 10,
			Dst: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 0),
				Mask: net.CIDRMask(24, 32),
			},
			Src: net.IPv4(127, 1, 1, 1),
		},
		{
			LinkIndex: 10,
			Scope:     unix.RT_SCOPE_LINK,
			Dst: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 0),
				Mask: net.CIDRMask(24, 32),
			},
			Src: net.IPv4(127, 1, 1, 1),
		},
		{
			LinkIndex: 3,
			Dst: &net.IPNet{
				IP:   net.IPv4(1, 1, 1, 1),
				Mask: net.CIDRMask(32, 32),
			},
			Src:      net.IPv4(127, 3, 3, 3),
			Scope:    unix.RT_SCOPE_LINK,
			Priority: 13,
			Table:    unix.RT_TABLE_MAIN,
			Type:     unix.RTN_UNICAST,
			Tos:      14,
		},
		{
			LinkIndex: 3,
			Dst: &net.IPNet{
				IP:   net.IPv4(1, 1, 1, 1),
				Mask: net.CIDRMask(32, 32),
			},
			Src:      net.IPv4(127, 3, 3, 3),
			Scope:    unix.RT_SCOPE_LINK,
			Priority: 13,
			Table:    unix.RT_TABLE_MAIN,
			Type:     unix.RTN_UNICAST,
			Hoplimit: 100,
		},
		{
			LinkIndex: 10,
			MPLSDst:   &mplsDst,
			NewDst: &MPLSDestination{
				Labels: []int{200, 300},
			},
		},
		{
			Dst: nil,
			Gw:  net.IPv4(1, 1, 1, 1),
			Encap: &MPLSEncap{
				Labels: []int{100},
			},
		},
		{
			LinkIndex: 10,
			Dst: &net.IPNet{
				IP:   net.IPv4(10, 0, 0, 102),
				Mask: net.CIDRMask(32, 32),
			},
			Encap: seg6encap,
		},
		{
			Dst:       nil,
			MultiPath: []*NexthopInfo{{LinkIndex: 10}, {LinkIndex: 20}},
		},
		{
			Dst: nil,
			MultiPath: []*NexthopInfo{{
				LinkIndex: 10,
				Gw:        net.IPv4(1, 1, 1, 1),
			}, {LinkIndex: 20}},
		},
		{
			Dst: nil,
			MultiPath: []*NexthopInfo{{
				LinkIndex: 10,
				Gw:        net.IPv4(1, 1, 1, 1),
				Encap: &MPLSEncap{
					Labels: []int{100},
				},
			}, {LinkIndex: 20}},
		},
		{
			Dst: nil,
			MultiPath: []*NexthopInfo{{
				LinkIndex: 10,
				NewDst: &MPLSDestination{
					Labels: []int{200, 300},
				},
			}, {LinkIndex: 20}},
		},
		{
			Dst: nil,
			MultiPath: []*NexthopInfo{{
				LinkIndex: 10,
				Encap:     seg6encap,
			}, {LinkIndex: 20}},
		},
	}
	for i1 := range cases {
		for i2 := range cases {
			got := cases[i1].Equal(cases[i2])
			expected := i1 == i2
			if got != expected {
				t.Errorf("Equal(%q,%q) == %s but expected %s",
					cases[i1], cases[i2],
					strconv.FormatBool(got),
					strconv.FormatBool(expected))
			}
		}
	}
}

func TestIPNetEqual(t *testing.T) {
	cases := []string{
		"1.1.1.1/24", "1.1.1.0/24", "1.1.1.1/32",
		"0.0.0.0/0", "0.0.0.0/14",
		"2001:db8::/32", "2001:db8::/128",
		"2001:db8::caff/32", "2001:db8::caff/128",
		"",
	}
	for _, c1 := range cases {
		var n1 *net.IPNet
		if c1 != "" {
			var i1 net.IP
			var err1 error
			i1, n1, err1 = net.ParseCIDR(c1)
			if err1 != nil {
				panic(err1)
			}
			n1.IP = i1
		}
		for _, c2 := range cases {
			var n2 *net.IPNet
			if c2 != "" {
				var i2 net.IP
				var err2 error
				i2, n2, err2 = net.ParseCIDR(c2)
				if err2 != nil {
					panic(err2)
				}
				n2.IP = i2
			}

			got := ipNetEqual(n1, n2)
			expected := c1 == c2
			if got != expected {
				t.Errorf("IPNetEqual(%q,%q) == %s but expected %s",
					c1, c2,
					strconv.FormatBool(got),
					strconv.FormatBool(expected))
			}
		}
	}
}

func TestSEG6LocalEqual(t *testing.T) {
	// Different attributes exists in different Actions. For example, Action
	// SEG6_LOCAL_ACTION_END_X has In6Addr, SEG6_LOCAL_ACTION_END_T has Table etc.
	segs := []net.IP{net.ParseIP("fc00:a000::11")}
	// set flags for each actions.
	var flags_end [nl.SEG6_LOCAL_MAX]bool
	flags_end[nl.SEG6_LOCAL_ACTION] = true
	var flags_end_x [nl.SEG6_LOCAL_MAX]bool
	flags_end_x[nl.SEG6_LOCAL_ACTION] = true
	flags_end_x[nl.SEG6_LOCAL_NH6] = true
	var flags_end_t [nl.SEG6_LOCAL_MAX]bool
	flags_end_t[nl.SEG6_LOCAL_ACTION] = true
	flags_end_t[nl.SEG6_LOCAL_TABLE] = true
	var flags_end_dx2 [nl.SEG6_LOCAL_MAX]bool
	flags_end_dx2[nl.SEG6_LOCAL_ACTION] = true
	flags_end_dx2[nl.SEG6_LOCAL_OIF] = true
	var flags_end_dx6 [nl.SEG6_LOCAL_MAX]bool
	flags_end_dx6[nl.SEG6_LOCAL_ACTION] = true
	flags_end_dx6[nl.SEG6_LOCAL_NH6] = true
	var flags_end_dx4 [nl.SEG6_LOCAL_MAX]bool
	flags_end_dx4[nl.SEG6_LOCAL_ACTION] = true
	flags_end_dx4[nl.SEG6_LOCAL_NH4] = true
	var flags_end_dt6 [nl.SEG6_LOCAL_MAX]bool
	flags_end_dt6[nl.SEG6_LOCAL_ACTION] = true
	flags_end_dt6[nl.SEG6_LOCAL_TABLE] = true
	var flags_end_dt4 [nl.SEG6_LOCAL_MAX]bool
	flags_end_dt4[nl.SEG6_LOCAL_ACTION] = true
	flags_end_dt4[nl.SEG6_LOCAL_TABLE] = true
	var flags_end_b6 [nl.SEG6_LOCAL_MAX]bool
	flags_end_b6[nl.SEG6_LOCAL_ACTION] = true
	flags_end_b6[nl.SEG6_LOCAL_SRH] = true
	var flags_end_b6_encaps [nl.SEG6_LOCAL_MAX]bool
	flags_end_b6_encaps[nl.SEG6_LOCAL_ACTION] = true
	flags_end_b6_encaps[nl.SEG6_LOCAL_SRH] = true

	cases := []SEG6LocalEncap{
		{
			Flags:  flags_end,
			Action: nl.SEG6_LOCAL_ACTION_END,
		},
		{
			Flags:   flags_end_x,
			Action:  nl.SEG6_LOCAL_ACTION_END_X,
			In6Addr: net.ParseIP("2001:db8::1"),
		},
		{
			Flags:  flags_end_t,
			Action: nl.SEG6_LOCAL_ACTION_END_T,
			Table:  10,
		},
		{
			Flags:  flags_end_dx2,
			Action: nl.SEG6_LOCAL_ACTION_END_DX2,
			Oif:    20,
		},
		{
			Flags:   flags_end_dx6,
			Action:  nl.SEG6_LOCAL_ACTION_END_DX6,
			In6Addr: net.ParseIP("2001:db8::1"),
		},
		{
			Flags:  flags_end_dx4,
			Action: nl.SEG6_LOCAL_ACTION_END_DX4,
			InAddr: net.IPv4(192, 168, 10, 10),
		},
		{
			Flags:  flags_end_dt6,
			Action: nl.SEG6_LOCAL_ACTION_END_DT6,
			Table:  30,
		},
		{
			Flags:  flags_end_dt4,
			Action: nl.SEG6_LOCAL_ACTION_END_DT4,
			Table:  40,
		},
		{
			Flags:    flags_end_b6,
			Action:   nl.SEG6_LOCAL_ACTION_END_B6,
			Segments: segs,
		},
		{
			Flags:    flags_end_b6_encaps,
			Action:   nl.SEG6_LOCAL_ACTION_END_B6_ENCAPS,
			Segments: segs,
		},
	}
	for i1 := range cases {
		for i2 := range cases {
			got := cases[i1].Equal(&cases[i2])
			expected := i1 == i2
			if got != expected {
				t.Errorf("Equal(%v,%v) == %s but expected %s",
					cases[i1], cases[i2],
					strconv.FormatBool(got),
					strconv.FormatBool(expected))
			}
		}
	}
}
func TestSEG6RouteAddDel(t *testing.T) {
	// add/del routes with LWTUNNEL_SEG6 to/from loopback interface.
	// Test both seg6 modes: encap (IPv4) & inline (IPv6).
	tearDown := setUpSEG6NetlinkTest(t)
	defer tearDown()

	// get loopback interface and bring it up
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	dst1 := &net.IPNet{ // INLINE mode must be IPv6 route
		IP:   net.ParseIP("2001:db8::1"),
		Mask: net.CIDRMask(128, 128),
	}
	dst2 := &net.IPNet{
		IP:   net.IPv4(10, 0, 0, 102),
		Mask: net.CIDRMask(32, 32),
	}
	var s1, s2 []net.IP
	s1 = append(s1, net.ParseIP("::")) // inline requires "::"
	s1 = append(s1, net.ParseIP("fc00:a000::12"))
	s1 = append(s1, net.ParseIP("fc00:a000::11"))
	s2 = append(s2, net.ParseIP("fc00:a000::22"))
	s2 = append(s2, net.ParseIP("fc00:a000::21"))
	e1 := &SEG6Encap{Mode: nl.SEG6_IPTUN_MODE_INLINE}
	e2 := &SEG6Encap{Mode: nl.SEG6_IPTUN_MODE_ENCAP}
	e1.Segments = s1
	e2.Segments = s2
	route1 := Route{LinkIndex: link.Attrs().Index, Dst: dst1, Encap: e1}
	route2 := Route{LinkIndex: link.Attrs().Index, Dst: dst2, Encap: e2}

	// Add SEG6 routes
	if err := RouteAdd(&route1); err != nil {
		t.Fatal(err)
	}
	if err := RouteAdd(&route2); err != nil {
		t.Fatal(err)
	}
	// SEG6_IPTUN_MODE_INLINE
	routes, err := RouteList(link, FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("SEG6 routes not added properly")
	}
	for _, route := range routes {
		if route.Encap.Type() != nl.LWTUNNEL_ENCAP_SEG6 {
			t.Fatal("Invalid Type. SEG6_IPTUN_MODE_INLINE routes not added properly")
		}
	}
	// SEG6_IPTUN_MODE_ENCAP
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("SEG6 routes not added properly")
	}
	for _, route := range routes {
		if route.Encap.Type() != nl.LWTUNNEL_ENCAP_SEG6 {
			t.Fatal("Invalid Type. SEG6_IPTUN_MODE_ENCAP routes not added properly")
		}
	}

	// Del (remove) SEG6 routes
	if err := RouteDel(&route1); err != nil {
		t.Fatal(err)
	}
	if err := RouteDel(&route2); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("SEG6 routes not removed properly")
	}
}

// add/del routes with LWTUNNEL_ENCAP_SEG6_LOCAL to/from dummy interface.
func TestSEG6LocalRoute6AddDel(t *testing.T) {
	minKernelRequired(t, 4, 14)
	tearDown := setUpSEG6NetlinkTest(t)
	defer tearDown()

	// create dummy interface
	// IPv6 route added to loopback interface will be unreachable
	la := NewLinkAttrs()
	la.Name = "dummy_route6"
	la.TxQLen = 1500
	dummy := &Dummy{LinkAttrs: la}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	// get dummy interface and bring it up
	link, err := LinkByName("dummy_route6")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	dst1 := &net.IPNet{
		IP:   net.ParseIP("2001:db8::1"),
		Mask: net.CIDRMask(128, 128),
	}

	// Create Route including Action SEG6_LOCAL_ACTION_END_B6.
	// Could be any Action but thought better to have seg list.
	var s1 []net.IP
	s1 = append(s1, net.ParseIP("fc00:a000::12"))
	s1 = append(s1, net.ParseIP("fc00:a000::11"))
	var flags_end_b6_encaps [nl.SEG6_LOCAL_MAX]bool
	flags_end_b6_encaps[nl.SEG6_LOCAL_ACTION] = true
	flags_end_b6_encaps[nl.SEG6_LOCAL_SRH] = true
	e1 := &SEG6LocalEncap{
		Flags:    flags_end_b6_encaps,
		Action:   nl.SEG6_LOCAL_ACTION_END_B6,
		Segments: s1,
	}
	route1 := Route{LinkIndex: link.Attrs().Index, Dst: dst1, Encap: e1}

	// Add SEG6Local routes
	if err := RouteAdd(&route1); err != nil {
		t.Fatal(err)
	}

	// typically one route (fe80::/64) will be created when dummy_route6 is created.
	// Thus you cannot use RouteList() to find the route entry just added.
	// Lookup route and confirm it's SEG6Local route just added.
	routesFound, err := RouteGet(dst1.IP)
	if err != nil {
		t.Fatal(err)
	}
	if len(routesFound) != 1 { // should only find 1 route entry
		t.Fatal("SEG6Local route not added correctly")
	}
	if !e1.Equal(routesFound[0].Encap) {
		t.Fatal("Encap does not match the original SEG6LocalEncap")
	}

	// Del SEG6Local routes
	if err := RouteDel(&route1); err != nil {
		t.Fatal(err)
	}
	// Confirm route is deleted.
	routesFound, err = RouteGet(dst1.IP)
	if err == nil {
		t.Fatal("SEG6Local route still exists.")
	}

	// cleanup dummy interface created for the test
	if err := LinkDel(link); err != nil {
		t.Fatal(err)
	}
}

func TestBpfEncap(t *testing.T) {
	tCase := &BpfEncap{}
	if err := tCase.SetProg(nl.LWT_BPF_IN, 0, "test_in"); err == nil {
		t.Fatal("BpfEncap: inserting invalid FD did not return error")
	}
	if err := tCase.SetProg(nl.LWT_BPF_XMIT_HEADROOM, 23, "test_nout"); err == nil {
		t.Fatal("BpfEncap: inserting invalid mode did not return error")
	}
	if err := tCase.SetProg(nl.LWT_BPF_XMIT, 12, "test_xmit"); err != nil {
		t.Fatal("BpfEncap: inserting valid program option returned error")
	}
	if err := tCase.SetXmitHeadroom(12); err != nil {
		t.Fatal("BpfEncap: inserting valid headroom returned error")
	}
	if err := tCase.SetXmitHeadroom(nl.LWT_BPF_MAX_HEADROOM + 1); err == nil {
		t.Fatal("BpfEncap: inserting invalid headroom did not return error")
	}
	tCase = &BpfEncap{}

	expected := &BpfEncap{
		progs: [nl.LWT_BPF_MAX]bpfObj{
			1: {
				progName: "test_in[fd:10]",
				progFd:   10,
			},
			2: {
				progName: "test_out[fd:11]",
				progFd:   11,
			},
			3: {
				progName: "test_xmit[fd:21]",
				progFd:   21,
			},
		},
		headroom: 128,
	}

	_ = tCase.SetProg(1, 10, "test_in")
	_ = tCase.SetProg(2, 11, "test_out")
	_ = tCase.SetProg(3, 21, "test_xmit")
	_ = tCase.SetXmitHeadroom(128)
	if !tCase.Equal(expected) {
		t.Fatal("BpfEncap: equal comparison failed")
	}
	_ = tCase.SetProg(3, 21, "test2_xmit")
	if tCase.Equal(expected) {
		t.Fatal("BpfEncap: equal comparison succeeded when attributes differ")
	}
}

func TestMTURouteAddDel(t *testing.T) {
	_, err := RouteList(nil, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, MTU: 500}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	if route.MTU != routes[0].MTU {
		t.Fatal("Route mtu not set properly")
	}

	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}
}

func TestRouteViaAddDel(t *testing.T) {
	minKernelRequired(t, 5, 4)
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	_, err := RouteList(nil, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	route := &Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 0),
			Mask: net.CIDRMask(24, 32),
		},
		MultiPath: []*NexthopInfo{
			{
				LinkIndex: link.Attrs().Index,
				Via: &Via{
					AddrFamily: FAMILY_V6,
					Addr:       net.ParseIP("2001::1"),
				},
			},
		},
	}

	if err := RouteAdd(route); err != nil {
		t.Fatalf("route: %v, err: %v", route, err)
	}

	routes, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	got := routes[0].Via
	want := route.MultiPath[0].Via
	if !want.Equal(got) {
		t.Fatalf("Route Via attribute does not match; got: %s, want: %s", got, want)
	}

	if err := RouteDel(route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}
}
