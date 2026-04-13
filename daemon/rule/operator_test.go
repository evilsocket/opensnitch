package rule

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
)

var (
	defaultProcPath = "/usr/bin/opensnitchd"
	defaultProcArgs = "-rules-path /etc/opensnitchd/rules/"
	defaultDstHost  = "opensnitch.io"
	defaultDstPort  = uint(443)
	defaultDstIP    = "185.53.178.14"
	defaultUserID   = 666

	netEntry = &netstat.Entry{
		UserId: defaultUserID,
	}

	proc = &procmon.Process{
		ID:   12345,
		Path: defaultProcPath,
		Args: []string{"-rules-path", "/etc/opensnitchd/rules/"},
	}

	conn = &conman.Connection{
		Protocol: "TCP",
		SrcPort:  66666,
		SrcIP:    net.ParseIP("192.168.1.111"),
		DstIP:    net.ParseIP(defaultDstIP),
		DstPort:  defaultDstPort,
		DstHost:  defaultDstHost,
		Process:  proc,
		Entry:    netEntry,
	}
)

func compileListOperators(list *[]Operator, t *testing.T) {
	op := *list
	for i := 0; i < len(*list); i++ {
		if err := op[i].Compile(); err != nil {
			t.Error("NewOperator List, Compile() subitem error:", err)
		}
	}
}

func BenchmarkOperatorDomainsSnapshotMatchParallel(b *testing.B) {
	op := &Operator{
		Sensitive:       false,
		lists:           make(map[string]interface{}),
		domainWildcards: newDomainWildcardTrie(),
	}
	op.domainWildcards.insertSuffix("example.org")
	const globPat = "api-??.example.org"
	if err := validateDomainGlobPattern(globPat); err != nil {
		b.Fatalf("invalid benchmark glob: %v", err)
	}
	op.domainGlobs = append(op.domainGlobs, globPat)
	op.listSnapshot.Store(&listCacheSnapshot{
		lists:           op.lists,
		domainWildcards: op.domainWildcards,
		domainGlobs:     op.domainGlobs,
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !op.domainsListsCmp("svc.example.org") {
				b.Fatal("expected wildcard snapshot match")
			}
		}
	})
}

func BenchmarkOperatorDomainsSnapshotMixedParallel(b *testing.B) {
	op := &Operator{
		Sensitive:       false,
		lists:           make(map[string]interface{}),
		domainWildcards: newDomainWildcardTrie(),
	}
	op.lists["exact.example.org"] = "bench"
	op.domainWildcards.insertSuffix("example.org")
	const globPat = "api-??.example.org"
	if err := validateDomainGlobPattern(globPat); err != nil {
		b.Fatalf("invalid benchmark glob: %v", err)
	}
	op.domainGlobs = append(op.domainGlobs, globPat)
	op.listSnapshot.Store(&listCacheSnapshot{
		lists:           op.lists,
		domainWildcards: op.domainWildcards,
		domainGlobs:     op.domainGlobs,
	})

	inputs := []string{
		"exact.example.org",      // exact hit
		"svc.example.org",        // wildcard hit
		"api-12.example.org",     // glob hit
		"no-match.invalid.local", // miss
		"exact.example.org",
		"svc.example.org",
		"api-99.example.org",
		"nope.nowhere",
		"exact.example.org",
		"svc.example.org",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = op.domainsListsCmp(inputs[i%len(inputs)])
			i++
		}
	})
}

type rlockDomainMatcher struct {
	sync.RWMutex
	lists       map[string]interface{}
	wildcards   domainWildcardTrie
	domainGlobs []string
}

func (m *rlockDomainMatcher) match(host string) bool {
	m.RLock()
	defer m.RUnlock()
	if _, found := m.lists[host]; found {
		return true
	}
	if m.wildcards.matchesHost(host) {
		return true
	}
	for _, g := range m.domainGlobs {
		if matchDomainGlob(g, host) {
			return true
		}
	}
	return false
}

func BenchmarkOperatorDomainsRLockMixedParallel(b *testing.B) {
	m := &rlockDomainMatcher{
		lists:       make(map[string]interface{}),
		wildcards:   newDomainWildcardTrie(),
		domainGlobs: make([]string, 0, 1),
	}
	m.lists["exact.example.org"] = "bench"
	m.wildcards.insertSuffix("example.org")
	const globPat = "api-??.example.org"
	if err := validateDomainGlobPattern(globPat); err != nil {
		b.Fatalf("invalid benchmark glob: %v", err)
	}
	m.domainGlobs = append(m.domainGlobs, globPat)

	inputs := []string{
		"exact.example.org",
		"svc.example.org",
		"api-12.example.org",
		"no-match.invalid.local",
		"exact.example.org",
		"svc.example.org",
		"api-99.example.org",
		"nope.nowhere",
		"exact.example.org",
		"svc.example.org",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = m.match(inputs[i%len(inputs)])
			i++
		}
	})
}

type rlockIPNetMatcher struct {
	sync.RWMutex
	exact map[string]struct{}
	nets  []*net.IPNet
}

func (m *rlockIPNetMatcher) match(ip net.IP) bool {
	m.RLock()
	defer m.RUnlock()
	if _, found := m.exact[ip.String()]; found {
		return true
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func BenchmarkOperatorIPSnapshotMixedParallel(b *testing.B) {
	_, cidrA, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR A: %v", err)
	}
	_, cidrB, err := net.ParseCIDR("2002:dead:beef::/48")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR B: %v", err)
	}

	op := &Operator{}
	exact := map[string]struct{}{
		"10.0.0.4":         {},
		"2002:dead:beef::": {},
	}
	nets := []*net.IPNet{cidrA, cidrB}
	op.listSnapshot.Store(&listCacheSnapshot{
		listExact: exact,
		listNets:  nets,
	})

	inputs := []net.IP{
		net.ParseIP("10.0.0.4"),             // exact
		net.ParseIP("10.0.0.99"),            // cidr
		net.ParseIP("2002:dead:beef::"),     // exact
		net.ParseIP("2002:dead:beef::1234"), // cidr
		net.ParseIP("172.16.0.1"),           // miss
		net.ParseIP("8.8.8.8"),              // miss
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = op.ipListsCmp(inputs[i%len(inputs)])
			i++
		}
	})
}

func BenchmarkOperatorIPRLockMixedParallel(b *testing.B) {
	_, cidrA, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR A: %v", err)
	}
	_, cidrB, err := net.ParseCIDR("2002:dead:beef::/48")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR B: %v", err)
	}

	m := &rlockIPNetMatcher{
		exact: map[string]struct{}{
			"10.0.0.4":         {},
			"2002:dead:beef::": {},
		},
		nets: []*net.IPNet{cidrA, cidrB},
	}

	inputs := []net.IP{
		net.ParseIP("10.0.0.4"),
		net.ParseIP("10.0.0.99"),
		net.ParseIP("2002:dead:beef::"),
		net.ParseIP("2002:dead:beef::1234"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("8.8.8.8"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = m.match(inputs[i%len(inputs)])
			i++
		}
	})
}

func BenchmarkOperatorNetSnapshotMixedParallel(b *testing.B) {
	_, cidrA, err := net.ParseCIDR("172.16.0.0/16")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR A: %v", err)
	}
	_, cidrB, err := net.ParseCIDR("10.200.0.0/16")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR B: %v", err)
	}

	op := &Operator{}
	exact := map[string]struct{}{
		"172.16.1.2": {},
		"10.200.8.9": {},
	}
	nets := []*net.IPNet{cidrA, cidrB}
	op.listSnapshot.Store(&listCacheSnapshot{
		listExact: exact,
		listNets:  nets,
	})

	inputs := []net.IP{
		net.ParseIP("172.16.1.2"),   // exact
		net.ParseIP("172.16.44.10"), // cidr
		net.ParseIP("10.200.8.9"),   // exact
		net.ParseIP("10.200.77.1"),  // cidr
		net.ParseIP("192.168.1.10"), // miss
		net.ParseIP("1.1.1.1"),      // miss
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = op.netListsCmp(inputs[i%len(inputs)])
			i++
		}
	})
}

func BenchmarkOperatorNetRLockMixedParallel(b *testing.B) {
	_, cidrA, err := net.ParseCIDR("172.16.0.0/16")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR A: %v", err)
	}
	_, cidrB, err := net.ParseCIDR("10.200.0.0/16")
	if err != nil {
		b.Fatalf("failed to parse benchmark CIDR B: %v", err)
	}

	m := &rlockIPNetMatcher{
		exact: map[string]struct{}{
			"172.16.1.2": {},
			"10.200.8.9": {},
		},
		nets: []*net.IPNet{cidrA, cidrB},
	}

	inputs := []net.IP{
		net.ParseIP("172.16.1.2"),
		net.ParseIP("172.16.44.10"),
		net.ParseIP("10.200.8.9"),
		net.ParseIP("10.200.77.1"),
		net.ParseIP("192.168.1.10"),
		net.ParseIP("1.1.1.1"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = m.match(inputs[i%len(inputs)])
			i++
		}
	})
}

type rlockRegexpMatcher struct {
	sync.RWMutex
	entries []listRegexEntry
}

func (m *rlockRegexpMatcher) match(host string) bool {
	m.RLock()
	defer m.RUnlock()
	for _, entry := range m.entries {
		if entry.re.MatchString(host) {
			return true
		}
	}
	return false
}

func BenchmarkOperatorDomainsRegexpSnapshotMixedParallel(b *testing.B) {
	op := &Operator{}
	op.listSnapshot.Store(&listCacheSnapshot{
		regexEntries: []listRegexEntry{
			{file: "bench-a", re: mustCompileRegexpBench(b, `(^|\\.)example\\.org$`)},
			{file: "bench-b", re: mustCompileRegexpBench(b, `^api-[0-9]{2}\\.example\\.org$`)},
			{file: "bench-c", re: mustCompileRegexpBench(b, `^[a-z0-9-]+\\.service\\.internal$`)},
		},
	})

	inputs := []string{
		"www.example.org",         // hit
		"api-12.example.org",      // hit
		"node-1.service.internal", // hit
		"no-match.local",          // miss
		"api-aa.example.org",      // miss
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = op.reListCmp(inputs[i%len(inputs)])
			i++
		}
	})
}

func BenchmarkOperatorDomainsRegexpRLockMixedParallel(b *testing.B) {
	m := &rlockRegexpMatcher{
		entries: []listRegexEntry{
			{file: "bench-a", re: mustCompileRegexpBench(b, `(^|\\.)example\\.org$`)},
			{file: "bench-b", re: mustCompileRegexpBench(b, `^api-[0-9]{2}\\.example\\.org$`)},
			{file: "bench-c", re: mustCompileRegexpBench(b, `^[a-z0-9-]+\\.service\\.internal$`)},
		},
	}

	inputs := []string{
		"www.example.org",
		"api-12.example.org",
		"node-1.service.internal",
		"no-match.local",
		"api-aa.example.org",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = m.match(inputs[i%len(inputs)])
			i++
		}
	})
}

func mustCompileRegexpBench(b *testing.B, pattern string) *regexp.Regexp {
	b.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		b.Fatalf("failed to compile benchmark regexp %q: %v", pattern, err)
	}
	return re
}

func BenchmarkLoaderFindFirstMatchSnapshotParallel(b *testing.B) {
	loader := &Loader{rules: make(map[string]*Rule)}

	dummyList := make([]Operator, 0)
	nonMatchOp, err := NewOperator(Simple, false, OpDstHost, "does-not-match.example", dummyList)
	if err != nil {
		b.Fatalf("failed creating non-match operator: %v", err)
	}
	if err := nonMatchOp.Compile(); err != nil {
		b.Fatalf("failed compiling non-match operator: %v", err)
	}

	matchOp, err := NewOperator(Simple, false, OpDstHost, "opensnitch.io", dummyList)
	if err != nil {
		b.Fatalf("failed creating match operator: %v", err)
	}
	if err := matchOp.Compile(); err != nil {
		b.Fatalf("failed compiling match operator: %v", err)
	}

	for i := 0; i < 63; i++ {
		r := Create(fmt.Sprintf("%03d-non-match", i), "", true, false, false, Allow, Always, nonMatchOp)
		loader.rules[r.Name] = r
	}
	matchRule := Create("999-match", "", true, false, false, Allow, Always, matchOp)
	loader.rules[matchRule.Name] = matchRule
	loader.sortRules()

	conn := &conman.Connection{DstHost: "opensnitch.io"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if loader.FindFirstMatch(conn) == nil {
				b.Fatal("expected non-nil matching rule")
			}
		}
	})
}

func unmarshalListData(data string, t *testing.T) (op *[]Operator) {
	if err := json.Unmarshal([]byte(data), &op); err != nil {
		t.Error("Error unmarshalling list data:", err, data)
		return nil
	}
	return op
}

func restoreConnection() {
	conn.Process.Path = defaultProcPath
	conn.DstHost = defaultDstHost
	conn.DstPort = defaultDstPort
	conn.Entry.UserId = defaultUserID
}

func TestNewOperatorSimple(t *testing.T) {
	t.Log("Test NewOperator() simple")
	var list []Operator

	opSimple, err := NewOperator(Simple, false, OpTrue, "", list)
	if err != nil {
		t.Error("NewOperator simple.err should be nil: ", err)
		t.Fail()
	}
	if err = opSimple.Compile(); err != nil {
		t.Fail()
	}
	if opSimple.Match(nil, false) == false {
		t.Error("Test NewOperator() simple.case-insensitive doesn't match")
		t.Fail()
	}

	t.Run("Operator Simple proc.id", func(t *testing.T) {
		// proc.id not sensitive
		opSimple, err = NewOperator(Simple, false, OpProcessID, "12345", list)
		if err != nil {
			t.Error("NewOperator simple.case-insensitive.proc.id err should be nil: ", err)
			t.Fail()
		}
		if err = opSimple.Compile(); err != nil {
			t.Error("NewOperator simple.case-insensitive.proc.id Compile() err:", err)
			t.Fail()
		}
		if opSimple.Match(conn, false) == false {
			t.Error("Test NewOperator() simple proc.id doesn't match")
			t.Fail()
		}
	})

	opSimple, err = NewOperator(Simple, false, OpProcessPath, defaultProcPath, list)
	t.Run("Operator Simple proc.path case-insensitive", func(t *testing.T) {
		// proc path not sensitive
		if err != nil {
			t.Error("NewOperator simple proc.path err should be nil: ", err)
			t.Fail()
		}
		if err = opSimple.Compile(); err != nil {
			t.Error("NewOperator simple.case-insensitive.proc.path Compile() err:", err)
			t.Fail()
		}
		if opSimple.Match(conn, false) == false {
			t.Error("Test NewOperator() simple proc.path doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator Simple proc.path sensitive", func(t *testing.T) {
		// proc path sensitive
		opSimple.Sensitive = true
		conn.Process.Path = "/usr/bin/OpenSnitchd"
		if opSimple.Match(conn, false) == true {
			t.Error("Test NewOperator() simple proc.path sensitive match")
			t.Fail()
		}
	})

	opSimple, err = NewOperator(Simple, false, OpDstHost, defaultDstHost, list)
	t.Run("Operator Simple con.dstHost case-insensitive", func(t *testing.T) {
		// proc dst host not sensitive
		if err != nil {
			t.Error("NewOperator simple proc.path err should be nil: ", err)
			t.Fail()
		}
		if err = opSimple.Compile(); err != nil {
			t.Error("NewOperator simple.case-insensitive.dstHost Compile() err:", err)
			t.Fail()
		}
		if opSimple.Match(conn, false) == false {
			t.Error("Test NewOperator() simple.conn.dstHost.not-sensitive doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator Simple con.dstHost case-insensitive different host", func(t *testing.T) {
		conn.DstHost = "www.opensnitch.io"
		if opSimple.Match(conn, false) == true {
			t.Error("Test NewOperator() simple.conn.dstHost.not-sensitive doesn't MATCH")
			t.Fail()
		}
	})

	t.Run("Operator Simple con.dstHost sensitive", func(t *testing.T) {
		// proc dst host sensitive
		opSimple, err = NewOperator(Simple, true, OpDstHost, "OpEnsNitCh.io", list)
		if err != nil {
			t.Error("NewOperator simple.dstHost.sensitive err should be nil: ", err)
			t.Fail()
		}
		if err = opSimple.Compile(); err != nil {
			t.Error("NewOperator simple.dstHost.sensitive Compile() err:", err)
			t.Fail()
		}
		conn.DstHost = "OpEnsNitCh.io"
		if opSimple.Match(conn, false) == false {
			t.Error("Test NewOperator() simple.dstHost.sensitive doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator Simple proc.args case-insensitive", func(t *testing.T) {
		// proc args case-insensitive
		opSimple, err = NewOperator(Simple, false, OpProcessCmd, defaultProcArgs, list)
		if err != nil {
			t.Error("NewOperator simple proc.args err should be nil: ", err)
			t.Fail()
		}
		if err = opSimple.Compile(); err != nil {
			t.Error("NewOperator simple proc.args Compile() err: ", err)
			t.Fail()
		}
		if opSimple.Match(conn, false) == false {
			t.Error("Test NewOperator() simple proc.args doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator Simple con.dstIp case-insensitive", func(t *testing.T) {
		// proc dstIp case-insensitive
		opSimple, err = NewOperator(Simple, false, OpDstIP, defaultDstIP, list)
		if err != nil {
			t.Error("NewOperator simple conn.dstip.err should be nil: ", err)
			t.Fail()
		}
		if err = opSimple.Compile(); err != nil {
			t.Error("NewOperator simple con.dstIp Compile() err: ", err)
			t.Fail()
		}
		if opSimple.Match(conn, false) == false {
			t.Error("Test NewOperator() simple conn.dstip doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator Simple UserId case-insensitive", func(t *testing.T) {
		// conn.uid case-insensitive
		opSimple, err = NewOperator(Simple, false, OpUserID, fmt.Sprint(defaultUserID), list)
		if err != nil {
			t.Error("NewOperator simple conn.userid.err should be nil: ", err)
			t.Fail()
		}
		if err = opSimple.Compile(); err != nil {
			t.Error("NewOperator simple UserId Compile() err: ", err)
			t.Fail()
		}
		if opSimple.Match(conn, false) == false {
			t.Error("Test NewOperator() simple conn.userid doesn't match")
			t.Fail()
		}
	})

	restoreConnection()
}

func TestNewOperatorNetwork(t *testing.T) {
	t.Log("Test NewOperator() network")
	var dummyList []Operator

	opSimple, err := NewOperator(Network, false, OpDstNetwork, "185.53.178.14/24", dummyList)
	if err != nil {
		t.Error("NewOperator network.err should be nil: ", err)
		t.Fail()
	}
	if err = opSimple.Compile(); err != nil {
		t.Fail()
	}
	if opSimple.Match(conn, false) == false {
		t.Error("Test NewOperator() network doesn't match")
		t.Fail()
	}

	opSimple, err = NewOperator(Network, false, OpDstNetwork, "8.8.8.8/24", dummyList)
	if err != nil {
		t.Error("NewOperator network.err should be nil: ", err)
		t.Fail()
	}
	if err = opSimple.Compile(); err != nil {
		t.Fail()
	}
	if opSimple.Match(conn, false) == true {
		t.Error("Test NewOperator() network doesn't match:", conn.DstIP)
		t.Fail()
	}

	restoreConnection()
}

func TestNewOperatorRegexp(t *testing.T) {
	t.Log("Test NewOperator() regexp")
	var dummyList []Operator

	opRE, err := NewOperator(Regexp, false, OpProto, "^TCP$", dummyList)
	if err != nil {
		t.Error("NewOperator regexp.err should be nil: ", err)
		t.Fail()
	}
	if err = opRE.Compile(); err != nil {
		t.Fail()
	}
	if opRE.Match(conn, false) == false {
		t.Error("Test NewOperator() regexp doesn't match")
		t.Fail()
	}

	restoreConnection()
}

func TestNewOperatorInvalidRegexp(t *testing.T) {
	t.Log("Test NewOperator() invalid regexp")
	var dummyList []Operator

	opRE, err := NewOperator(Regexp, false, OpProto, "^TC(P$", dummyList)
	if err != nil {
		t.Error("NewOperator regexp.err should be nil: ", err)
		t.Fail()
	}
	if err = opRE.Compile(); err == nil {
		t.Error("NewOperator() invalid regexp. It should fail: ", err)
		t.Fail()
	}

	restoreConnection()
}

func TestNewOperatorRegexpSensitive(t *testing.T) {
	t.Log("Test NewOperator() regexp sensitive")
	var dummyList []Operator

	var sensitive Sensitive
	sensitive = true

	conn.Process.Path = "/tmp/cUrL"

	opRE, err := NewOperator(Regexp, sensitive, OpProcessPath, "^/tmp/cUrL$", dummyList)
	if err != nil {
		t.Error("NewOperator regexp.case-sensitive.err should be nil: ", err)
		t.Fail()
	}
	if err = opRE.Compile(); err != nil {
		t.Fail()
	}
	if opRE.Match(conn, false) == false {
		t.Error("Test NewOperator() RE sensitive doesn't match:", conn.Process.Path)
		t.Fail()
	}

	t.Run("Operator regexp proc.path case-sensitive", func(t *testing.T) {
		conn.Process.Path = "/tmp/curl"
		if opRE.Match(conn, false) == true {
			t.Error("Test NewOperator() RE sensitive match:", conn.Process.Path)
			t.Fail()
		}
	})

	opRE, err = NewOperator(Regexp, !sensitive, OpProcessPath, "^/tmp/cUrL$", dummyList)
	if err != nil {
		t.Error("NewOperator regexp.case-insensitive.err should be nil: ", err)
		t.Fail()
	}
	if err = opRE.Compile(); err != nil {
		t.Fail()
	}
	if opRE.Match(conn, false) == false {
		t.Error("Test NewOperator() RE not sensitive match:", conn.Process.Path)
		t.Fail()
	}

	restoreConnection()
}

func TestNewOperatorList(t *testing.T) {
	t.Log("Test NewOperator() List")
	var list []Operator
	listData := `[{"type": "simple", "operand": "dest.ip", "data": "185.53.178.14", "sensitive": false}, {"type": "simple", "operand": "dest.port", "data": "443", "sensitive": false}]`

	// simple list
	opList, err := NewOperator(List, false, OpProto, listData, list)
	t.Run("Operator List simple case-insensitive", func(t *testing.T) {
		if err != nil {
			t.Error("NewOperator list.regexp.err should be nil: ", err)
			t.Fail()
		}
		if err = opList.Compile(); err != nil {
			t.Error("NewOperator list.regexp.err compiling:", err)
			t.Fail()
		}
		opList.List = *unmarshalListData(opList.Data, t)
		compileListOperators(&opList.List, t)
		if opList.Match(conn, false) == false {
			t.Error("Test NewOperator() list simple doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator List regexp case-insensitive", func(t *testing.T) {
		// list with regexp, case-insensitive
		listData = `[{"type": "regexp", "operand": "process.path", "data": "^/usr/bin/.*", "sensitive": false},{"type": "simple", "operand": "dest.ip", "data": "185.53.178.14", "sensitive": false}, {"type": "simple", "operand": "dest.port", "data": "443", "sensitive": false}]`
		opList.List = *unmarshalListData(listData, t)
		compileListOperators(&opList.List, t)
		if err = opList.Compile(); err != nil {
			t.Fail()
		}
		if opList.Match(conn, false) == false {
			t.Error("Test NewOperator() list regexp doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator List regexp case-sensitive", func(t *testing.T) {
		// list with regexp, case-sensitive
		// "data": "^/usr/BiN/.*" must match conn.Process.Path (sensitive)
		listData = `[{"type": "regexp", "operand": "process.path", "data": "^/usr/BiN/.*", "sensitive": true},{"type": "simple", "operand": "dest.ip", "data": "185.53.178.14", "sensitive": false}, {"type": "simple", "operand": "dest.port", "data": "443", "sensitive": false}]`
		opList.List = *unmarshalListData(listData, t)
		compileListOperators(&opList.List, t)
		conn.Process.Path = "/usr/BiN/opensnitchd"
		opList.Sensitive = true
		if err = opList.Compile(); err != nil {
			t.Fail()
		}
		if opList.Match(conn, false) == false {
			t.Error("Test NewOperator() list.regexp.sensitive doesn't match:", conn.Process.Path)
			t.Fail()
		}
	})

	// These tests check how the global Sensitive field on a List operand affect
	// the children Operands.
	// As of v1.8.0 it has no effect.
	/*t.Run("Operator List regexp case-insensitive 2", func(t *testing.T) {
		// "data": "^/usr/BiN/.*" must not match conn.Process.Path (insensitive)
		opList.Sensitive = false
		conn.Process.Path = "/USR/BiN/opensnitchd"
		if err = opList.Compile(); err != nil {
			t.Fail()
		}
		if opList.Match(conn, false) == false {
			t.Error("Test NewOperator() list.regexp.insensitive match:", conn.Process.Path)
			t.Fail()
		}
	})

	t.Run("Operator List regexp case-insensitive 3", func(t *testing.T) {
		// "data": "^/usr/BiN/.*" must match conn.Process.Path (insensitive)
		opList.Sensitive = false
		conn.Process.Path = "/USR/bin/opensnitchd"
		if err = opList.Compile(); err != nil {
			t.Fail()
		}
		if opList.Match(conn, false) == false {
			t.Error("Test NewOperator() list.regexp.insensitive match:", conn.Process.Path)
			t.Fail()
		}
	})*/

	restoreConnection()
}

func TestNewOperatorListsSimple(t *testing.T) {
	t.Log("Test NewOperator() Lists simple")
	var dummyList []Operator

	opLists, err := NewOperator(Lists, false, OpDomainsLists, "testdata/lists/domains/", dummyList)
	if err != nil {
		t.Error("NewOperator Lists, shouldn't be nil: ", err)
		t.Fail()
	}
	if err = opLists.Compile(); err != nil {
		t.Error("NewOperator Lists, Compile() error:", err)
	}
	time.Sleep(time.Second)
	t.Log("testing Lists, DstHost:", conn.DstHost)
	// The list contains 4 lines, 1 is a comment and there's a domain duplicated.
	// We should only load lines that start with 0.0.0.0 or 127.0.0.1
	if len(opLists.lists) != 2 {
		t.Error("NewOperator Lists, number of domains error:", opLists.lists, len(opLists.lists))
	}
	if opLists.Match(conn, false) == false {
		t.Error("Test NewOperator() lists doesn't match")
	}

	opLists.StopMonitoringLists()
	time.Sleep(time.Second)
	opLists.Lock()
	if len(opLists.lists) != 0 {
		t.Error("NewOperator Lists, number should be 0 after stop:", opLists.lists, len(opLists.lists))
	}
	opLists.Unlock()

	restoreConnection()
}

func TestNewOperatorListsIPs(t *testing.T) {
	t.Log("Test NewOperator() Lists domains_regexp")

	var subOp *Operator
	var list []Operator
	listData := `[{"type": "simple", "operand": "user.id", "data": "666", "sensitive": false}, {"type": "lists", "operand": "lists.ips", "data": "testdata/lists/ips/", "sensitive": false}]`

	opLists, err := NewOperator(List, false, OpList, listData, list)
	if err != nil {
		t.Error("NewOperator Lists domains_regexp, shouldn't be nil: ", err)
		t.Fail()
	}
	if err := opLists.Compile(); err != nil {
		t.Error("NewOperator Lists domains_regexp, Compile() error:", err)
	}
	opLists.List = *unmarshalListData(opLists.Data, t)
	for i := 0; i < len(opLists.List); i++ {
		if err := opLists.List[i].Compile(); err != nil {
			t.Error("NewOperator Lists domains_regexp, Compile() subitem error:", err)
		}
		if opLists.List[i].Type == Lists {
			subOp = &opLists.List[i]
		}
	}

	time.Sleep(time.Second)
	if opLists.Match(conn, false) == false {
		t.Error("Test NewOperator() Lists domains_regexp, doesn't match:", conn.DstHost)
	}

	subOp.Lock()
	listslen := len(subOp.lists)
	subOp.Unlock()
	if listslen != 2 {
		t.Error("NewOperator Lists domains_regexp, number of domains error:", subOp.lists)
	}

	//t.Log("checking lists.domains_regexp:", tries, conn.DstHost)
	if opLists.Match(conn, false) == false {
		// we don't care about if it matches, we're testing race conditions
		t.Log("Test NewOperator() Lists domains_regexp, doesn't match:", conn.DstHost)
	}

	subOp.StopMonitoringLists()
	time.Sleep(time.Second)
	subOp.Lock()
	if len(subOp.lists) != 0 {
		t.Error("NewOperator Lists number should be 0:", subOp.lists, len(subOp.lists))
	}
	subOp.Unlock()

	restoreConnection()
}

func TestNewOperatorListsNETs(t *testing.T) {
	t.Log("Test NewOperator() Lists domains_regexp")

	var subOp *Operator
	var list []Operator
	listData := `[{"type": "simple", "operand": "user.id", "data": "666", "sensitive": false}, {"type": "lists", "operand": "lists.nets", "data": "testdata/lists/nets/", "sensitive": false}]`

	opLists, err := NewOperator(List, false, OpList, listData, list)
	if err != nil {
		t.Error("NewOperator Lists domains_regexp, shouldn't be nil: ", err)
		t.Fail()
	}
	if err := opLists.Compile(); err != nil {
		t.Error("NewOperator Lists domains_regexp, Compile() error:", err)
	}
	opLists.List = *unmarshalListData(opLists.Data, t)
	for i := 0; i < len(opLists.List); i++ {
		if err := opLists.List[i].Compile(); err != nil {
			t.Error("NewOperator Lists domains_regexp, Compile() subitem error:", err)
		}
		if opLists.List[i].Type == Lists {
			subOp = &opLists.List[i]
		}
	}

	time.Sleep(time.Second)
	if opLists.Match(conn, false) == false {
		t.Error("Test NewOperator() Lists domains_regexp, doesn't match:", conn.DstHost)
	}

	subOp.Lock()
	listslen := len(subOp.lists)
	subOp.Unlock()
	if listslen != 2 {
		t.Error("NewOperator Lists domains_regexp, number of domains error:", subOp.lists)
	}

	//t.Log("checking lists.domains_regexp:", tries, conn.DstHost)
	if opLists.Match(conn, false) == false {
		// we don't care about if it matches, we're testing race conditions
		t.Log("Test NewOperator() Lists domains_regexp, doesn't match:", conn.DstHost)
	}

	subOp.StopMonitoringLists()
	time.Sleep(time.Second)
	subOp.Lock()
	if len(subOp.lists) != 0 {
		t.Error("NewOperator Lists number should be 0:", subOp.lists, len(subOp.lists))
	}
	subOp.Unlock()

	restoreConnection()
}

func TestNewOperatorListsComplex(t *testing.T) {
	t.Log("Test NewOperator() Lists complex")
	var subOp *Operator
	var list []Operator
	listData := `[{"type": "simple", "operand": "user.id", "data": "666", "sensitive": false}, {"type": "lists", "operand": "lists.domains", "data": "testdata/lists/domains/", "sensitive": false}]`

	opLists, err := NewOperator(List, false, OpList, listData, list)
	if err != nil {
		t.Error("NewOperator Lists complex, shouldn't be nil: ", err)
		t.Fail()
	}
	if err := opLists.Compile(); err != nil {
		t.Error("NewOperator Lists complex, Compile() error:", err)
	}
	opLists.List = *unmarshalListData(opLists.Data, t)
	for i := 0; i < len(opLists.List); i++ {
		if err := opLists.List[i].Compile(); err != nil {
			t.Error("NewOperator Lists complex, Compile() subitem error:", err)
		}
		if opLists.List[i].Type == Lists {
			subOp = &opLists.List[i]
		}
	}
	time.Sleep(time.Second)
	subOp.Lock()
	if len(subOp.lists) != 2 {
		t.Error("NewOperator Lists complex, number of domains error:", subOp.lists)
	}
	subOp.Unlock()
	if opLists.Match(conn, false) == false {
		t.Error("Test NewOperator() Lists complex, doesn't match")
	}

	subOp.StopMonitoringLists()
	time.Sleep(time.Second)
	subOp.Lock()
	if len(subOp.lists) != 0 {
		t.Error("NewOperator Lists number should be 0:", subOp.lists, len(subOp.lists))
	}
	subOp.Unlock()

	restoreConnection()
}

func TestNewOperatorListsDomainsRegexp(t *testing.T) {
	t.Log("Test NewOperator() Lists domains_regexp")

	var subOp *Operator
	var list []Operator
	listData := `[{"type": "simple", "operand": "user.id", "data": "666", "sensitive": false}, {"type": "lists", "operand": "lists.domains_regexp", "data": "testdata/lists/regexp/", "sensitive": false}]`

	opLists, err := NewOperator(List, false, OpList, listData, list)
	if err != nil {
		t.Error("NewOperator Lists domains_regexp, shouldn't be nil: ", err)
		t.Fail()
	}
	if err := opLists.Compile(); err != nil {
		t.Error("NewOperator Lists domains_regexp, Compile() error:", err)
	}
	opLists.List = *unmarshalListData(opLists.Data, t)
	for i := 0; i < len(opLists.List); i++ {
		if err := opLists.List[i].Compile(); err != nil {
			t.Error("NewOperator Lists domains_regexp, Compile() subitem error:", err)
		}
		if opLists.List[i].Type == Lists {
			subOp = &opLists.List[i]
		}
	}

	time.Sleep(time.Second)
	if opLists.Match(conn, false) == false {
		t.Error("Test NewOperator() Lists domains_regexp, doesn't match:", conn.DstHost)
	}

	subOp.Lock()
	listslen := len(subOp.lists)
	subOp.Unlock()
	if listslen != 2 {
		t.Error("NewOperator Lists domains_regexp, number of domains error:", subOp.lists)
	}

	//t.Log("checking lists.domains_regexp:", tries, conn.DstHost)
	if opLists.Match(conn, false) == false {
		// we don't care about if it matches, we're testing race conditions
		t.Log("Test NewOperator() Lists domains_regexp, doesn't match:", conn.DstHost)
	}

	subOp.StopMonitoringLists()
	time.Sleep(time.Second)
	subOp.Lock()
	if len(subOp.lists) != 0 {
		t.Error("NewOperator Lists number should be 0:", subOp.lists, len(subOp.lists))
	}
	subOp.Unlock()

	restoreConnection()
}

func TestDomainsListsWildcardAndGlobFallback(t *testing.T) {
	op := &Operator{
		Sensitive:       false,
		lists:           make(map[string]interface{}),
		domainWildcards: newDomainWildcardTrie(),
	}
	op.domainWildcards.insertSuffix("example.org")
	const globPat = "api-??.example.org"
	if err := validateDomainGlobPattern(globPat); err != nil {
		t.Fatalf("invalid test glob: %v", err)
	}
	op.domainGlobs = append(op.domainGlobs, globPat)
	op.listSnapshot.Store(&listCacheSnapshot{
		lists:           op.lists,
		domainWildcards: op.domainWildcards,
		domainGlobs:     op.domainGlobs,
	})

	if !op.domainsListsCmp("svc.example.org") {
		t.Fatal("expected wildcard trie fallback match")
	}
	if op.domainsListsCmp("example.org") {
		t.Fatal("wildcard fallback must not match suffix root")
	}
	if !op.domainsListsCmp("api-12.example.org") {
		t.Fatal("expected glob fallback match")
	}
}

func TestMatchDomainGlobLabelBoundary(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
		desc    string
	}{
		{"api-??.example.org", "api-12.example.org", true, "? matches single char in label"},
		{"api-??.example.org", "api-123.example.org", false, "? must not match more than one char"},
		{"api*.example.org", "apidev.example.org", true, "* matches within label"},
		{"api*.example.org", "api.v2.example.org", false, "* must not cross label boundary"},
		{"tracker-[0-9].example.org", "tracker-3.example.org", true, "character class in label"},
		{"tracker-[0-9].example.org", "tracker-x.example.org", false, "character class mismatch"},
		{"api-??.example.org", "api-12.sub.example.org", false, "different label count"},
	}
	for _, tc := range tests {
		got := matchDomainGlob(tc.pattern, tc.host)
		if got != tc.want {
			t.Errorf("%s: matchDomainGlob(%q, %q) = %v, want %v", tc.desc, tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestIPListsCmpSupportsExactAndCIDRFallback(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("failed to parse cidr: %v", err)
	}

	op := &Operator{
		listExact: map[string]struct{}{
			"10.0.0.4": {},
		},
		listNets: []*net.IPNet{cidr},
	}
	op.listSnapshot.Store(&listCacheSnapshot{
		listExact: op.listExact,
		listNets:  op.listNets,
	})

	if !op.ipListsCmp(net.ParseIP("10.0.0.4")) {
		t.Fatal("expected exact ip list match")
	}
	if !op.ipListsCmp(net.ParseIP("10.0.0.99")) {
		t.Fatal("expected cidr fallback match for ip list")
	}
	if op.ipListsCmp(net.ParseIP("192.168.1.10")) {
		t.Fatal("unexpected ip list match")
	}
}

func TestNetListsCmpSupportsExactAndCIDRFallback(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.1.0.0/16")
	if err != nil {
		t.Fatalf("failed to parse cidr: %v", err)
	}

	op := &Operator{
		listExact: map[string]struct{}{
			"10.1.2.3": {},
		},
		listNets: []*net.IPNet{cidr},
	}
	op.listSnapshot.Store(&listCacheSnapshot{
		listExact: op.listExact,
		listNets:  op.listNets,
	})

	if !op.netListsCmp(net.ParseIP("10.1.2.3")) {
		t.Fatal("expected exact net list match")
	}
	if !op.netListsCmp(net.ParseIP("10.1.44.5")) {
		t.Fatal("expected cidr fallback match for net list")
	}
	if op.netListsCmp(net.ParseIP("172.16.0.1")) {
		t.Fatal("unexpected net list match")
	}
}

// Must be launched with -race to test that we don't cause leaks
// Race occured on operator.go:241 reListCmp().MathString()
// fixed here: 53419fe
func TestRaceNewOperatorListsDomainsRegexp(t *testing.T) {
	t.Log("Test NewOperator() Lists domains_regexp")

	var subOp *Operator
	var list []Operator
	listData := `[{"type": "simple", "operand": "user.id", "data": "666", "sensitive": false}, {"type": "lists", "operand": "lists.domains_regexp", "data": "testdata/lists/regexp/", "sensitive": false}]`

	opLists, err := NewOperator(List, false, OpList, listData, list)
	if err != nil {
		t.Error("NewOperator Lists domains_regexp, shouldn't be nil: ", err)
		t.Fail()
	}
	if err := opLists.Compile(); err != nil {
		t.Error("NewOperator Lists domains_regexp, Compile() error:", err)
	}
	opLists.List = *unmarshalListData(opLists.Data, t)
	for i := 0; i < len(opLists.List); i++ {
		if err := opLists.List[i].Compile(); err != nil {
			t.Error("NewOperator Lists domains_regexp, Compile() subitem error:", err)
		}
		if opLists.List[i].Type == Lists {
			subOp = &opLists.List[i]
		}
	}

	// touch domains list in background, to force a reload.
	go func() {
		touches := 1000
		for {
			if touches < 0 {
				break
			}
			core.Exec("/bin/touch", []string{"testdata/lists/regexp/domainsregexp.txt"})
			touches--
			time.Sleep(100 * time.Millisecond)
			//t.Log("touching:", touches)
		}
	}()

	time.Sleep(time.Second)

	subOp.Lock()
	listslen := len(subOp.lists)
	subOp.Unlock()
	if listslen != 2 {
		t.Error("NewOperator Lists domains_regexp, number of domains error:", subOp.lists)
	}

	tries := 10000
	for {
		if tries < 0 {
			break
		}
		//t.Log("checking lists.domains_regexp:", tries, conn.DstHost)
		if opLists.Match(conn, false) == false {
			// we don't care about if it matches, we're testing race conditions
			t.Log("Test NewOperator() Lists domains_regexp, doesn't match:", conn.DstHost)
		}

		tries--
		time.Sleep(10 * time.Millisecond)
	}

	subOp.StopMonitoringLists()
	time.Sleep(time.Second)
	subOp.Lock()
	if len(subOp.lists) != 0 {
		t.Error("NewOperator Lists number should be 0:", subOp.lists, len(subOp.lists))
	}
	subOp.Unlock()

	restoreConnection()
}

func TestNewOperatorRegexpBareIpNoHostName(t *testing.T) {
	t.Log("Test NewOperator() regex bare IP (no host name)")
	var dummyList []Operator

	conn.DstHost = ""

	opRE, err := NewOperator(Regexp, true, OpDstHost, "^$", dummyList)
	if err != nil {
		t.Error("NewOperator regexp.case-sensitive.err should be nil: ", err)
		t.Fail()
	}
	if err = opRE.Compile(); err != nil {
		t.Fail()
	}
	if opRE.Match(conn, false) == false {
		t.Error("Test NewOperator() RE sensitive match:", conn.DstHost)
		t.Fail()
	}

	restoreConnection()
}

func TestNewOperatorSimpleBareIpNoHostName(t *testing.T) {
	t.Log("Test NewOperator() simple bare IP (no host name)")
	var dummyList []Operator

	conn.DstHost = ""

	opSimple, err := NewOperator(Simple, true, OpDstHost, "", dummyList)
	if err != nil {
		t.Error("NewOperator simple.case-sensitive.err should be nil: ", err)
		t.Fail()
	}
	if err = opSimple.Compile(); err != nil {
		t.Fail()
	}
	if opSimple.Match(conn, false) == false {
		t.Error("Test NewOperator() simple sensitive match:", conn.DstHost)
		t.Fail()
	}

	restoreConnection()
}

func TestNewOperatorRange(t *testing.T) {
	t.Log("Test NewOperator() range")
	var list []Operator

	tests := map[string]bool{
		"1-5000":  true,
		"443-445": true,
		// we should not allow spaces, but we trim them when compiling the operator
		"1 - 5000": true,
		"1-442":    false,
		"89-80":    true,
		"-80":      true,
		"53-":      true,
	}

	for r, expected := range tests {
		t.Run(fmt.Sprintf("Operator Range conn.dst_port %s", r), func(t *testing.T) {
			opRange, err := NewOperator(Range, false, OpDstPort, r, list)
			if err != nil {
				t.Error("NewOperator range.err should be nil: ", err, r)
				t.Fail()
			}
			if err = opRange.Compile(); err != nil {
				if expected {
					return
				}
				t.Error("Test NewOperator() range doesn't compile", r)
				t.Fail()
			}
			if opRange.Match(conn, false) != expected {
				t.Error("Test NewOperator() range doesn't match", r)
				t.Fail()
			}
		})
	}

	restoreConnection()
}
