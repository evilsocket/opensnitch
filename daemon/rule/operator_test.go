package rule

import (
	"encoding/json"
	"fmt"
	"net"
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
		listData = `[{"type": "regexp", "operand": "process.path", "data": "^/usr/BiN/.*", "sensitive": false},{"type": "simple", "operand": "dest.ip", "data": "185.53.178.14", "sensitive": false}, {"type": "simple", "operand": "dest.port", "data": "443", "sensitive": false}]`
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

	t.Run("Operator List regexp case-insensitive 2", func(t *testing.T) {
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
	})

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
