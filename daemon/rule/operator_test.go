package rule

import (
	"fmt"
	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"net"
	"testing"
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
	if opSimple.Match(nil) == false {
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
		if opSimple.Match(conn) == false {
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
		if opSimple.Match(conn) == false {
			t.Error("Test NewOperator() simple proc.path doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator Simple proc.path sensitive", func(t *testing.T) {
		// proc path sensitive
		opSimple.Sensitive = true
		conn.Process.Path = "/usr/bin/OpenSnitchd"
		if opSimple.Match(conn) == true {
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
		if opSimple.Match(conn) == false {
			t.Error("Test NewOperator() simple.conn.dstHost.not-sensitive doesn't match")
			t.Fail()
		}
	})

	t.Run("Operator Simple con.dstHost case-insensitive different host", func(t *testing.T) {
		conn.DstHost = "www.opensnitch.io"
		if opSimple.Match(conn) == true {
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
		conn.DstHost = "OpEnsNitCh.io"
		if opSimple.Match(conn) == false {
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
		if opSimple.Match(conn) == false {
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
		if opSimple.Match(conn) == false {
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
		if opSimple.Match(conn) == false {
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
	if opSimple.Match(conn) == false {
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
	if opSimple.Match(conn) == true {
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
	if opRE.Match(conn) == false {
		t.Error("Test NewOperator() regexp doesn't match")
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
	if opRE.Match(conn) == false {
		t.Error("Test NewOperator() RE sensitive doesn't match:", conn.Process.Path)
		t.Fail()
	}

	t.Run("Operator regexp proc.path case-sensitive", func(t *testing.T) {
		conn.Process.Path = "/tmp/curl"
		if opRE.Match(conn) == true {
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
	if opRE.Match(conn) == false {
		t.Error("Test NewOperator() RE not sensitive match:", conn.Process.Path)
		t.Fail()
	}

	restoreConnection()
}

func TestNewOperatorList(t *testing.T) {
	t.Log("Test NewOperator() regexp")
	var list []Operator
	listData := `[{"type": "simple", "operand": "dest.ip", "data": "185.53.178.14", "sensitive": false}, {"type": "simple", "operand": "dest.port", "data": "443", "sensitive": false}]`

	// simple list
	opList, err := NewOperator(List, false, OpProto, listData, list)
	if err != nil {
		t.Error("NewOperator list.regexp.err should be nil: ", err)
		t.Fail()
	}
	if err = opList.Compile(); err != nil {
		t.Fail()
	}
	if opList.Match(conn) == false {
		t.Error("Test NewOperator() list simple doesn't match")
		t.Fail()
	}

	// list with regexp, case-insensitive
	listData = `["type": "regexp", "operand": "process.path", "data": "^/usr/bin/.*", "sensitive": false},{"type": "simple", "operand": "dest.ip", "data": "185.53.178.14", "sensitive": false}, {"type": "simple", "operand": "dest.port", "data": "443", "sensitive": false}]`
	if err = opList.Compile(); err != nil {
		t.Fail()
	}
	if opList.Match(conn) == false {
		t.Error("Test NewOperator() list regexp doesn't match")
		t.Fail()
	}

	// list with regexp, case-sensitive
	// "data": "^/usr/BiN/.*" must match conn.Process.Path (sensitive)
	opList.Data = `["type": "regexp", "operand": "process.path", "data": "^/usr/BiN/.*", "sensitive": false},{"type": "simple", "operand": "dest.ip", "data": "185.53.178.14", "sensitive": false}, {"type": "simple", "operand": "dest.port", "data": "443", "sensitive": false}]`
	conn.Process.Path = "/usr/BiN/opensnitchd"
	opList.Sensitive = true
	if err = opList.Compile(); err != nil {
		t.Fail()
	}
	if opList.Match(conn) == false {
		t.Error("Test NewOperator() list.regexp.sensitive doesn't match:", conn.Process.Path)
		t.Fail()
	}

	// "data": "^/usr/BiN/.*" must not match conn.Process.Path (insensitive)
	opList.Sensitive = false
	conn.Process.Path = "/USR/BiN/opensnitchd"
	if err = opList.Compile(); err != nil {
		t.Fail()
	}
	if opList.Match(conn) == false {
		t.Error("Test NewOperator() list.regexp.insensitive match:", conn.Process.Path)
		t.Fail()
	}

	// "data": "^/usr/BiN/.*" must match conn.Process.Path (insensitive)
	opList.Sensitive = false
	conn.Process.Path = "/USR/bin/opensnitchd"
	if err = opList.Compile(); err != nil {
		t.Fail()
	}
	if opList.Match(conn) == false {
		t.Error("Test NewOperator() list.regexp.insensitive match:", conn.Process.Path)
		t.Fail()
	}

	restoreConnection()
}
