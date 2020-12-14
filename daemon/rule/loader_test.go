package rule

import (
	"testing"
	"time"
)

func TestRuleLoader(t *testing.T) {
	t.Log("Test rules loader")

	var list []Operator
	dur1s := Duration("1s")
	dummyOper, _ := NewOperator(Simple, false, OpTrue, "", list)
	inMem1sRule := Create("000-xxx-name", true, false, Allow, dur1s, dummyOper)
	inMemUntilRestartRule := Create("000-aaa-name", true, false, Allow, Restart, dummyOper)

	l, err := NewLoader(false)
	if err != nil {
		t.Fail()
	}
	if err = l.Load("/non/existent/path/"); err == nil {
		t.Error("non existent path test: err should not be nil")
		t.Fail()
	}

	if err = l.Load("testdata/"); err != nil {
		t.Error("Error loading test rules: ", err)
		t.Fail()
	}

	testNumRules(t, l, 2)

	if err = l.Add(inMem1sRule, false); err != nil {
		t.Error("Error adding temporary rule")
		t.Fail()
	}
	testNumRules(t, l, 3)

	// test auto deletion of temporary rule
	time.Sleep(time.Second * 2)
	testNumRules(t, l, 2)

	if err = l.Add(inMemUntilRestartRule, false); err != nil {
		t.Error("Error adding temporary rule (2)")
		t.Fail()
	}
	testNumRules(t, l, 3)
	testRulesOrder(t, l)
	testSortRules(t, l)
	testFindMatch(t, l)
}

func testNumRules(t *testing.T, l *Loader, num int) {
	if l.NumRules() != num {
		t.Error("rules number should be (2): ", num)
		t.Fail()
	}
}

func testRulesOrder(t *testing.T, l *Loader) {
	if l.rulesKeys[0] != "000-aaa-name" {
		t.Error("Rules not in order (0): ", l.rulesKeys)
		t.Fail()
	}
	if l.rulesKeys[1] != "000-allow-chrome" {
		t.Error("Rules not in order (1): ", l.rulesKeys)
		t.Fail()
	}
	if l.rulesKeys[2] != "001-deny-chrome" {
		t.Error("Rules not in order (2): ", l.rulesKeys)
		t.Fail()
	}
}

func testSortRules(t *testing.T, l *Loader) {
	l.rulesKeys[1] = "001-deny-chrome"
	l.rulesKeys[2] = "000-allow-chrome"
	l.sortRules()
	if l.rulesKeys[1] != "000-allow-chrome" {
		t.Error("Rules not in order (1): ", l.rulesKeys)
		t.Fail()
	}
	if l.rulesKeys[2] != "001-deny-chrome" {
		t.Error("Rules not in order (2): ", l.rulesKeys)
		t.Fail()
	}
}

func testFindMatch(t *testing.T, l *Loader) {
	conn.Process.Path = "/opt/google/chrome/chrome"

	testFindPriorityMatch(t, l)
	testFindDenyMatch(t, l)
	testFindAllowMatch(t, l)

	restoreConnection()
}

func testFindPriorityMatch(t *testing.T, l *Loader) {
	match := l.FindFirstMatch(conn)
	if match == nil {
		t.Error("FindFirstMatch didn't match")
		t.Fail()
	}
	// test 000-allow-chrome, priority == true
	if match.Name != "000-allow-chrome" {
		t.Error("findFirstMatch: priority rule failed: ", match)
		t.Fail()
	}

}

func testFindDenyMatch(t *testing.T, l *Loader) {
	l.rules["000-allow-chrome"].Precedence = false
	// test 000-allow-chrome, priority == false
	// 001-deny-chrome must match
	match := l.FindFirstMatch(conn)
	if match == nil {
		t.Error("FindFirstMatch deny didn't match")
		t.Fail()
	}
	if match.Name != "001-deny-chrome" {
		t.Error("findFirstMatch: deny rule failed: ", match)
		t.Fail()
	}
}

func testFindAllowMatch(t *testing.T, l *Loader) {
	l.rules["000-allow-chrome"].Precedence = false
	l.rules["001-deny-chrome"].Action = Allow
	// test 000-allow-chrome, priority == false
	// 001-deny-chrome must match
	match := l.FindFirstMatch(conn)
	if match == nil {
		t.Error("FindFirstMatch allow didn't match")
		t.Fail()
	}
	if match.Name != "001-deny-chrome" {
		t.Error("findFirstMatch: allow rule failed: ", match)
		t.Fail()
	}
}
