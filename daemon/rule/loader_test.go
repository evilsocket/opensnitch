package rule

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"
	"time"
)

var tmpDir string

func TestMain(m *testing.M) {
	tmpDir = "/tmp/ostest_" + randString()
	os.Mkdir(tmpDir, 0777)
	defer os.RemoveAll(tmpDir)
	os.Exit(m.Run())
}

func TestRuleLoader(t *testing.T) {
	t.Parallel()
	t.Log("Test rules loader")

	var list []Operator
	dur1s := Duration("1s")
	dummyOper, _ := NewOperator(Simple, false, OpTrue, "", list)
	dummyOper.Compile()
	inMem1sRule := Create("000-xxx-name", "rule description xxx", true, false, false, Allow, dur1s, dummyOper)
	inMemUntilRestartRule := Create("000-aaa-name", "rule description aaa", true, false, false, Allow, Restart, dummyOper)

	l, err := NewLoader(false)
	if err != nil {
		t.Fail()
	}
	if err = l.Load("/non/existent/path/"); err == nil {
		t.Error("non existent path test: err should not be nil")
	}

	if err = l.Load("testdata/"); err != nil {
		t.Error("Error loading test rules: ", err)
	}
	// we expect 6 valid rules (2 invalid), loaded from testdata/
	testNumRules(t, l, 6)

	if err = l.Add(inMem1sRule, false); err != nil {
		t.Error("Error adding temporary rule")
	}
	testNumRules(t, l, 7)

	// test auto deletion of temporary rule
	time.Sleep(time.Second * 2)
	testNumRules(t, l, 6)

	if err = l.Add(inMemUntilRestartRule, false); err != nil {
		t.Error("Error adding temporary rule (2)")
	}
	testNumRules(t, l, 7)
	testRulesOrder(t, l)
	testSortRules(t, l)
	testFindMatch(t, l)
	testFindEnabled(t, l)
	testDurationChange(t, l)
}

func TestRuleLoaderInvalidRegexp(t *testing.T) {
	t.Parallel()
	t.Log("Test rules loader: invalid regexp")

	l, err := NewLoader(true)
	if err != nil {
		t.Fail()
	}
	t.Run("loadRule() from disk test (simple)", func(t *testing.T) {
		if err := l.loadRule("testdata/invalid-regexp.json"); err == nil {
			t.Error("invalid regexp rule loaded: loadRule()")
		}
	})

	t.Run("loadRule() from disk test (list)", func(t *testing.T) {
		if err := l.loadRule("testdata/invalid-regexp-list.json"); err == nil {
			t.Error("invalid regexp rule loaded: loadRule()")
		}
	})

	var list []Operator
	dur30m := Duration("30m")
	opListData := `[{"type": "regexp", "operand": "process.path", "sensitive": false, "data": "^(/di(rmngr)$"}, {"type": "simple", "operand": "dest.port", "data": "53", "sensitive": false}]`
	invalidRegexpOp, _ := NewOperator(List, false, OpList, opListData, list)
	invalidRegexpRule := Create("invalid-regexp", "invalid rule description", true, false, false, Allow, dur30m, invalidRegexpOp)

	t.Run("replaceUserRule() test list", func(t *testing.T) {
		if err := l.replaceUserRule(invalidRegexpRule); err == nil {
			t.Error("invalid regexp rule loaded: replaceUserRule()")
		}
	})
}

// Test rules of type operator.list. There're these scenarios:
// - Enabled rules:
//    * operator Data field is ignored if it contains the list of operators as json string.
//    * the operarots list is expanded as json objecs under "list": []
// For new rules (> v1.6.3), Data field will be empty.
//
// - Disabled rules
//    * (old) the Data field contains the list of operators as json string, and the list of operarots is empty.
//    * Data field empty, and the list of operators expanded.
// In all cases the list of operators must be loaded.
func TestRuleLoaderList(t *testing.T) {
	l, err := NewLoader(true)
	if err != nil {
		t.Fail()
	}

	testRules := map[string]string{
		"rule-with-operator-list":                          "testdata/rule-operator-list.json",
		"rule-disabled-with-operators-list-as-json-string": "testdata/rule-disabled-operator-list.json",
		"rule-disabled-with-operators-list-expanded":       "testdata/rule-disabled-operator-list-expanded.json",
		"rule-with-operator-list-data-empty":               "testdata/rule-operator-list-data-empty.json",
	}

	for name, path := range testRules {
		t.Run(fmt.Sprint("loadRule() ", path), func(t *testing.T) {
			if err := l.loadRule(path); err != nil {
				t.Error(fmt.Sprint("loadRule() ", path, " error:"), err)
			}
			t.Log("Test: List rule:", name, path)
			r, found := l.rules[name]
			if !found {
				t.Error(fmt.Sprint("loadRule() ", path, " not in the list:"), l.rules)
			}
			// Starting from > v1.6.3, after loading a rule of type List, the field Operator.Data is emptied, if the Data contained the list of operators as json.
			if len(r.Operator.List) != 2 {
				t.Error(fmt.Sprint("loadRule() ", path, " operator List not loaded:"), r)
			}
			if r.Operator.List[0].Type != Simple ||
				r.Operator.List[0].Operand != OpProcessPath ||
				r.Operator.List[0].Data != "/usr/bin/telnet" {
				t.Error(fmt.Sprint("loadRule() ", path, " operator List 0 not loaded:"), r)
			}
			if r.Operator.List[1].Type != Simple ||
				r.Operator.List[1].Operand != OpDstPort ||
				r.Operator.List[1].Data != "53" {
				t.Error(fmt.Sprint("loadRule() ", path, " operator List 1 not loaded:"), r)
			}
		})
	}
}

func TestLiveReload(t *testing.T) {
	t.Parallel()
	t.Log("Test rules loader with live reload")
	l, err := NewLoader(true)
	if err != nil {
		t.Fail()
	}
	if err = Copy("testdata/000-allow-chrome.json", tmpDir+"/000-allow-chrome.json"); err != nil {
		t.Error("Error copying rule into a temp dir")
	}
	if err = Copy("testdata/001-deny-chrome.json", tmpDir+"/001-deny-chrome.json"); err != nil {
		t.Error("Error copying rule into a temp dir")
	}
	if err = l.Load(tmpDir); err != nil {
		t.Error("Error loading test rules: ", err)
	}
	//wait for watcher to activate
	time.Sleep(time.Second)
	if err = Copy("testdata/live_reload/test-live-reload-remove.json", tmpDir+"/test-live-reload-remove.json"); err != nil {
		t.Error("Error copying rules into temp dir")
	}
	if err = Copy("testdata/live_reload/test-live-reload-delete.json", tmpDir+"/test-live-reload-delete.json"); err != nil {
		t.Error("Error copying rules into temp dir")
	}
	//wait for watcher to pick up the changes
	time.Sleep(time.Second)
	testNumRules(t, l, 4)
	if err = os.Remove(tmpDir + "/test-live-reload-remove.json"); err != nil {
		t.Error("Error Remove()ing file from temp dir")
	}
	if err = l.Delete("test-live-reload-delete"); err != nil {
		t.Error("Error Delete()ing file from temp dir")
	}
	//wait for watcher to pick up the changes
	time.Sleep(time.Second)
	testNumRules(t, l, 2)
}

func randString() string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func testNumRules(t *testing.T, l *Loader, num int) {
	if l.NumRules() != num {
		t.Error("rules number should be (2): ", num)
	}
}

func testRulesOrder(t *testing.T, l *Loader) {
	if l.rulesKeys[0] != "000-aaa-name" {
		t.Error("Rules not in order (0): ", l.rulesKeys)
	}
	if l.rulesKeys[1] != "000-allow-chrome" {
		t.Error("Rules not in order (1): ", l.rulesKeys)
	}
	if l.rulesKeys[2] != "001-deny-chrome" {
		t.Error("Rules not in order (2): ", l.rulesKeys)
	}
}

func testSortRules(t *testing.T, l *Loader) {
	l.rulesKeys[1] = "001-deny-chrome"
	l.rulesKeys[2] = "000-allow-chrome"
	l.sortRules()
	if l.rulesKeys[1] != "000-allow-chrome" {
		t.Error("Rules not in order (1): ", l.rulesKeys)
	}
	if l.rulesKeys[2] != "001-deny-chrome" {
		t.Error("Rules not in order (2): ", l.rulesKeys)
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
		t.Error("FindPriorityMatch didn't match")
	}
	// test 000-allow-chrome, priority == true
	if match.Name != "000-allow-chrome" {
		t.Error("findPriorityMatch: priority rule failed: ", match)
	}

}

func testFindDenyMatch(t *testing.T, l *Loader) {
	l.rules["000-allow-chrome"].Precedence = false
	// test 000-allow-chrome, priority == false
	// 001-deny-chrome must match
	match := l.FindFirstMatch(conn)
	if match == nil {
		t.Error("FindDenyMatch deny didn't match")
	}
	if match.Name != "001-deny-chrome" {
		t.Error("findDenyMatch: deny rule failed: ", match)
	}
}

func testFindAllowMatch(t *testing.T, l *Loader) {
	l.rules["000-allow-chrome"].Precedence = false
	l.rules["001-deny-chrome"].Action = Allow
	// test 000-allow-chrome, priority == false
	// 001-deny-chrome must match
	match := l.FindFirstMatch(conn)
	if match == nil {
		t.Error("FindAllowMatch allow didn't match")
	}
	if match.Name != "001-deny-chrome" {
		t.Error("findAllowMatch: allow rule failed: ", match)
	}
}

func testFindEnabled(t *testing.T, l *Loader) {
	l.rules["000-allow-chrome"].Precedence = false
	l.rules["001-deny-chrome"].Action = Allow
	l.rules["001-deny-chrome"].Enabled = false
	// test 000-allow-chrome, priority == false
	// 001-deny-chrome must match
	match := l.FindFirstMatch(conn)
	if match == nil {
		t.Error("FindEnabledMatch, match nil")
	}
	if match.Name == "001-deny-chrome" {
		t.Error("findEnabledMatch: deny rule shouldn't have matched: ", match)
	}
}

// test that changing the Duration of a temporary rule doesn't delete
// the new one, ignoring the old timer.
func testDurationChange(t *testing.T, l *Loader) {
	l.rules["000-aaa-name"].Duration = "2s"
	if err := l.replaceUserRule(l.rules["000-aaa-name"]); err != nil {
		t.Error("testDurationChange, error replacing rule: ", err)
	}
	l.rules["000-aaa-name"].Duration = "1h"
	if err := l.replaceUserRule(l.rules["000-aaa-name"]); err != nil {
		t.Error("testDurationChange, error replacing rule: ", err)
	}
	time.Sleep(time.Second * 4)
	if _, found := l.rules["000-aaa-name"]; !found {
		t.Error("testDurationChange, error: rule has been deleted")
	}
}
