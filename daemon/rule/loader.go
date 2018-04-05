package rule

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
)

type Loader struct {
	sync.RWMutex
	path  string
	rules map[string]*Rule
}

func NewLoader() *Loader {
	return &Loader{
		path:  "",
		rules: make(map[string]*Rule),
	}
}

func (l *Loader) NumRules() int {
	l.RLock()
	defer l.RUnlock()
	return len(l.rules)
}

func (l *Loader) Load(path string) error {
	if core.Exists(path) == false {
		return fmt.Errorf("Path '%s' does not exist.", path)
	}

	expr := filepath.Join(path, "*.json")
	matches, err := filepath.Glob(expr)
	if err != nil {
		return fmt.Errorf("Error globbing '%s': %s", expr, err)
	}

	l.Lock()
	defer l.Unlock()

	l.path = path
	l.rules = make(map[string]*Rule)

	for _, fileName := range matches {
		raw, err := ioutil.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Error while reading %s: %s", fileName, err)
		}

		var r Rule

		err = json.Unmarshal(raw, &r)
		if err != nil {
			return fmt.Errorf("Error while parsing rule from %s: %s", fileName, err)
		}

		log.Debug("Loaded rule from %s: %s", fileName, r.String())
		l.rules[r.Name] = &r
	}

	return nil
}

func (l *Loader) Reload() error {
	return l.Load(l.path)
}

func (l *Loader) isUniqueName(name string) bool {
	_, found := l.rules[name]
	return !found
}

func (l *Loader) setUniqueName(rule *Rule) {
	idx := 1
	base := rule.Name
	for l.isUniqueName(rule.Name) == false {
		idx++
		rule.Name = fmt.Sprintf("%s-%d", base, idx)
	}
}

func (l *Loader) addUserRule(rule *Rule) {
	l.Lock()
	l.setUniqueName(rule)
	l.rules[rule.Name] = rule
	l.Unlock()
}

func (l *Loader) Add(rule *Rule, saveToDisk bool) error {
	l.addUserRule(rule)
	if saveToDisk {
		fileName := filepath.Join(l.path, fmt.Sprintf("%s.json", rule.Name))
		return l.Save(rule, fileName)
	}
	return nil
}

func (l *Loader) Save(rule *Rule, path string) error {
	rule.Updated = time.Now()
	raw, err := json.MarshalIndent(rule, " ", "  ")
	if err != nil {
		return fmt.Errorf("Error while saving rule %s to %s: %s", rule, err)
	}

	if err = ioutil.WriteFile(path, raw, 0644); err != nil {
		return fmt.Errorf("Error while saving rule %s to %s: %s", rule, err)
	}

	return nil
}

func (l *Loader) FindFirstMatch(con *conman.Connection) *Rule {
	l.RLock()
	defer l.RUnlock()

	for _, rule := range l.rules {
		if rule.Match(con) == true {
			return rule
		}
	}

	return nil
}
