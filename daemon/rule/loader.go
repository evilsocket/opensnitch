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
	rules []*Rule
}

func NewLoader() *Loader {
	return &Loader{
		path:  "",
		rules: make([]*Rule, 0),
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
	l.rules = make([]*Rule, 0)

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
		l.rules = append(l.rules, &r)
	}

	return nil
}

func (l *Loader) Reload() error {
	return l.Load(l.path)
}

func (l *Loader) Save(rule *Rule, path string) error {
	rule.Updated = time.Now()
	raw, err := json.Marshal(rule)
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
