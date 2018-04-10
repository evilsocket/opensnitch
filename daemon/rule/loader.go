package rule

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"

	"github.com/fsnotify/fsnotify"
)

type Loader struct {
	sync.RWMutex
	path              string
	rules             map[string]*Rule
	watcher           *fsnotify.Watcher
	liveReload        bool
	liveReloadRunning bool
}

func NewLoader(liveReload bool) (*Loader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Loader{
		path:              "",
		rules:             make(map[string]*Rule),
		liveReload:        liveReload,
		watcher:           watcher,
		liveReloadRunning: false,
	}, nil
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
		log.Debug("Reading rule from %s", fileName)
		raw, err := ioutil.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Error while reading %s: %s", fileName, err)
		}

		var r Rule

		err = json.Unmarshal(raw, &r)
		if err != nil {
			return fmt.Errorf("Error while parsing rule from %s: %s", fileName, err)
		}

		r.Operator.Compile()

		log.Debug("Loaded rule from %s: %s", fileName, r.String())
		l.rules[r.Name] = &r
	}

	if l.liveReload && l.liveReloadRunning == false {
		go l.liveReloadWorker()
	}

	return nil
}

func (l *Loader) liveReloadWorker() {
	l.liveReloadRunning = true

	log.Debug("Rules watcher started on path %s ...", l.path)
	if err := l.watcher.Add(l.path); err != nil {
		log.Error("Could not watch path: %s", err)
		l.liveReloadRunning = false
		return
	}

	for {
		select {
		case event := <-l.watcher.Events:
			// a new rule json file has been created or updated
			if (event.Op&fsnotify.Write == fsnotify.Write) || (event.Op&fsnotify.Remove == fsnotify.Remove) {
				if strings.HasSuffix(event.Name, ".json") {
					log.Important("Ruleset changed due to %s, reloading ...", path.Base(event.Name))
					if err := l.Reload(); err != nil {
						log.Error("%s", err)
					}
				}
			}
		case err := <-l.watcher.Errors:
			log.Error("File system watcher error: %s", err)
		}
	}
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
	raw, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return fmt.Errorf("Error while saving rule %s to %s: %s", rule, path, err)
	}

	if err = ioutil.WriteFile(path, raw, 0644); err != nil {
		return fmt.Errorf("Error while saving rule %s to %s: %s", rule, path, err)
	}

	return nil
}

func (l *Loader) FindFirstMatch(con *conman.Connection) (match *Rule) {
	l.RLock()
	defer l.RUnlock()

	for _, rule := range l.rules {
		// if we already have a match, we don't need
		// to evaluate 'allow' rules anymore, we only
		// need to make sure there's no 'deny' rule
		// matching this specific connection
		if match != nil && rule.Action == Allow {
			continue
		} else if rule.Match(con) == true {
			// only return if we found a deny
			// rule, otherwise keep searching as we
			// might have situations like:
			//
			//     rule 1: allow chrome
			//     rule 2: block www.google.com
			match = rule
			if rule.Action == Deny {
				break
			}
		}
	}

	return match
}
