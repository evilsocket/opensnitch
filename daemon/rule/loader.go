package rule

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/conman"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/core"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"

	"github.com/fsnotify/fsnotify"
)

// Loader is the object that holds the rules loaded from disk, as well as the
// rules watcher.
type Loader struct {
	sync.RWMutex
	path              string
	rules             map[string]*Rule
	rulesKeys         []string
	watcher           *fsnotify.Watcher
	liveReload        bool
	liveReloadRunning bool
}

// NewLoader loads rules from disk, and watches for changes made to the rules files
// on disk.
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

// NumRules returns he number of loaded rules.
func (l *Loader) NumRules() int {
	l.RLock()
	defer l.RUnlock()
	return len(l.rules)
}

// Load loads rules files from disk.
func (l *Loader) Load(path string) error {
	if core.Exists(path) == false {
		return fmt.Errorf("Path '%s' does not exist", path)
	}

	expr := filepath.Join(path, "*.json")
	matches, err := filepath.Glob(expr)
	if err != nil {
		return fmt.Errorf("Error globbing '%s': %s", expr, err)
	}

	l.Lock()
	defer l.Unlock()

	l.path = path
	if len(l.rules) == 0 {
		l.rules = make(map[string]*Rule)
	}
	diskRules := make(map[string]string)

	for _, fileName := range matches {
		log.Debug("Reading rule from %s", fileName)
		raw, err := ioutil.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("Error while reading %s: %s", fileName, err)
		}

		var r Rule

		err = json.Unmarshal(raw, &r)
		if err != nil {
			log.Error("Error parsing rule from %s: %s", fileName, err)
			continue
		}

		r.Operator.Compile()
		diskRules[r.Name] = r.Name

		log.Debug("Loaded rule from %s: %s", fileName, r.String())
		l.rules[r.Name] = &r
	}
	for ruleName, inMemoryRule := range l.rules {
		if _, ok := diskRules[ruleName]; ok == false {
			if inMemoryRule.Duration == Always {
				log.Debug("Rule deleted from disk, updating rules list: ", ruleName)
				delete(l.rules, ruleName)
			}
		}
	}

	l.sortRules()

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

// Reload reloads the rules from disk.
func (l *Loader) Reload() error {
	return l.Load(l.path)
}

// GetAll returns the loaded rules.
func (l *Loader) GetAll() map[string]*Rule {
	l.RLock()
	defer l.RUnlock()
	return l.rules
}

func (l *Loader) isUniqueName(name string) bool {
	_, found := l.rules[name]
	return !found
}

func (l *Loader) setUniqueName(rule *Rule) {
	l.Lock()
	defer l.Unlock()

	idx := 1
	base := rule.Name
	for l.isUniqueName(rule.Name) == false {
		idx++
		rule.Name = fmt.Sprintf("%s-%d", base, idx)
	}
}

func (l *Loader) sortRules() {
	l.rulesKeys = make([]string, 0, len(l.rules))
	for k := range l.rules {
		l.rulesKeys = append(l.rulesKeys, k)
	}
	sort.Strings(l.rulesKeys)
}

func (l *Loader) addUserRule(rule *Rule) {
	if rule.Duration == Once {
		return
	}

	l.setUniqueName(rule)
	l.replaceUserRule(rule)
}

func (l *Loader) replaceUserRule(rule *Rule) {
	l.Lock()
	if rule.Operator.Type == List {
		if err := json.Unmarshal([]byte(rule.Operator.Data), &rule.Operator.List); err != nil {
			log.Error("Error loading rule of type list", err)
		}
	}
	l.rules[rule.Name] = rule
	l.sortRules()
	l.Unlock()

	if rule.Duration == Restart || rule.Duration == Always {
		return
	}

	tTime, err := time.ParseDuration(string(rule.Duration))
	if err != nil {
		return
	}

	time.AfterFunc(tTime, func() {
		l.Lock()
		delete(l.rules, rule.Name)
		l.sortRules()
		l.Unlock()
	})
}

// Add adds a rule to the list of rules, and optionally saves it to disk.
func (l *Loader) Add(rule *Rule, saveToDisk bool) error {
	l.addUserRule(rule)
	if saveToDisk {
		fileName := filepath.Join(l.path, fmt.Sprintf("%s.json", rule.Name))
		return l.Save(rule, fileName)
	}
	return nil
}

// Replace adds a rule to the list of rules, and optionally saves it to disk.
func (l *Loader) Replace(rule *Rule, saveToDisk bool) error {
	l.replaceUserRule(rule)
	if saveToDisk {
		l.Lock()
		defer l.Unlock()

		fileName := filepath.Join(l.path, fmt.Sprintf("%s.json", rule.Name))
		return l.Save(rule, fileName)
	}
	return nil
}

// Save a rule to disk.
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

// Delete deletes a rule from the list.
// If the duration is Always (i.e: saved on disk), it'll attempt to delete
// it from disk.
func (l *Loader) Delete(ruleName string) error {
	l.Lock()
	defer l.Unlock()

	rule := l.rules[ruleName]
	if rule == nil {
		return nil
	}

	delete(l.rules, ruleName)
	l.sortRules()

	if rule.Duration != Always {
		return nil
	}

	log.Info("Delete() rule: ", rule)
	path := fmt.Sprint(l.path, "/", ruleName, ".json")
	return os.Remove(path)
}

// FindFirstMatch will try match the connection against the existing rule set.
func (l *Loader) FindFirstMatch(con *conman.Connection) (match *Rule) {
	l.RLock()
	defer l.RUnlock()

	for _, ruleIdx := range l.rulesKeys {
		rule, valid := l.rules[ruleIdx]
		if !valid {
			continue
		}
		// if we already have a match, we don't need
		// to evaluate 'allow' rules anymore, we only
		// need to make sure there's no 'deny' rule
		// matching this specific connection
		if match != nil && rule.Action == Allow {
			if rule.Precedence {
				break
			}
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
