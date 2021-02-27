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

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"

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

	for _, fileName := range matches {
		log.Debug("Reading rule from %s", fileName)

		if err := l.loadRule(fileName); err != nil {
			log.Warning("%s", err)
			continue
		}
	}

	l.sortRules()

	if l.liveReload && l.liveReloadRunning == false {
		go l.liveReloadWorker()
	}

	return nil
}

func (l *Loader) loadRule(fileName string) error {
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("Error while reading %s: %s", fileName, err)
	}

	var r Rule
	err = json.Unmarshal(raw, &r)
	if err != nil {
		return fmt.Errorf("Error parsing rule from %s: %s", fileName, err)
	}

	if r.Enabled {
		r.Operator.Compile()
		if r.Operator.Type == List {
			for i := 0; i < len(r.Operator.List); i++ {
				if err := r.Operator.List[i].Compile(); err != nil {
					log.Warning("Operator.Compile() error: %s: ", err)
				}
			}
		}
	} else {
		// if we're reloading the list of rules (due to changes on disk),
		// we need to delete any possible loaded lists.
		if r.Operator.Type == Lists {
			r.Operator.ClearLists()
		} else if r.Operator.Type == List {
			for i := 0; i < len(r.Operator.List); i++ {
				if r.Operator.List[i].Type == Lists {
					r.Operator.ClearLists()
				}
			}
		}
	}
	// FIXME: if a rule file is changed manually on disk from Always to !Always,
	// the file is deleted from disk, but the Remove event deletes it
	// also from memory.
	l.deleteOldRuleFromDisk(&r)

	log.Debug("Loaded rule from %s: %s", fileName, r.String())
	l.rules[r.Name] = &r

	return nil
}

// deleteRule deletes a rule from memory and from disk if the Duration is Always
func (l *Loader) deleteRule(filePath string) {
	fileName := filepath.Base(filePath)
	l.Delete(fileName[:len(fileName)-5])
}

func (l *Loader) deleteRuleFromDisk(ruleName string) error {
	path := fmt.Sprint(l.path, "/", ruleName, ".json")
	return os.Remove(path)
}

// deleteOldRuleFromDisk deletes a rule from disk if the Duration changes
// from Always (saved on disk), to !Always (temporary).
func (l *Loader) deleteOldRuleFromDisk(newRule *Rule) {
	if oldRule, found := l.rules[newRule.Name]; found {
		if oldRule.Duration == Always && newRule.Duration != Always {
			if err := l.deleteRuleFromDisk(oldRule.Name); err != nil {
				log.Error("Error deleting old rule from disk: %s", oldRule.Name)
			}
		}
	}
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
			if event.Op&fsnotify.Write == fsnotify.Write {
				if strings.HasSuffix(event.Name, ".json") {
					log.Important("Ruleset changed due to %s, reloading ...", path.Base(event.Name))
					if err := l.loadRule(event.Name); err != nil {
						log.Warning("%s", err)
					}
				}
			} else if event.Op&fsnotify.Remove == fsnotify.Remove {
				if strings.HasSuffix(event.Name, ".json") {
					log.Important("Rule deleted %s", path.Base(event.Name))
					l.deleteRule(event.Name)
				}
			}
		case err := <-l.watcher.Errors:
			log.Error("File system watcher error: %s", err)
		}
	}
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

func (l *Loader) replaceUserRule(rule *Rule) (err error) {
	// If the rule has changed from Always (saved on disk) to !Always (temporary),
	// we need to delete the rule from disk and keep it in memory.
	l.deleteOldRuleFromDisk(rule)

	l.Lock()
	l.rules[rule.Name] = rule
	l.sortRules()
	l.Unlock()

	if rule.Enabled == false && rule.Operator.Type == Lists {
		rule.Operator.ClearLists()
	} else {
		rule.Operator.isCompiled = false
		if err := rule.Operator.Compile(); err != nil {
			log.Warning("Operator.Compile() error: %s: %s", err, rule.Operator.Data)
		}
	}

	if rule.Operator.Type == List {
		// TODO: use List protobuf object instead of un/marshalling to/from json
		if err = json.Unmarshal([]byte(rule.Operator.Data), &rule.Operator.List); err != nil {
			return fmt.Errorf("Error loading rule of type list: %s", err)
		}

		// TODO handle the situation where the field Lists has been unchecked: delete lists
		for i := 0; i < len(rule.Operator.List); i++ {
			if rule.Enabled == false && rule.Operator.List[i].Type == Lists {
				rule.Operator.ClearLists()
				continue
			}
			// force re-Compile() changed rule
			rule.Operator.List[i].isCompiled = false
			if err := rule.Operator.List[i].Compile(); err != nil {
				log.Warning("Operator.Compile() error: %s: ", err)
			}
		}
	}

	if rule.Duration == Restart || rule.Duration == Always || rule.Duration == Once {
		return err
	}

	var tTime time.Duration
	tTime, err = time.ParseDuration(string(rule.Duration))
	if err != nil {
		return err
	}

	time.AfterFunc(tTime, func() {
		l.Lock()
		log.Info("Temporary rule expired: %s - %s", rule.Name, rule.Duration)
		delete(l.rules, rule.Name)
		l.sortRules()
		l.Unlock()
	})

	return err
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
	if err := l.replaceUserRule(rule); err != nil {
		return err
	}
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

// Delete deletes a rule from the list by name.
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

	log.Info("Delete() rule: %s", rule)
	return l.deleteRuleFromDisk(ruleName)
}

// FindFirstMatch will try match the connection against the existing rule set.
func (l *Loader) FindFirstMatch(con *conman.Connection) (match *Rule) {
	l.RLock()
	defer l.RUnlock()

	for _, idx := range l.rulesKeys {
		rule, _ := l.rules[idx]
		if rule.Enabled == false {
			continue
		}
		if rule.Match(con) {
			// We have a match.
			// Save the rule in order to don't ask the user to take action,
			// and keep iterating until a Deny or a Priority rule appears.
			match = rule
			if rule.Action == Deny || rule.Precedence == true {
				return rule
			}
		}
	}

	return match
}
