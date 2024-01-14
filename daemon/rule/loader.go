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
	"github.com/evilsocket/opensnitch/daemon/procmon"

	"github.com/fsnotify/fsnotify"
)

// Loader is the object that holds the rules loaded from disk, as well as the
// rules watcher.
type Loader struct {
	watcher           *fsnotify.Watcher
	rules             map[string]*Rule
	path              string
	rulesKeys         []string
	liveReload        bool
	liveReloadRunning bool
	checkSums         bool

	sync.RWMutex
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

// GetAll returns the loaded rules.
func (l *Loader) GetAll() map[string]*Rule {
	l.RLock()
	defer l.RUnlock()
	return l.rules
}

// EnableChecksums enables checksums field for rules globally.
func (l *Loader) EnableChecksums(enable bool) {
	log.Debug("[rules loader] EnableChecksums: %v", enable)
	l.checkSums = enable
	procmon.EventsCache.SetComputeChecksums(enable)
	procmon.EventsCache.AddChecksumHash(string(OpProcessHashMD5))
}

// HasChecksums checks if the rule will check for binary checksum matches
func (l *Loader) HasChecksums(op Operand) {
	if op == OpProcessHashMD5 {
		log.Debug("[rules loader] Adding MD5")
		procmon.EventsCache.AddChecksumHash(string(OpProcessHashMD5))
	} else if op == OpProcessHashSHA1 {
		log.Debug("[rules loader] Adding SHA1")
		procmon.EventsCache.AddChecksumHash(string(OpProcessHashSHA1))
	}
}

// Load loads rules files from disk.
func (l *Loader) Load(path string) error {
	if core.Exists(path) == false {
		return fmt.Errorf("Path '%s' does not exist\nCreate it if you want to save rules to disk", path)
	}
	path, err := core.ExpandPath(path)
	if err != nil {
		return fmt.Errorf("Error accessing rules path: %s.\nCreate it if you want to save rules to disk", err)
	}

	expr := filepath.Join(path, "*.json")
	matches, err := filepath.Glob(expr)
	if err != nil {
		return fmt.Errorf("Error globbing '%s': %s", expr, err)
	}

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

	if l.liveReload && l.liveReloadRunning == false {
		go l.liveReloadWorker()
	}

	return nil
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

	if err = ioutil.WriteFile(path, raw, 0600); err != nil {
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
	l.cleanListsRule(rule)

	delete(l.rules, ruleName)
	l.sortRules()

	if rule.Duration != Always {
		return nil
	}

	log.Info("Delete() rule: %s", rule)
	return l.deleteRuleFromDisk(ruleName)
}

func (l *Loader) loadRule(fileName string) error {
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("Error while reading %s: %s", fileName, err)
	}
	l.Lock()
	defer l.Unlock()

	var r Rule
	err = json.Unmarshal(raw, &r)
	if err != nil {
		return fmt.Errorf("Error parsing rule from %s: %s", fileName, err)
	}
	raw = nil

	if oldRule, found := l.rules[r.Name]; found {
		l.cleanListsRule(oldRule)
	}

	if !r.Enabled {
		// XXX: we only parse and load the Data field if the rule is disabled and the Data field is not empty
		// the rule will remain disabled.
		if err = l.unmarshalOperatorList(&r.Operator); err != nil {
			return err
		}
	} else {
		if err := r.Operator.Compile(); err != nil {
			log.Warning("Operator.Compile() error: %s: %s", err, r.Operator.Data)
			return fmt.Errorf("(1) Error compiling rule: %s", err)
		}
		if r.Operator.Type == List {
			for i := 0; i < len(r.Operator.List); i++ {
				if err := r.Operator.List[i].Compile(); err != nil {
					log.Warning("Operator.Compile() error: %s: ", err)
					return fmt.Errorf("(1) Error compiling list rule: %s", err)
				}
			}
		}
	}
	if oldRule, found := l.rules[r.Name]; found {
		l.deleteOldRuleFromDisk(oldRule, &r)
	}

	log.Debug("Loaded rule from %s: %s", fileName, r.String())
	l.rules[r.Name] = &r
	l.sortRules()

	if l.isTemporary(&r) {
		err = l.scheduleTemporaryRule(r)
	}

	return nil
}

// deleteRule deletes a rule from memory if it has been deleted from disk.
// This is only called if fsnotify's Remove event is fired, thus it doesn't
// have to delete temporary rules (!Always).
func (l *Loader) deleteRule(filePath string) {
	fileName := filepath.Base(filePath)
	ruleName := fileName[:len(fileName)-5]

	l.RLock()
	rule, found := l.rules[ruleName]
	delRule := found && rule.Duration == Always
	l.RUnlock()
	if delRule {
		l.Delete(ruleName)
	}
}

func (l *Loader) deleteRuleFromDisk(ruleName string) error {
	path := fmt.Sprint(l.path, "/", ruleName, ".json")
	return os.Remove(path)
}

// deleteOldRuleFromDisk deletes a rule from disk if the Duration changes
// from Always (saved on disk), to !Always (temporary).
func (l *Loader) deleteOldRuleFromDisk(oldRule, newRule *Rule) {
	if oldRule.Duration == Always && newRule.Duration != Always {
		if err := l.deleteRuleFromDisk(oldRule.Name); err != nil {
			log.Error("Error deleting old rule from disk: %s", oldRule.Name)
		}
	}
}

// cleanListsRule erases the list of domains of an Operator of type Lists
func (l *Loader) cleanListsRule(oldRule *Rule) {
	if oldRule.Operator.Type == Lists {
		oldRule.Operator.StopMonitoringLists()
	} else if oldRule.Operator.Type == List {
		for i := 0; i < len(oldRule.Operator.List); i++ {
			if oldRule.Operator.List[i].Type == Lists {
				oldRule.Operator.List[i].StopMonitoringLists()
				break
			}
		}
	}
}

func (l *Loader) isTemporary(r *Rule) bool {
	return r.Duration != Restart && r.Duration != Always && r.Duration != Once
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

// Deprecated: rule.Operator.Data no longer holds the operator list in json format as string.
func (l *Loader) unmarshalOperatorList(op *Operator) error {
	if op.Type == List && len(op.List) == 0 && op.Data != "" {
		if err := json.Unmarshal([]byte(op.Data), &op.List); err != nil {
			return fmt.Errorf("error loading rule of type list: %s", err)
		}
		op.Data = ""
	}

	return nil
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
	l.Lock()
	oldRule, found := l.rules[rule.Name]
	l.Unlock()

	if found {
		// If the rule has changed from Always (saved on disk) to !Always (temporary),
		// we need to delete the rule from disk and keep it in memory.
		l.deleteOldRuleFromDisk(oldRule, rule)

		// delete loaded lists, if this is a rule of type Lists
		l.cleanListsRule(oldRule)
	}

	if err := l.unmarshalOperatorList(&rule.Operator); err != nil {
		log.Error(err.Error())
	}

	if rule.Enabled {
		if err := rule.Operator.Compile(); err != nil {
			log.Warning("Operator.Compile() error: %s: %s", err, rule.Operator.Data)
			return fmt.Errorf("(2) error compiling rule: %s", err)
		}

		if rule.Operator.Type == List {
			for i := 0; i < len(rule.Operator.List); i++ {
				if err := rule.Operator.List[i].Compile(); err != nil {
					log.Warning("Operator.Compile() error: %s: ", err)
					return fmt.Errorf("(2) error compiling list rule: %s", err)
				}
			}
		}
	}
	l.Lock()
	l.rules[rule.Name] = rule
	l.sortRules()
	l.Unlock()

	if l.isTemporary(rule) {
		err = l.scheduleTemporaryRule(*rule)
	}

	return err
}

func (l *Loader) scheduleTemporaryRule(rule Rule) error {
	tTime, err := time.ParseDuration(string(rule.Duration))
	if err != nil {
		return err
	}

	time.AfterFunc(tTime, func() {
		l.Lock()
		defer l.Unlock()

		log.Info("Temporary rule expired: %s - %s", rule.Name, rule.Duration)
		if newRule, found := l.rules[rule.Name]; found {
			if newRule.Duration != rule.Duration {
				log.Debug("%s temporary rule expired, but has new Duration, old: %s, new: %s", rule.Name, rule.Duration, newRule.Duration)
				return
			}
			delete(l.rules, rule.Name)
			l.sortRules()
		}
	})
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
					// we only need to delete from memory rules of type Always,
					// because the Remove event is of a file, i.e.: Duration == Always
					l.deleteRule(event.Name)
				}
			}
		case err := <-l.watcher.Errors:
			log.Error("File system watcher error: %s", err)
		}
	}
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
		if rule.Match(con, l.checkSums) {
			// We have a match.
			// Save the rule in order to don't ask the user to take action,
			// and keep iterating until a Deny or a Priority rule appears.
			match = rule
			if rule.Action == Reject || rule.Action == Deny || rule.Precedence == true {
				return rule
			}
		}
	}

	return match
}
