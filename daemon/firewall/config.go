package firewall

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
)

var (
	configFile    = "/etc/opensnitchd/fw.json"
	configWatcher *fsnotify.Watcher
	fwConfig      config
)

type rulesList struct {
	Allow []string
	Deny  []string
}

type rulesDirection struct {
	Out rulesList
}

type config struct {
	sync.RWMutex
	PriorityRules rulesDirection
}

func loadDiskConfiguration(reload bool) {
	raw, err := ioutil.ReadFile(configFile)
	if err != nil {
		fmt.Errorf("Error loading disk firewall configuration %s: %s", configFile, err)
	}

	if ok := loadConfiguration(raw); ok {
		if err := configWatcher.Add(configFile); err != nil {
			log.Error("Could not watch firewall configuration: %s", err)
			return
		}
	}

	if reload {
		return
	}

	go monitorConfigWorker()
}

func loadConfiguration(rawConfig []byte) bool {
	fwConfig.Lock()
	defer fwConfig.Unlock()

	if err := json.Unmarshal(rawConfig, &fwConfig); err != nil {
		fmt.Errorf("Error parsing firewall configuration %s: %s", configFile, err)
		return false
	}

	RunRule(FLUSH, true, []string{PRIORITYRULE, "-t", "mangle"})

	for _, r := range fwConfig.PriorityRules.Out.Allow {
		AllowPriorityRule(ADD, true, r)
	}
	for _, r := range fwConfig.PriorityRules.Out.Deny {
		DenyPriorityRule(ADD, true, r)
	}

	return true
}

func saveConfiguration(rawConfig string) error {
	conf, err := json.Marshal([]byte(rawConfig))
	if err != nil {
		log.Error("saving json firewall configuration: ", err, conf)
		return err
	}

	if loadConfiguration([]byte(rawConfig)) != true {
		return fmt.Errorf("Error parsing firewall configuration %s: %s", rawConfig, err)
	}

	if err = ioutil.WriteFile(configFile, []byte(rawConfig), 0644); err != nil {
		log.Error("writing firewall configuration to disk: ", err)
		return err
	}
	return nil
}

func monitorConfigWorker() {
	for {
		select {
		case <-rulesCheckerChan:
			return
		case event := <-configWatcher.Events:
			if (event.Op&fsnotify.Write == fsnotify.Write) || (event.Op&fsnotify.Remove == fsnotify.Remove) {
				loadDiskConfiguration(true)
			}
		}
	}
}
