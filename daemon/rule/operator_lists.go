package rule

import (
	"fmt"
	"github.com/evilsocket/opensnitch/daemon/log"
	"io/ioutil"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// ClearLists deletes all the entries of a list
func (o *Operator) ClearLists() {
	log.Debug("clearing domains lists: %d - %s", len(o.lists), o.Data)
	for k := range o.lists {
		delete(o.lists, k)
	}
	o.lists = nil
	debug.FreeOSMemory()
}

func (o *Operator) loadLists() error {
	log.Info("loading domains lists: %s, %s, %s", o.Type, o.Operand, o.Data)

	o.ClearLists()
	var dups uint64

	// this list is particular to this operator/rule
	o.lists = make(map[string]string)

	expr := filepath.Join(o.Data, "/*.*")
	fileList, err := filepath.Glob(expr)
	if err != nil {
		return fmt.Errorf("Error loading domains lists '%s': %s", expr, err)
	}

	for _, fileName := range fileList {
		log.Debug("Loading domains list: %s", fileName)
		raw, err := ioutil.ReadFile(fileName)
		log.Debug("domains list size: %d", len(raw))
		if err != nil {
			log.Warning("Error reading list of domains (%s): %s", fileName, err)
			continue
		}
		for _, domain := range strings.Split(string(raw), "\n") {
			if len(domain) < 9 {
				continue
			}
			// exclude not valid lines
			if domain[:7] != "0.0.0.0" && domain[:9] != "127.0.0.1" {
				continue
			}
			host := domain[8:]
			// exclude localhost entries
			if domain[:9] == "127.0.0.1" {
				host = domain[10:]
			}
			if host == "local" || host == "localhost" || host == "localhost.localdomain" || host == "broadcasthost" {
				continue
			}
			if _, found := o.lists[host]; found {
				dups++
				continue
			}
			o.lists[host] = fileName
		}
		raw = nil
		log.Info("domains loaded: %d, %s", len(o.lists), fileName)
	}
	log.Info("Total domains loaded: %d - Duplicated: %d", len(o.lists), dups)

	return nil
}
