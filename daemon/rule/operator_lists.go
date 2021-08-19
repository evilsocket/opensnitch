package rule

import (
	"fmt"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"io/ioutil"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

func (o *Operator) monitorLists() {
	log.Info("monitor lists started: %s", o.Data)

	modTimes := make(map[string]time.Time)
	totalFiles := 0
	needReload := false
	numFiles := 0

	expr := filepath.Join(o.Data, "/*.*")
	for {
		select {
		case <-o.exitMonitorChan:
			goto Exit
		default:
			fileList, err := filepath.Glob(expr)
			if err != nil {
				log.Warning("Error reading directory of domains list: %s, %s", o.Data, err)
				goto Exit
			}
			numFiles = 0

			for _, filename := range fileList {
				// ignore hidden files
				name := filepath.Base(filename)
				if name[:1] == "." {
					delete(modTimes, filename)
					continue
				}
				// an overwrite operation performs two tasks: truncate the file and save the new content,
				// causing the file time to be modified twice.
				modTime, err := core.GetFileModTime(filename)
				if err != nil {
					log.Debug("deleting saved mod time due to error reading the list, %s", filename)
					delete(modTimes, filename)
				} else if lastModTime, found := modTimes[filename]; found {
					if lastModTime.Equal(modTime) == false {
						log.Debug("list changed: %s, %s, %s", lastModTime, modTime, filename)
						needReload = true
					}
				}
				modTimes[filename] = modTime
				numFiles++
			}
			fileList = nil

			if numFiles != totalFiles {
				needReload = true
			}
			totalFiles = numFiles

			if needReload {
				// we can't reload a single list, because the domains of all lists are added to the same map.
				// we could have the domains separated by lists/files, but then we'd need to iterate the map in order
				// to match a domain. Reloading the lists shoud only occur once a day.
				if err := o.readLists(); err != nil {
					log.Warning("%s", err)
				}
				needReload = false
			}
			time.Sleep(4 * time.Second)
		}
	}

Exit:
	modTimes = nil
	o.ClearLists()
	log.Info("lists monitor stopped")
}

// ClearLists deletes all the entries of a list
func (o *Operator) ClearLists() {
	o.Lock()
	defer o.Unlock()

	log.Info("clearing domains lists: %d - %s", len(o.lists), o.Data)
	for k := range o.lists {
		delete(o.lists, k)
	}
	debug.FreeOSMemory()
}

// StopMonitoringLists stops the monitoring lists goroutine.
func (o *Operator) StopMonitoringLists() {
	if o.listsMonitorRunning == true {
		o.exitMonitorChan <- true
		o.exitMonitorChan = nil
		o.listsMonitorRunning = false
	}
}

func (o *Operator) readList(fileName string) (dups uint64) {
	log.Debug("Loading domains list: %s", fileName)
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Warning("Error reading list of domains (%s): %s", fileName, err)
		return
	}

	log.Debug("domains list size: %d", len(raw))
	lines := strings.Split(string(raw), "\n")
	for _, domain := range lines {
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
	lines = nil
	log.Info("%d domains loaded, %s", len(o.lists), fileName)

	return dups
}

func (o *Operator) readLists() error {
	o.ClearLists()

	var dups uint64
	// this list is particular to this operator and rule
	o.Lock()
	defer o.Unlock()
	o.lists = make(map[string]string)

	expr := filepath.Join(o.Data, "*.*")
	fileList, err := filepath.Glob(expr)
	if err != nil {
		return fmt.Errorf("Error loading domains lists '%s': %s", expr, err)
	}

	for _, fileName := range fileList {
		// ignore hidden files
		name := filepath.Base(fileName)
		if name[:1] == "." {
			continue
		}
		dups += o.readList(fileName)
	}
	log.Info("%d lists loaded, %d domains, %d duplicated", len(fileList), len(o.lists), dups)
	return nil
}

func (o *Operator) loadLists() {
	log.Info("loading domains lists: %s, %s, %s", o.Type, o.Operand, o.Data)

	// when loading from disk, we don't use the Operator's constructor, so we need to create this channel
	if o.exitMonitorChan == nil {
		o.exitMonitorChan = make(chan bool)
		o.listsMonitorRunning = true
		go o.monitorLists()
	}
}
