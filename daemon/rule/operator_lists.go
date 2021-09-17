package rule

import (
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
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

func (o *Operator) readDomainsList(raw, fileName string) (dups uint64) {
	log.Debug("Loading domains list: %s, size: %d", fileName, len(raw))
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

		host = core.Trim(host)
		if _, found := o.lists[host]; found {
			dups++
			continue
		}
		o.lists[host] = fileName
	}
	lines = nil
	log.Info("%d domains loaded, %s", len(o.lists), fileName)

	return dups
}

func (o *Operator) readNetList(raw, fileName string) (dups uint64) {
	log.Debug("Loading nets list: %s, size: %d", fileName, len(raw))
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		if line == "" || line[0] == '#' {
			continue
		}
		host := core.Trim(line)
		if _, found := o.lists[host]; found {
			dups++
			continue
		}
		_, netMask, err := net.ParseCIDR(host)
		if err != nil {
			log.Warning("Error parsing net from list: %s, (%s)", err, fileName)
			continue
		}
		o.lists[host] = netMask
	}
	lines = nil
	log.Info("%d nets loaded, %s", len(o.lists), fileName)

	return dups
}

func (o *Operator) readRegexpList(raw, fileName string) (dups uint64) {
	log.Debug("Loading regexp list: %s, size: %d", fileName, len(raw))
	lines := strings.Split(string(raw), "\n")
	for n, line := range lines {
		if line == "" || line[0] == '#' {
			continue
		}
		host := core.Trim(line)
		if _, found := o.lists[host]; found {
			dups++
			continue
		}
		re, err := regexp.Compile(line)
		if err != nil {
			log.Warning("Error compiling regexp from list: %s, (%d:%s)", err, n, fileName)
			continue
		}
		o.lists[line] = re
	}
	lines = nil
	log.Info("%d regexps loaded, %s", len(o.lists), fileName)

	return dups
}

func (o *Operator) readIPList(raw, fileName string) (dups uint64) {
	log.Debug("Loading IPs list: %s, size: %d", fileName, len(raw))
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		if line == "" || line[0] == '#' {
			continue
		}
		ip := core.Trim(line)
		if _, found := o.lists[ip]; found {
			dups++
			continue
		}
		o.lists[ip] = fileName
	}
	lines = nil
	log.Info("%d IPs loaded, %s", len(o.lists), fileName)

	return dups
}

func (o *Operator) readLists() error {
	o.ClearLists()

	var dups uint64
	// this list is particular to this operator and rule
	o.Lock()
	defer o.Unlock()
	o.lists = make(map[string]interface{})

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

		raw, err := ioutil.ReadFile(fileName)
		if err != nil {
			log.Warning("Error reading list of IPs (%s): %s", fileName, err)
			continue
		}

		if o.Operand == OpDomainsLists {
			dups += o.readDomainsList(string(raw), fileName)
		} else if o.Operand == OpDomainsRegexpLists {
			dups += o.readRegexpList(string(raw), fileName)
		} else if o.Operand == OpNetLists {
			dups += o.readNetList(string(raw), fileName)
		} else if o.Operand == OpIPLists {
			dups += o.readIPList(string(raw), fileName)
		} else {
			log.Warning("Unknown lists operand type: %s", o.Operand)
		}
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
