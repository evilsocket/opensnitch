package config

import (
	//"path"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/fsnotify/fsnotify"
)

func (l *Loader) AddWatch(path string) error {
	l.RLock()
	defer l.RUnlock()
	return l.watcher.Add(path)
}

func (l *Loader) RemoveWatch(path string) error {
	l.RLock()
	defer l.RUnlock()
	return l.watcher.Remove(path)
}

func (l *Loader) AddWatches() {
	if err := l.watcher.Add(l.CfgFile); err != nil {
		log.Error("[tasks] Could not watch path %s: %s", l.CfgFile, err)
	}

	for _, task := range l.Tasks {
		if task.ConfigFile == "" {
			log.Warning("[tasks] Loader watch, \"configfile\" field missing, skipping task %s: enabled: %v, %s", task.Name, task.Enabled, task.ConfigFile)
			continue
		}
		if !task.Enabled {
			continue
		}
		log.Debug("[tasks] Loader watching %s: %v, %s", task.Name, task.Enabled, task.ConfigFile)

		if err := l.AddWatch(task.ConfigFile); err != nil {
			log.Error("[tasks] Loader, could not watch path %s: %s", task.ConfigFile, err)
		}
	}
}

func (l *Loader) setLiveReloadRunning(running bool) {
	l.Lock()
	l.liveReloadRunning = running
	l.Unlock()
}

func (l *Loader) isLiveReloadRunning() bool {
	l.RLock()
	defer l.RUnlock()
	return l.liveReloadRunning
}

func (l *Loader) liveReloadWorker() {
	l.setLiveReloadRunning(true)
	defer l.setLiveReloadRunning(false)

	//log.Info("Tasks watcher started on path %v ...", l.Tasks)

	for {
		l.AddWatches()

		select {
		case <-l.stopLiveReload:
			goto Exit
		case event, ok := <-l.watcher.Events:
			if !ok {
				log.Error("[tasks] Loader.watcher events not ready, closed?")
			}
			if !strings.HasSuffix(event.Name, ".json") {
				continue
			}
			log.Trace("[tasks] watcher event. Write: %v, Create: %v, Removed: %v Renamed: %v, %+v, %s",
				event.Op&fsnotify.Write == fsnotify.Write,
				event.Op&fsnotify.Create == fsnotify.Create,
				event.Op&fsnotify.Remove == fsnotify.Remove,
				event.Op&fsnotify.Rename == fsnotify.Rename,
				event, event.Name)

			// a new rule json file has been created or updated
			if event.Op&fsnotify.Create == fsnotify.Create {
				log.Info("New task: %s", event.Name)

			} else if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Rename == fsnotify.Rename {
				log.Important("Tasks file changed %s, reloading ...", event.Name)
				// the events may occur too rapidly, and sometimes the file does not exist yet.
				time.Sleep(1 * time.Second)
				l.TaskChanged <- event.Name
			}

		case err := <-l.watcher.Errors:
			log.Warning("[tasks] watcher error: %s", err)
		}
	}
Exit:
	log.Info("[tasks] liveReloadWorker() exited")
}
