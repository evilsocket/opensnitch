package tasks

import (
	//"fmt"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/tasks/config"
	"github.com/evilsocket/opensnitch/daemon/tasks/downloader"
	//"github.com/evilsocket/opensnitch/daemon/tasks/iocscanner"
	"github.com/evilsocket/opensnitch/daemon/tasks/looptask"
	//"github.com/evilsocket/opensnitch/daemon/tasks/netsniffer"
)

func (tm *TaskManager) ReloadTaskFile(cfgfile string) error {
	bakFile := tm.loader.CfgFile
	err := tm.LoadTaskFile(cfgfile)
	if err != nil {
		tm.loader.CfgFile = bakFile
		log.Debug("[tasks] ReloadTaskFile: %s", err)
		return err
	}

	return nil
}

// LoadTaskFile loads the file where all the tasks are defined.
// This file is configurable, saved under TaskManager.cfgFile, and if it's
// not supplied, we'll try to use /etc/opensnitchd/tasks/tasks.json
func (tm *TaskManager) LoadTaskFile(cfgfile string) error {
	/*tm.cfgFile = cfgfile
	if !core.Exists(cfgfile) {
		log.Warning("[Tasks] tasks config file does not exist: %s", cfgfile)
		return fmt.Errorf("%s doesn't exist", cfgfile)
	}*/

	tasks, err := tm.loader.Load(cfgfile)
	if err != nil {
		//return fmt.Errorf("error loading tasks from %s: %s", cfgfile, err)
		log.Warning("[tasks] LoadTaskFile, error loading tasks (%s), %s", cfgfile, err)
	}

	// listen for tasks file config changes.
	go func() {
		for {
			select {
			case file := <-tm.loader.TaskChanged:
				log.Info("[tasks] Task changed: %s", file)
				if file == tm.loader.CfgFile {
					goto ReloadTasks
				}

				taskConf, err := config.LoadTaskData(file)
				if err != nil {
					log.Error("[tasks] LoadTaskFile() error loading %s: %s", file, err)
					continue
				}
				if taskConf.Parent == "" {
					taskConf.Parent = taskConf.Name
				}

				log.Info("[tasks] LoadTaskFile, task %s running", taskConf.Name)
				if err := tm.RemoveTask(taskConf.Name); err != nil {
					log.Error("[tasks] LoadTaskFile, error removing task %s: %s", taskConf.Name, err)
				}

				if err := tm.loadDiskTask(taskConf.Name, taskConf); err != nil {
					log.Error("[tasks] loading task %s: %s", taskConf.Name, err)
				}
			}
		}
	ReloadTasks:
		log.Info("[tasks] reloading tasks from %s", tm.loader.CfgFile)
		tm.LoadTaskFile(cfgfile)
	}()

	tm.loadDiskTasks(tasks)
	return nil
}

func (tm *TaskManager) loadDiskTasks(tasks []config.TaskConfig) {
	for _, task := range tasks {
		taskConf, err := config.LoadTaskData(task.ConfigFile)
		_, running := tm.GetTask(taskConf.Name)

		// We need the name of the task instance (not the task name),
		// in order to stop the task.
		if !task.Enabled {
			log.Info("TaskMgr.loadDiskTasks() disabled: %s, %s", task.Name, taskConf.Name)
			tm.loader.RemoveWatch(task.ConfigFile)
			tm.RemoveTask(taskConf.Name)
			continue
		}
		if running {
			log.Debug("TaskMgr.loadDiskTasks() %s already running, %s", task.Name, taskConf.Name)
			continue
		}
		if err != nil {
			log.Error("TaskMgr.LoadTaskFile() error loading %s: %s", task.ConfigFile, err)
			continue
		}

		if err := tm.loadDiskTask(task.Name, taskConf); err != nil {
			log.Error("TaskMgr.loadDiskTasks() loading task %s: %s", task.Name, err)
		}
	}
}

// loadDiskTask loads a permanent task from disk.
func (tm *TaskManager) loadDiskTask(name string, taskConf config.TaskData) error {
	log.Debug("TaskMgr.loadDiskTask() %s, %s", name, taskConf.Name)
	switch name {
	case looptask.Name:
		// TODO: check interface errors
		taskName, looper := looptask.New(taskConf.Name, taskConf.Data["interval"].(string))
		_, err := tm.AddTask(taskName, looper)
		if err != nil {
			log.Error("loading task %s: %s", taskName, err)
			return err
		}
	case downloader.Name:
		downloader := downloader.New(taskConf.Data, false)
		log.Info("LoadTaskData, downloader: %s", taskConf.Name)
		_, err := tm.AddTask(taskConf.Name, downloader)
		if err != nil {
			log.Error("loading task %s: %s", taskConf.Name, err)
			return err
		}

	default:
		log.Debug("TaskStart, unknown task %s: %s", name, taskConf.Name)
	}

	return nil
}
