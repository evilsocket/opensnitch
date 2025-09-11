package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/evilsocket/opensnitch/daemon/log"
)

func LoadTaskData(path string) (TaskData, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return TaskData{}, fmt.Errorf("error opening task file %s: %s", path, err)
	}
	log.Trace("LoadTaskData: %s -> %s", path, string(raw))

	var taskConf TaskData
	err = json.Unmarshal(raw, &taskConf)
	if err != nil {
		return TaskData{}, fmt.Errorf("error unmarshalling task file %s: %s", path, err)
	}

	return taskConf, nil
}
