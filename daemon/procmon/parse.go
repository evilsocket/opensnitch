package procmon

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/core"
)

// [inode] -> pid
func GetOpenSockets() map[int]int {
	m := make(map[int]int)

	ls, err := ioutil.ReadDir("/proc/")
	if err == nil {
		for _, f := range ls {
			// check if it's a folder to skip atoi if not needed
			if f.IsDir() == false {
				continue
			} else if pid, err := strconv.Atoi(f.Name()); err == nil {
				// loop process descriptors
				path := fmt.Sprintf("/proc/%s/fd/", f.Name())
				descriptors, err := ioutil.ReadDir(path)
				if err == nil {
					for _, desc := range descriptors {
						descLink := fmt.Sprintf("%s%s", path, desc.Name())
						// resolve the symlink and compare to what we expect
						if link, err := os.Readlink(descLink); err == nil {
							// only consider sockets
							if strings.HasPrefix(link, "socket:[") == true {
								socket := link[8 : len(link)-1]
								inode, err := strconv.Atoi(socket)
								if err == nil {
									m[inode] = pid
								}
							}
						}
					}
				}
			}
		}
	}

	return m
}

func FindProcess(pid int) *Process {
	linkName := fmt.Sprintf("/proc/%d/exe", pid)
	if core.Exists(linkName) == false {
		return nil
	}

	if link, err := os.Readlink(linkName); err == nil && core.Exists(link) == true {
		proc := NewProcess(pid, link)

		if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			for i, b := range data {
				if b == 0x00 {
					data[i] = byte(' ')
				}
			}

			args := strings.Split(string(data), " ")
			for _, arg := range args {
				arg = core.Trim(arg)
				if arg != "" {
					proc.Args = append(proc.Args, arg)
				}
			}
		}

		return proc
	}
	return nil
}
