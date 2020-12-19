package procmon

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/netlink"
)

var socketsRegex, _ = regexp.Compile(`socket:\[([0-9]+)\]`)

// GetInfo collects information of a process.
func (p *Process) GetInfo() error {
	if err := p.readPath(); err != nil {
		return err
	}
	p.readCwd()
	p.readCmdline()
	p.readEnv()
	p.readDescriptors()
	p.readIOStats()
	p.readStatus()
	p.cleanPath()

	return nil
}

func (p *Process) setCwd(cwd string) {
	p.CWD = cwd
}

func (p *Process) readCwd() error {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.ID))
	if err != nil {
		return err
	}
	p.CWD = link
	return nil
}

// read and parse environment variables of a process.
func (p *Process) readEnv() {
	if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/environ", p.ID)); err == nil {
		for _, s := range strings.Split(string(data), "\x00") {
			parts := strings.SplitN(core.Trim(s), "=", 2)
			if parts != nil && len(parts) == 2 {
				key := core.Trim(parts[0])
				val := core.Trim(parts[1])
				p.Env[key] = val
			}
		}
	}
}

func (p *Process) readPath() error {
	linkName := fmt.Sprint("/proc/", p.ID, "/exe")
	if _, err := os.Lstat(linkName); err != nil {
		return err
	}

	if link, err := os.Readlink(linkName); err == nil {
		p.Path = link
	}

	return nil
}

func (p *Process) readCmdline() {
	if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.ID)); err == nil {
		for i, b := range data {
			if b == 0x00 {
				data[i] = byte(' ')
			}
		}

		p.Args = make([]string, 0)

		args := strings.Split(string(data), " ")
		for _, arg := range args {
			arg = core.Trim(arg)
			if arg != "" {
				p.Args = append(p.Args, arg)
			}
		}
	}
}

func (p *Process) readDescriptors() {
	f, err := os.Open(fmt.Sprint("/proc/", p.ID, "/fd/"))
	if err != nil {
		return
	}
	fDesc, err := f.Readdir(-1)
	f.Close()
	p.Descriptors = nil

	for _, fd := range fDesc {
		tempFd := &procDescriptors{
			Name: fd.Name(),
		}
		if link, err := os.Readlink(fmt.Sprint("/proc/", p.ID, "/fd/", fd.Name())); err == nil {
			tempFd.SymLink = link
			socket := socketsRegex.FindStringSubmatch(link)
			if len(socket) > 0 {
				socketInfo, err := netlink.GetSocketInfoByInode(socket[1])
				if err == nil {
					tempFd.SymLink = fmt.Sprintf("socket:[%s] - %d:%s -> %s:%d, state: %s", fd.Name(),
						socketInfo.ID.SourcePort,
						socketInfo.ID.Source.String(),
						dns.HostOr(socketInfo.ID.Destination, socketInfo.ID.Destination.String()),
						socketInfo.ID.DestinationPort,
						netlink.TCPStatesMap[socketInfo.State])
				}
			}

			if linkInfo, err := os.Lstat(link); err == nil {
				tempFd.Size = linkInfo.Size()
				tempFd.ModTime = linkInfo.ModTime()
			}
		}
		p.Descriptors = append(p.Descriptors, tempFd)
	}
}

func (p *Process) readIOStats() {
	f, err := os.Open(fmt.Sprint("/proc/", p.ID, "/io"))
	if err != nil {
		return
	}
	defer f.Close()

	p.IOStats = &procIOstats{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), " ")
		switch s[0] {
		case "rchar:":
			p.IOStats.RChar, _ = strconv.ParseInt(s[1], 10, 64)
		case "wchar:":
			p.IOStats.WChar, _ = strconv.ParseInt(s[1], 10, 64)
		case "syscr:":
			p.IOStats.SyscallRead, _ = strconv.ParseInt(s[1], 10, 64)
		case "syscw:":
			p.IOStats.SyscallWrite, _ = strconv.ParseInt(s[1], 10, 64)
		case "read_bytes:":
			p.IOStats.ReadBytes, _ = strconv.ParseInt(s[1], 10, 64)
		case "write_bytes:":
			p.IOStats.WriteBytes, _ = strconv.ParseInt(s[1], 10, 64)
		}
	}
}

func (p *Process) readStatus() {
	if data, err := ioutil.ReadFile(fmt.Sprint("/proc/", p.ID, "/status")); err == nil {
		p.Status = string(data)
	}
	if data, err := ioutil.ReadFile(fmt.Sprint("/proc/", p.ID, "/stat")); err == nil {
		p.Stat = string(data)
	}
	if data, err := ioutil.ReadFile(fmt.Sprint("/proc/", p.ID, "/stack")); err == nil {
		p.Stack = string(data)
	}
	if data, err := ioutil.ReadFile(fmt.Sprint("/proc/", p.ID, "/maps")); err == nil {
		p.Maps = string(data)
	}
	if data, err := ioutil.ReadFile(fmt.Sprint("/proc/", p.ID, "/statm")); err == nil {
		p.Statm = &procStatm{}
		fmt.Sscanf(string(data), "%d %d %d %d %d %d %d", &p.Statm.Size, &p.Statm.Resident, &p.Statm.Shared, &p.Statm.Text, &p.Statm.Lib, &p.Statm.Data, &p.Statm.Dt)
	}
}

func (p *Process) cleanPath() {
	pathLen := len(p.Path)
	if pathLen >= 10 && p.Path[pathLen-10:] == " (deleted)" {
		p.Path = p.Path[:len(p.Path)-10]
	}
}
