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
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netlink"
)

var socketsRegex, _ = regexp.Compile(`socket:\[([0-9]+)\]`)

// GetInfo collects information of a process.
func (p *Process) GetInfo() error {
	if os.Getpid() == p.ID {
		return nil
	}
	// if the PID dir doesn't exist, the process may have exited or be a kernel connection
	// XXX: can a kernel connection exist without an entry in ProcFS?
	if p.Path == "" && core.Exists(fmt.Sprint("/proc/", p.ID)) == false {
		log.Debug("PID can't be read /proc/ %d %s", p.ID, p.Comm)

		// The Comm field shouldn't be empty if the proc monitor method is ebpf or audit.
		// If it's proc and the corresponding entry doesn't exist, there's nothing we can
		// do to inform the user about this process.
		if p.Comm == "" {
			return fmt.Errorf("Unable to get process information")
		}
	}
	p.ReadCmdline()
	p.ReadComm()
	p.ReadCwd()

	if err := p.ReadPath(); err != nil {
		log.Error("GetInfo() path can't be read")
		return err
	}
	p.ReadEnv()

	return nil
}

// GetExtraInfo collects information of a process.
func (p *Process) GetExtraInfo() error {
	p.ReadEnv()
	p.readDescriptors()
	p.readIOStats()
	p.readStatus()

	return nil
}

// ReadComm reads the comm name from ProcFS /proc/<pid>/comm
func (p *Process) ReadComm() error {
	if p.Comm != "" {
		return nil
	}
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", p.ID))
	if err != nil {
		return err
	}
	p.Comm = core.Trim(string(data))
	return nil
}

// ReadCwd reads the current working directory name from ProcFS /proc/<pid>/cwd
func (p *Process) ReadCwd() error {
	if p.CWD != "" {
		return nil
	}
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.ID))
	if err != nil {
		return err
	}
	p.CWD = link
	return nil
}

// ReadEnv reads and parses the environment variables of a process.
func (p *Process) ReadEnv() {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/environ", p.ID))
	if err != nil {
		return
	}
	for _, s := range strings.Split(string(data), "\x00") {
		parts := strings.SplitN(core.Trim(s), "=", 2)
		if parts != nil && len(parts) == 2 {
			key := core.Trim(parts[0])
			val := core.Trim(parts[1])
			p.Env[key] = val
		}
	}
}

// ReadPath reads the symbolic link that /proc/<pid>/exe points to.
// Note 1: this link might not exist on the root filesystem, it might
// have been executed from a container, so the real path would be:
// /proc/<pid>/root/<path that 'exe' points to>
//
// Note 2:
// There're at least 3 things that a (regular) kernel connection meets
// from userspace POV:
// - /proc/<pid>/cmdline and /proc/<pid>/maps empty
// - /proc/<pid>/exe can't be read
func (p *Process) ReadPath() error {
	// avoid rereading the path
	if p.Path != "" {
		return nil
	}
	defer func() {
		if p.Path == "" {
			// determine if this process might be of a kernel task.
			if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/maps", p.ID)); err == nil && len(data) == 0 {
				p.Path = "Kernel connection"
				p.Args = append(p.Args, p.Comm)
				return
			}
			p.Path = p.Comm
		}
	}()

	linkName := fmt.Sprint("/proc/", p.ID, "/exe")
	if _, err := os.Lstat(linkName); err != nil {
		return err
	}

	// FIXME: this reading can give error: file name too long
	link, err := os.Readlink(linkName)
	if err != nil {
		return err
	}
	p.SetPath(link)
	return nil
}

// SetPath sets the path of the process, and fixes it if it's needed.
func (p *Process) SetPath(path string) {
	p.Path = path
	p.CleanPath()
}

// ReadCmdline reads the cmdline of the process from ProcFS /proc/<pid>/cmdline
// This file may be empty if the process is of a kernel task.
// It can also be empty for short-lived processes.
func (p *Process) ReadCmdline() {
	if len(p.Args) > 0 {
		return
	}
	if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.ID)); err == nil {
		if len(data) == 0 {
			return
		}
		for i, b := range data {
			if b == 0x00 {
				data[i] = byte(' ')
			}
		}

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

// CleanPath removes extra characters from the link that it points to.
// When a running process is deleted, the symlink has the bytes " (deleted")
// appended to the link.
func (p *Process) CleanPath() {

	// Sometimes the path to the binary reported is the symbolic link of the process itself.
	// This is not useful to the user, and besides it's a generic path that can represent
	// to any process.
	// Therefore we cannot use /proc/self/exe directly, because it resolves to our own process.
	if p.Path == "/proc/self/exe" {
		if link, err := os.Readlink(fmt.Sprint("/proc/", p.ID, "/exe")); err == nil {
			p.Path = link
			return
		}
		// link read failed

		if p.Args[0] != "" {
			p.Path = p.Args[0]
			return
		}
		p.Path = p.Comm
	}

	pathLen := len(p.Path)
	if pathLen >= 10 && p.Path[pathLen-10:] == " (deleted)" {
		p.Path = p.Path[:len(p.Path)-10]
	}
}
