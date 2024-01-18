package procmon

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

var socketsRegex, _ = regexp.Compile(`socket:\[([0-9]+)\]`)

// GetParent obtains the information of this process' parent.
func (p *Process) GetParent() {
	hasParent := p.Parent != nil

	if hasParent {
		return
	}

	p.ReadPPID()
	if p.PPID == 0 {
		return
	}
	it, found := EventsCache.IsInStoreByPID(p.PPID)
	if found {
		p.Parent = &it.Proc
		p.Parent.GetParent()
		return
	}

	p.mu.Lock()
	p.Parent = NewProcessEmpty(p.PPID, "")
	p.mu.Unlock()
	p.Parent.ReadPath()

	// get process tree
	p.Parent.GetParent()
}

// BuildTree returns all the parents of this process.
func (p *Process) BuildTree() {
	items := len(p.Tree)
	if items > 0 && p.Tree[items-1].Value == 1 {
		return
	}

	// Adding this process to the tree, not to loose track of it.
	p.Tree = append(p.Tree,
		&protocol.StringInt{
			Key: p.Path, Value: uint32(p.ID),
		},
	)
	for pp := p.Parent; pp != nil; pp = pp.Parent {
		// add the parents in reverse order, so when we iterate over them with the rules
		// the first item is the most direct parent of the process.
		p.Tree = append(p.Tree,
			&protocol.StringInt{
				Key: pp.Path, Value: uint32(pp.ID),
			},
		)
	}
}

// GetDetails collects information of a process.
func (p *Process) GetDetails() error {
	if os.Getpid() == p.ID {
		return nil
	}
	// if the PID dir doesn't exist, the process may have exited or be a kernel connection
	// XXX: can a kernel connection exist without an entry in ProcFS?
	if p.Path == "" && p.IsAlive() == false {
		log.Debug("PID can't be read /proc/ %d %s", p.ID, p.Comm)

		// The Comm field shouldn't be empty if the proc monitor method is ebpf or audit.
		// If it's proc and the corresponding entry doesn't exist, there's nothing we can
		// do to inform the user about this process.
		if p.Comm == "" {
			return fmt.Errorf("Unable to get process information")
		}
	}
	if err := p.ReadPath(); err != nil {
		log.Debug("GetInfo() path can't be read: %s", p.Path)
		return err
	}
	p.ReadCmdline()
	p.ReadComm()
	p.ReadCwd()

	// we need to load the env variables now, in order to be used with the rules.
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

// ReadPPID obtains the pid of the parent process
func (p *Process) ReadPPID() {
	// ReadFile + parse = ~40us
	data, err := ioutil.ReadFile(p.pathStat)
	if err != nil {
		p.PPID = 0
		return
	}

	var state string
	// https://lore.kernel.org/lkml/tog7cb$105a$1@ciao.gmane.io/T/
	parts := bytes.Split(data, []byte(")"))
	data = parts[len(parts)-1]
	_, err = fmt.Sscanf(string(data), "%s %d", &state, &p.PPID)
	if err != nil || p.PPID == 0 {
		p.PPID = 0
		return
	}
}

// ReadComm reads the comm name from ProcFS /proc/<pid>/comm
func (p *Process) ReadComm() error {
	if p.Comm != "" {
		return nil
	}
	data, err := ioutil.ReadFile(p.pathComm)
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
	link, err := os.Readlink(p.pathCwd)
	if err != nil {
		return err
	}
	p.CWD = link
	return nil
}

// ReadEnv reads and parses the environment variables of a process.
func (p *Process) ReadEnv() {
	data, err := ioutil.ReadFile(p.pathEnviron)
	if err != nil {
		return
	}
	for _, s := range strings.Split(string(data), "\x00") {
		parts := strings.SplitN(core.Trim(s), "=", 2)
		if parts != nil && len(parts) == 2 {
			key := core.Trim(parts[0])
			val := core.Trim(parts[1])
			p.mu.Lock()
			p.Env[key] = val
			p.mu.Unlock()
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
	if p.Path != "" && core.IsAbsPath(p.Path) {
		return nil
	}
	defer func() {
		if p.Path == "" {
			// determine if this process might be of a kernel task.
			if data, err := ioutil.ReadFile(p.pathMaps); err == nil && len(data) == 0 {
				p.Path = KernelConnection
				p.Args = append(p.Args, p.Comm)
				return
			}
			p.Path = p.Comm
		}
	}()

	if _, err := os.Lstat(p.pathExe); err != nil {
		return err
	}

	// FIXME: this reading can give error: file name too long
	link, err := os.Readlink(p.pathExe)
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
	p.RealPath = core.ConcatStrings(p.pathRoot, "/", p.Path)
	if core.Exists(p.RealPath) == false {
		p.RealPath = p.Path
		// p.CleanPath() ?
	}
}

// ReadCmdline reads the cmdline of the process from ProcFS /proc/<pid>/cmdline
// This file may be empty if the process is of a kernel task.
// It can also be empty for short-lived processes.
func (p *Process) ReadCmdline() {
	if len(p.Args) > 0 {
		return
	}
	data, err := ioutil.ReadFile(p.pathCmdline)
	if err != nil || len(data) == 0 {
		return
	}
	// XXX: remove this loop, and split by "\x00"
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
	p.CleanArgs()
}

// CleanArgs applies fixes on the cmdline arguments.
// - AppImages cmdline reports the execuable launched as /proc/self/exe,
//   instead of the actual path to the binary.
func (p *Process) CleanArgs() {
	if len(p.Args) > 0 && p.Args[0] == ProcSelf {
		p.Args[0] = p.Path
	}
}

func (p *Process) readDescriptors() {
	f, err := os.Open(p.pathFd)
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
		link, err := os.Readlink(core.ConcatStrings(p.pathFd, fd.Name()))
		if err != nil {
			continue
		}
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

		p.Descriptors = append(p.Descriptors, tempFd)
	}
}

func (p *Process) readIOStats() (err error) {
	f, err := os.Open(p.pathIO)
	if err != nil {
		return err
	}
	defer f.Close()

	p.IOStats = &procIOstats{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), " ")
		switch s[0] {
		case "rchar:":
			p.IOStats.RChar, err = strconv.ParseInt(s[1], 10, 64)
		case "wchar:":
			p.IOStats.WChar, err = strconv.ParseInt(s[1], 10, 64)
		case "syscr:":
			p.IOStats.SyscallRead, err = strconv.ParseInt(s[1], 10, 64)
		case "syscw:":
			p.IOStats.SyscallWrite, err = strconv.ParseInt(s[1], 10, 64)
		case "read_bytes:":
			p.IOStats.ReadBytes, err = strconv.ParseInt(s[1], 10, 64)
		case "write_bytes:":
			p.IOStats.WriteBytes, err = strconv.ParseInt(s[1], 10, 64)
		}
	}

	return err
}

func (p *Process) readStatus() {
	if data, err := ioutil.ReadFile(p.pathStatus); err == nil {
		p.Status = string(data)
	}
	if data, err := ioutil.ReadFile(p.pathStat); err == nil {
		p.Stat = string(data)
	}
	if data, err := ioutil.ReadFile(core.ConcatStrings("/proc/", strconv.Itoa(p.ID), "/stack")); err == nil {
		p.Stack = string(data)
	}
	if data, err := ioutil.ReadFile(p.pathMaps); err == nil {
		p.Maps = string(data)
	}
	if data, err := ioutil.ReadFile(p.pathStatm); err == nil {
		p.Statm = &procStatm{}
		fmt.Sscanf(string(data), "%d %d %d %d %d %d %d", &p.Statm.Size, &p.Statm.Resident, &p.Statm.Shared, &p.Statm.Text, &p.Statm.Lib, &p.Statm.Data, &p.Statm.Dt)
	}
}

// CleanPath applies fixes on the path to the binary:
// - Remove extra characters from the link that it points to.
//   When a running process is deleted, the symlink has the bytes " (deleted")
//   appended to the link.
// - If the path is /proc/self/exe, resolve the symlink that it points to.
func (p *Process) CleanPath() {

	// Sometimes the path to the binary reported is the symbolic link of the process itself.
	// This is not useful to the user, and besides it's a generic path that can represent
	// to any process.
	// Therefore we cannot use /proc/self/exe directly, because it resolves to our own process.
	if strings.HasPrefix(p.Path, ProcSelf) {
		if link, err := os.Readlink(p.pathExe); err == nil {
			p.Path = link
			return
		}

		if len(p.Args) > 0 && p.Args[0] != "" {
			p.Path = p.Args[0]
			return
		}
		p.Path = p.Comm
	}

	pathLen := len(p.Path)
	if pathLen >= 10 && p.Path[pathLen-10:] == " (deleted)" {
		p.Path = p.Path[:len(p.Path)-10]
	}

	// We may receive relative paths from kernel, but the path of a process must be absolute
	if core.IsAbsPath(p.Path) == false {
		if err := p.ReadPath(); err != nil {
			log.Debug("ClenPath() error reading process path%s", err)
			return
		}
	}

}

// IsAlive checks if the process is still running
func (p *Process) IsAlive() bool {
	return core.Exists(p.pathProc)
}

// IsChild determines if this process is child of its parent
func (p *Process) IsChild() bool {
	return (p.Parent != nil && p.Parent.Path == p.Path && p.Parent.IsAlive()) ||
		core.Exists(core.ConcatStrings("/proc/", strconv.Itoa(p.PPID), "/task/", strconv.Itoa(p.ID)))

}

// ChecksumsCount returns the number of checksums of this process.
func (p *Process) ChecksumsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.Checksums)
}

// ResetChecksums initializes checksums
func (p *Process) ResetChecksums() {
	p.mu.Lock()
	p.Checksums = make(map[string]string)
	p.mu.Unlock()
}

// ComputeChecksums calculates the checksums of a the process path to the binary.
// Users may want to use different hashing alogrithms.
func (p *Process) ComputeChecksums(hashes map[string]uint) {
	if p.IsAlive() && len(p.Checksums) > 0 {
		log.Debug("process.ComputeChecksums() already hashed: %d, path: %s, %v", p.ID, p.Path, p.Checksums)
		return
	}

	for hash := range hashes {
		p.ComputeChecksum(hash)
	}
}

// ComputeChecksum calculates the checksum of a the process path to the binary
func (p *Process) ComputeChecksum(algo string) {
	if p.Path == "" || p.Path == KernelConnection {
		return
	}
	if p.Checksums[algo] != "" {
		log.Debug("[hashing] %d already hasshed [%s]: %s\n", p.ID, algo, p.Checksums[algo])
		return
	}

	// - hash first the exe link. That's the process that is currently running.
	//   If the binary has been updated while it's running, the checksum on disk
	//   will change and it won't match the one defined in the rules.
	//   However the exe link will match the one defined in the rules.
	//   So keep it valid until the user restarts the process.
	//
	// - If it can't be read, hash the RealPath, because containerized binaries'
	//   path usually won't exist on the host.
	//   Path cannot be trusted, because multiple processes with the same path
	//   can coexist in different namespaces.
	//   The real path is /proc/<pid>/root/<path-to-the-binary>
	paths := []string{p.pathExe, p.RealPath, p.Path}

	var h hash.Hash
	if algo == HashMD5 {
		h = md5.New()
	} else if algo == HashSHA1 {
		h = sha1.New()
	} else {
		log.Debug("Unknown hashing algorithm: %s", algo)
		return
	}

	i := uint8(0)
	for i = 0; i < 3; i++ {
		log.Debug("[hashing %s], path %d: %s -> %s", algo, i, paths[i], p.Path)

		start := time.Now()
		h.Reset()
		// can this be instantiate outside of the loop?
		f, err := os.Open(paths[i])
		if err != nil {
			log.Debug("[hashing %s] Unable to open path: %s", algo, paths[i])

			// one of the reasons to end here is when hashing AppImages
			code, err := p.DumpImage()
			if err != nil {
				log.Debug("[hashing] Unable to dump process memory: %s", err)
				continue
			}
			p.mu.Lock()
			p.Checksums[algo] = hex.EncodeToString(h.Sum(code))
			p.mu.Unlock()
			log.Debug("[hashing] memory region hashed, elapsed: %v ,Hash: %s, %s\n", time.Since(start), p.Checksums[algo], paths[i])
			code = nil
			break
		}
		defer f.Close()

		if _, err = io.Copy(h, f); err != nil {
			log.Debug("[hashing %s] Error copying data: %s", algo, err)
			continue
		}
		p.mu.Lock()
		p.Checksums[algo] = hex.EncodeToString(h.Sum(nil))
		p.mu.Unlock()
		log.Debug("[hashing] elapsed: %v ,Hash: %s, %s\n", time.Since(start), p.Checksums[algo], paths[i])

		break
	}

	return
}

// MemoryMapping represents a memory mapping region
type MemoryMapping struct {
	StartAddr uint64
	EndAddr   uint64
}

// DumpImage reads the memory of the current process, and returns it
// as byte array.
func (p *Process) DumpImage() ([]byte, error) {
	return p.dumpFileImage(p.Path)
}

// dumpFileImage will dump the memory region of a file mapped by this process.
// By default it'll dump the current image of this process.
func (p *Process) dumpFileImage(filePath string) ([]byte, error) {
	var mappings []MemoryMapping

	// read memory mappings
	mapsFile, err := os.Open(p.pathMaps)
	if err != nil {
		return nil, err
	}
	defer mapsFile.Close()

	if filePath == "" {
		filePath = p.Path
	}

	size := 0
	mapsScanner := bufio.NewScanner(mapsFile)
	for mapsScanner.Scan() {
		addrMap := mapsScanner.Text()
		// filter by process path
		// TODO: make it configurable
		if !strings.Contains(addrMap, filePath) {
			log.Debug("dumpFileImage() addr doesn't contain %s", filePath)
			continue
		}
		fields := strings.Fields(addrMap)
		if len(fields) < 6 {
			log.Debug("dumpFileImage() line less than 6: %v", fields)
			continue
		}

		// TODO: make it configurable
		/*permissions := fields[1]
		  if !strings.Contains(permissions, "r-xp") {
		      continue
		  }
		*/

		addrRange := strings.Split(fields[0], "-")
		addrStart, err := strconv.ParseUint(addrRange[0], 16, 64)
		if err != nil {
			//log.Debug("dumpFileImage() invalid addrStart: %v", addrRange)
			continue
		}
		addrEnd, err := strconv.ParseUint(addrRange[1], 16, 64)
		if err != nil {
			log.Debug("dumpFileImage() invalid addrEnd: %v", addrRange)
			continue
		}
		size += int(addrEnd - addrStart)
		mappings = append(mappings, MemoryMapping{StartAddr: addrStart, EndAddr: addrEnd})
	}

	// read process memory
	elfCode, err := p.readMem(mappings)
	mappings = nil
	//fmt.Printf(">>> READ MEM, regions size: %d, elfCode: %d\n", size, len(elfCode))

	if err != nil {
		return nil, err
	}

	return elfCode, nil
}

// given a range of addrs, read it from mem and return the content
func (p *Process) readMem(mappings []MemoryMapping) ([]byte, error) {
	var elfCode []byte
	memFile, err := os.Open(p.pathMem)
	if err != nil {
		return nil, err
	}
	defer memFile.Close()

	for _, mapping := range mappings {
		memFile.Seek(int64(mapping.StartAddr), io.SeekStart)
		code := make([]byte, mapping.EndAddr-mapping.StartAddr)
		_, err = memFile.Read(code)
		if err != nil {
			return nil, err
		}
	}

	return elfCode, nil
}
