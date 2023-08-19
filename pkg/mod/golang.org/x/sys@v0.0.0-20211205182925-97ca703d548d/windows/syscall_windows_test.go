// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package windows_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/internal/unsafeheader"
	"golang.org/x/sys/windows"
)

func TestWin32finddata(t *testing.T) {
	dir, err := ioutil.TempDir("", "go-build")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "long_name.and_extension")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create %v: %v", path, err)
	}
	f.Close()

	type X struct {
		fd  windows.Win32finddata
		got byte
		pad [10]byte // to protect ourselves

	}
	var want byte = 2 // it is unlikely to have this character in the filename
	x := X{got: want}

	pathp, _ := windows.UTF16PtrFromString(path)
	h, err := windows.FindFirstFile(pathp, &(x.fd))
	if err != nil {
		t.Fatalf("FindFirstFile failed: %v", err)
	}
	err = windows.FindClose(h)
	if err != nil {
		t.Fatalf("FindClose failed: %v", err)
	}

	if x.got != want {
		t.Fatalf("memory corruption: want=%d got=%d", want, x.got)
	}
}

func TestFormatMessage(t *testing.T) {
	dll := windows.MustLoadDLL("netevent.dll")

	const TITLE_SC_MESSAGE_BOX uint32 = 0xC0001B75
	const flags uint32 = syscall.FORMAT_MESSAGE_FROM_HMODULE | syscall.FORMAT_MESSAGE_ARGUMENT_ARRAY | syscall.FORMAT_MESSAGE_IGNORE_INSERTS
	buf := make([]uint16, 300)
	_, err := windows.FormatMessage(flags, uintptr(dll.Handle), TITLE_SC_MESSAGE_BOX, 0, buf, nil)
	if err != nil {
		t.Fatalf("FormatMessage for handle=%x and errno=%x failed: %v", dll.Handle, TITLE_SC_MESSAGE_BOX, err)
	}
}

func abort(funcname string, err error) {
	panic(funcname + " failed: " + err.Error())
}

func ExampleLoadLibrary() {
	h, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		abort("LoadLibrary", err)
	}
	defer windows.FreeLibrary(h)
	proc, err := windows.GetProcAddress(h, "GetVersion")
	if err != nil {
		abort("GetProcAddress", err)
	}
	r, _, _ := syscall.Syscall(uintptr(proc), 0, 0, 0, 0)
	major := byte(r)
	minor := uint8(r >> 8)
	build := uint16(r >> 16)
	print("windows version ", major, ".", minor, " (Build ", build, ")\n")
}

func TestTOKEN_ALL_ACCESS(t *testing.T) {
	if windows.TOKEN_ALL_ACCESS != 0xF01FF {
		t.Errorf("TOKEN_ALL_ACCESS = %x, want 0xF01FF", windows.TOKEN_ALL_ACCESS)
	}
}

func TestCreateWellKnownSid(t *testing.T) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("Unable to create well known sid for administrators: %v", err)
	}
	if got, want := sid.String(), "S-1-5-32-544"; got != want {
		t.Fatalf("Builtin Administrators SID = %s, want %s", got, want)
	}
}

func TestPseudoTokens(t *testing.T) {
	version, err := windows.GetVersion()
	if err != nil {
		t.Fatal(err)
	}
	if ((version&0xffff)>>8)|((version&0xff)<<8) < 0x0602 {
		return
	}

	realProcessToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer realProcessToken.Close()
	realProcessUser, err := realProcessToken.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	pseudoProcessToken := windows.GetCurrentProcessToken()
	pseudoProcessUser, err := pseudoProcessToken.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid(realProcessUser.User.Sid, pseudoProcessUser.User.Sid) {
		t.Fatal("The real process token does not have the same as the pseudo process token")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err = windows.RevertToSelf()
	if err != nil {
		t.Fatal(err)
	}

	pseudoThreadToken := windows.GetCurrentThreadToken()
	_, err = pseudoThreadToken.GetTokenUser()
	if err != windows.ERROR_NO_TOKEN {
		t.Fatal("Expected an empty thread token")
	}
	pseudoThreadEffectiveToken := windows.GetCurrentThreadEffectiveToken()
	pseudoThreadEffectiveUser, err := pseudoThreadEffectiveToken.GetTokenUser()
	if err != nil {
		t.Fatal(nil)
	}
	if !windows.EqualSid(realProcessUser.User.Sid, pseudoThreadEffectiveUser.User.Sid) {
		t.Fatal("The real process token does not have the same as the pseudo thread effective token, even though we aren't impersonating")
	}

	err = windows.ImpersonateSelf(windows.SecurityImpersonation)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.RevertToSelf()
	pseudoThreadUser, err := pseudoThreadToken.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid(realProcessUser.User.Sid, pseudoThreadUser.User.Sid) {
		t.Fatal("The real process token does not have the same as the pseudo thread token after impersonating self")
	}
}

func TestGUID(t *testing.T) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	if guid.Data1 == 0 && guid.Data2 == 0 && guid.Data3 == 0 && guid.Data4 == [8]byte{} {
		t.Fatal("Got an all zero GUID, which is overwhelmingly unlikely")
	}
	want := fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}", guid.Data1, guid.Data2, guid.Data3, guid.Data4[:2], guid.Data4[2:])
	got := guid.String()
	if got != want {
		t.Fatalf("String = %q; want %q", got, want)
	}
	guid2, err := windows.GUIDFromString(got)
	if err != nil {
		t.Fatal(err)
	}
	if guid2 != guid {
		t.Fatalf("Did not parse string back to original GUID = %q; want %q", guid2, guid)
	}
	_, err = windows.GUIDFromString("not-a-real-guid")
	if err != syscall.Errno(windows.CO_E_CLASSSTRING) {
		t.Fatalf("Bad GUID string error = %v; want CO_E_CLASSSTRING", err)
	}
}

func TestKnownFolderPath(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	profileDir, err := token.GetUserProfileDirectory()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(profileDir, "Desktop")
	got, err := windows.KnownFolderPath(windows.FOLDERID_Desktop, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	if want != got {
		t.Fatalf("Path = %q; want %q", got, want)
	}
}

func TestRtlGetVersion(t *testing.T) {
	version := windows.RtlGetVersion()
	major, minor, build := windows.RtlGetNtVersionNumbers()
	// Go is not explictly added to the application compatibility database, so
	// these two functions should return the same thing.
	if version.MajorVersion != major || version.MinorVersion != minor || version.BuildNumber != build {
		t.Fatalf("%d.%d.%d != %d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber, major, minor, build)
	}
}

func TestGetNamedSecurityInfo(t *testing.T) {
	path, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !sd.IsValid() {
		t.Fatal("Invalid security descriptor")
	}
	sdOwner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !sdOwner.IsValid() {
		t.Fatal("Invalid security descriptor owner")
	}
}

func TestGetSecurityInfo(t *testing.T) {
	sd, err := windows.GetSecurityInfo(windows.CurrentProcess(), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !sd.IsValid() {
		t.Fatal("Invalid security descriptor")
	}
	sdStr := sd.String()
	if !strings.HasPrefix(sdStr, "D:(A;") {
		t.Fatalf("DACL = %q; want D:(A;...", sdStr)
	}
}

func TestSddlConversion(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("O:BA")
	if err != nil {
		t.Fatal(err)
	}
	if !sd.IsValid() {
		t.Fatal("Invalid security descriptor")
	}
	sdOwner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !sdOwner.IsValid() {
		t.Fatal("Invalid security descriptor owner")
	}
	if !sdOwner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Fatalf("Owner = %q; want S-1-5-32-544", sdOwner)
	}
}

func TestBuildSecurityDescriptor(t *testing.T) {
	const want = "O:SYD:(A;;GA;;;BA)"

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}

	access := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(adminSid),
		},
	}}
	owner := &windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeType:  windows.TRUSTEE_IS_USER,
		TrusteeValue: windows.TrusteeValueFromSID(systemSid),
	}

	sd, err := windows.BuildSecurityDescriptor(owner, nil, access, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sd, err = sd.ToAbsolute()
	if err != nil {
		t.Fatal(err)
	}
	err = sd.SetSACL(nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := sd.String(); got != want {
		t.Fatalf("SD = %q; want %q", got, want)
	}
	sd, err = sd.ToSelfRelative()
	if err != nil {
		t.Fatal(err)
	}
	if got := sd.String(); got != want {
		t.Fatalf("SD = %q; want %q", got, want)
	}

	sd, err = windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = sd.SetDACL(acl, true, false)
	if err != nil {
		t.Fatal(err)
	}
	err = sd.SetOwner(systemSid, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := sd.String(); got != want {
		t.Fatalf("SD = %q; want %q", got, want)
	}
	sd, err = sd.ToSelfRelative()
	if err != nil {
		t.Fatal(err)
	}
	if got := sd.String(); got != want {
		t.Fatalf("SD = %q; want %q", got, want)
	}
}

func TestGetDiskFreeSpaceEx(t *testing.T) {
	cwd, err := windows.UTF16PtrFromString(".")
	if err != nil {
		t.Fatalf(`failed to call UTF16PtrFromString("."): %v`, err)
	}
	var freeBytesAvailableToCaller, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(cwd, &freeBytesAvailableToCaller, &totalNumberOfBytes, &totalNumberOfFreeBytes); err != nil {
		t.Fatalf("failed to call GetDiskFreeSpaceEx: %v", err)
	}

	if freeBytesAvailableToCaller == 0 {
		t.Errorf("freeBytesAvailableToCaller: got 0; want > 0")
	}
	if totalNumberOfBytes == 0 {
		t.Errorf("totalNumberOfBytes: got 0; want > 0")
	}
	if totalNumberOfFreeBytes == 0 {
		t.Errorf("totalNumberOfFreeBytes: got 0; want > 0")
	}
}

func TestGetPreferredUILanguages(t *testing.T) {
	tab := map[string]func(flags uint32) ([]string, error){
		"GetProcessPreferredUILanguages": windows.GetProcessPreferredUILanguages,
		"GetThreadPreferredUILanguages":  windows.GetThreadPreferredUILanguages,
		"GetUserPreferredUILanguages":    windows.GetUserPreferredUILanguages,
		"GetSystemPreferredUILanguages":  windows.GetSystemPreferredUILanguages,
	}
	for fName, f := range tab {
		lang, err := f(windows.MUI_LANGUAGE_ID)
		if err != nil {
			t.Errorf(`failed to call %v(MUI_LANGUAGE_ID): %v`, fName, err)
		}
		for _, l := range lang {
			_, err := strconv.ParseUint(l, 16, 16)
			if err != nil {
				t.Errorf(`%v(MUI_LANGUAGE_ID) returned unexpected LANGID: %v`, fName, l)
			}
		}

		lang, err = f(windows.MUI_LANGUAGE_NAME)
		if err != nil {
			t.Errorf(`failed to call %v(MUI_LANGUAGE_NAME): %v`, fName, err)
		}
	}
}

func TestProcessWorkingSetSizeEx(t *testing.T) {
	// Grab a handle to the current process
	hProcess := windows.CurrentProcess()

	// Allocate memory to store the result of the query
	var minimumWorkingSetSize, maximumWorkingSetSize uintptr

	// Make the system-call
	var flag uint32
	windows.GetProcessWorkingSetSizeEx(hProcess, &minimumWorkingSetSize, &maximumWorkingSetSize, &flag)

	// Set the new limits to the current ones
	if err := windows.SetProcessWorkingSetSizeEx(hProcess, minimumWorkingSetSize, maximumWorkingSetSize, flag); err != nil {
		t.Error(err)
	}
}

func TestJobObjectInfo(t *testing.T) {
	jo, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatalf("CreateJobObject failed: %v", err)
	}
	defer windows.CloseHandle(jo)

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION

	err = windows.QueryInformationJobObject(jo, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	if err != nil {
		t.Fatalf("QueryInformationJobObject failed: %v", err)
	}

	const wantMemLimit = 4 * 1024

	info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
	info.ProcessMemoryLimit = wantMemLimit
	_, err = windows.SetInformationJobObject(jo, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		t.Fatalf("SetInformationJobObject failed: %v", err)
	}

	err = windows.QueryInformationJobObject(jo, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	if err != nil {
		t.Fatalf("QueryInformationJobObject failed: %v", err)
	}

	if have := info.ProcessMemoryLimit; wantMemLimit != have {
		t.Errorf("ProcessMemoryLimit is wrong: want %v have %v", wantMemLimit, have)
	}
}

func TestIsWow64Process2(t *testing.T) {
	var processMachine, nativeMachine uint16
	err := windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine)
	if errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		maj, min, build := windows.RtlGetNtVersionNumbers()
		if maj < 10 || (maj == 10 && min == 0 && build < 17763) {
			t.Skip("not available on older versions of Windows")
			return
		}
	}
	if err != nil {
		t.Fatalf("IsWow64Process2 failed: %v", err)
	}
	if processMachine == pe.IMAGE_FILE_MACHINE_UNKNOWN {
		processMachine = nativeMachine
	}
	switch {
	case processMachine == pe.IMAGE_FILE_MACHINE_AMD64 && runtime.GOARCH == "amd64":
	case processMachine == pe.IMAGE_FILE_MACHINE_I386 && runtime.GOARCH == "386":
	case processMachine == pe.IMAGE_FILE_MACHINE_ARMNT && runtime.GOARCH == "arm":
	case processMachine == pe.IMAGE_FILE_MACHINE_ARM64 && runtime.GOARCH == "arm64":
	default:
		t.Errorf("IsWow64Process2 is wrong: want %v have %v", runtime.GOARCH, processMachine)
	}
}

func TestNTStatusString(t *testing.T) {
	want := "The name limit for the local computer network adapter card was exceeded."
	got := windows.STATUS_TOO_MANY_NAMES.Error()
	if want != got {
		t.Errorf("NTStatus.Error did not return an expected error string - want %q; got %q", want, got)
	}
}

func TestNTStatusConversion(t *testing.T) {
	want := windows.ERROR_TOO_MANY_NAMES
	got := windows.STATUS_TOO_MANY_NAMES.Errno()
	if want != got {
		t.Errorf("NTStatus.Errno = %q (0x%x); want %q (0x%x)", got.Error(), got, want.Error(), want)
	}
}

func TestPEBFilePath(t *testing.T) {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil || peb.Ldr == nil {
		t.Error("unable to retrieve PEB with valid Ldr")
	}
	var entry *windows.LDR_DATA_TABLE_ENTRY
	for cur := peb.Ldr.InMemoryOrderModuleList.Flink; cur != &peb.Ldr.InMemoryOrderModuleList; cur = cur.Flink {
		e := (*windows.LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(cur)) - unsafe.Offsetof(windows.LDR_DATA_TABLE_ENTRY{}.InMemoryOrderLinks)))
		if e.DllBase == peb.ImageBaseAddress {
			entry = e
			break
		}
	}
	if entry == nil {
		t.Error("unable to find Ldr entry for current process")
	}
	osPath, err := os.Executable()
	if err != nil {
		t.Errorf("unable to get path to current executable: %v", err)
	}
	pebPath := entry.FullDllName.String()
	if osPath != pebPath {
		t.Errorf("peb.Ldr.{entry}.FullDllName = %#q; want %#q", pebPath, osPath)
	}
	paramPath := peb.ProcessParameters.ImagePathName.String()
	if osPath != paramPath {
		t.Errorf("peb.ProcessParameters.ImagePathName.{entry}.ImagePathName = %#q; want %#q", paramPath, osPath)
	}
	osCwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get working directory: %v", err)
	}
	osCwd = filepath.Clean(osCwd)
	paramCwd := filepath.Clean(peb.ProcessParameters.CurrentDirectory.DosPath.String())
	if paramCwd != osCwd {
		t.Errorf("peb.ProcessParameters.CurrentDirectory.DosPath = %#q; want %#q", paramCwd, osCwd)
	}
}

func TestResourceExtraction(t *testing.T) {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Errorf("unable to find system32 directory: %v", err)
	}
	cmd, err := windows.LoadLibrary(filepath.Join(system32, "cmd.exe"))
	if err != nil {
		t.Errorf("unable to load cmd.exe: %v", err)
	}
	defer windows.FreeLibrary(cmd)
	rsrc, err := windows.FindResource(cmd, windows.CREATEPROCESS_MANIFEST_RESOURCE_ID, windows.RT_MANIFEST)
	if err != nil {
		t.Errorf("unable to find cmd.exe manifest resource: %v", err)
	}
	manifest, err := windows.LoadResourceData(cmd, rsrc)
	if err != nil {
		t.Errorf("unable to load cmd.exe manifest resource data: %v", err)
	}
	if !bytes.Contains(manifest, []byte("</assembly>")) {
		t.Errorf("did not find </assembly> in manifest")
	}
}

func TestCommandLineRecomposition(t *testing.T) {
	const (
		maxCharsPerArg  = 35
		maxArgsPerTrial = 80
		doubleQuoteProb = 4
		singleQuoteProb = 1
		backSlashProb   = 3
		spaceProb       = 1
		trials          = 1000
	)
	randString := func(l int) []rune {
		s := make([]rune, l)
		for i := range s {
			s[i] = rand.Int31()
		}
		return s
	}
	mungeString := func(s []rune, char rune, timesInTen int) {
		if timesInTen < rand.Intn(10)+1 || len(s) == 0 {
			return
		}
		s[rand.Intn(len(s))] = char
	}
	argStorage := make([]string, maxArgsPerTrial+1)
	for i := 0; i < trials; i++ {
		args := argStorage[:rand.Intn(maxArgsPerTrial)+2]
		args[0] = "valid-filename-for-arg0"
		for j := 1; j < len(args); j++ {
			arg := randString(rand.Intn(maxCharsPerArg + 1))
			mungeString(arg, '"', doubleQuoteProb)
			mungeString(arg, '\'', singleQuoteProb)
			mungeString(arg, '\\', backSlashProb)
			mungeString(arg, ' ', spaceProb)
			args[j] = string(arg)
		}
		commandLine := windows.ComposeCommandLine(args)
		decomposedArgs, err := windows.DecomposeCommandLine(commandLine)
		if err != nil {
			t.Errorf("Unable to decompose %#q made from %v: %v", commandLine, args, err)
			continue
		}
		if len(decomposedArgs) != len(args) {
			t.Errorf("Incorrect decomposition length from %v to %#q to %v", args, commandLine, decomposedArgs)
			continue
		}
		badMatches := make([]int, 0, len(args))
		for i := range args {
			if args[i] != decomposedArgs[i] {
				badMatches = append(badMatches, i)
			}
		}
		if len(badMatches) != 0 {
			t.Errorf("Incorrect decomposition at indices %v from %v to %#q to %v", badMatches, args, commandLine, decomposedArgs)
			continue
		}
	}
}

func TestWinVerifyTrust(t *testing.T) {
	evsignedfile := `.\testdata\ev-signed-file.exe`
	evsignedfile16, err := windows.UTF16PtrFromString(evsignedfile)
	if err != nil {
		t.Fatalf("unable to get utf16 of %s: %v", evsignedfile, err)
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE, // No revocation checking, in case the tests don't have network connectivity.
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: evsignedfile16,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		t.Errorf("%s did not verify: %v", evsignedfile, verifyErr)
	}
	if closeErr != nil {
		t.Errorf("unable to free verification resources: %v", closeErr)
	}

	// Now that we've verified the legitimate file verifies, let's corrupt it and see if it correctly fails.

	dir, err := ioutil.TempDir("", "go-build")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(dir)
	corruptedEvsignedfile := filepath.Join(dir, "corrupted-file")
	evsignedfileBytes, err := ioutil.ReadFile(evsignedfile)
	if err != nil {
		t.Fatalf("unable to read %s bytes: %v", evsignedfile, err)
	}
	if len(evsignedfileBytes) > 0 {
		evsignedfileBytes[len(evsignedfileBytes)/2-1]++
	}
	err = ioutil.WriteFile(corruptedEvsignedfile, evsignedfileBytes, 0755)
	if err != nil {
		t.Fatalf("unable to write corrupted ntoskrnl.exe bytes: %v", err)
	}
	evsignedfile16, err = windows.UTF16PtrFromString(corruptedEvsignedfile)
	if err != nil {
		t.Fatalf("unable to get utf16 of ntoskrnl.exe: %v", err)
	}
	data = &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE, // No revocation checking, in case the tests don't have network connectivity.
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: evsignedfile16,
		}),
	}
	verifyErr = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != windows.Errno(windows.TRUST_E_BAD_DIGEST) {
		t.Errorf("%s did not fail to verify as expected: %v", corruptedEvsignedfile, verifyErr)
	}
	if closeErr != nil {
		t.Errorf("unable to free verification resources: %v", closeErr)
	}

}

func TestProcessModules(t *testing.T) {
	process, err := windows.GetCurrentProcess()
	if err != nil {
		t.Fatalf("unable to get current process: %v", err)
	}
	// NB: Assume that we're always the first module. This technically isn't documented anywhere (that I could find), but seems to always hold.
	var module windows.Handle
	var cbNeeded uint32
	err = windows.EnumProcessModules(process, &module, uint32(unsafe.Sizeof(module)), &cbNeeded)
	if err != nil {
		t.Fatalf("EnumProcessModules failed: %v", err)
	}

	var moduleEx windows.Handle
	err = windows.EnumProcessModulesEx(process, &moduleEx, uint32(unsafe.Sizeof(moduleEx)), &cbNeeded, windows.LIST_MODULES_DEFAULT)
	if err != nil {
		t.Fatalf("EnumProcessModulesEx failed: %v", err)
	}
	if module != moduleEx {
		t.Fatalf("module from EnumProcessModules does not match EnumProcessModulesEx: %v != %v", module, moduleEx)
	}

	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("unable to get current executable path: %v", err)
	}

	modulePathUTF16 := make([]uint16, len(exePath)+1)
	err = windows.GetModuleFileNameEx(process, module, &modulePathUTF16[0], uint32(len(modulePathUTF16)))
	if err != nil {
		t.Fatalf("GetModuleFileNameEx failed: %v", err)
	}

	modulePath := windows.UTF16ToString(modulePathUTF16)
	if modulePath != exePath {
		t.Fatalf("module does not match executable for GetModuleFileNameEx: %s != %s", modulePath, exePath)
	}

	err = windows.GetModuleBaseName(process, module, &modulePathUTF16[0], uint32(len(modulePathUTF16)))
	if err != nil {
		t.Fatalf("GetModuleBaseName failed: %v", err)
	}

	modulePath = windows.UTF16ToString(modulePathUTF16)
	baseExePath := filepath.Base(exePath)
	if modulePath != baseExePath {
		t.Fatalf("module does not match executable for GetModuleBaseName: %s != %s", modulePath, baseExePath)
	}

	var moduleInfo windows.ModuleInfo
	err = windows.GetModuleInformation(process, module, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))
	if err != nil {
		t.Fatalf("GetModuleInformation failed: %v", err)
	}

	peFile, err := pe.Open(exePath)
	if err != nil {
		t.Fatalf("unable to open current executable: %v", err)
	}
	defer peFile.Close()

	var peSizeOfImage uint32
	switch runtime.GOARCH {
	case "amd64", "arm64":
		peSizeOfImage = peFile.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage
	case "386", "arm":
		peSizeOfImage = peFile.OptionalHeader.(*pe.OptionalHeader32).SizeOfImage
	default:
		t.Fatalf("unable to test GetModuleInformation on arch %v", runtime.GOARCH)
	}

	if moduleInfo.SizeOfImage != peSizeOfImage {
		t.Fatalf("module size does not match executable: %v != %v", moduleInfo.SizeOfImage, peSizeOfImage)
	}
}

func TestReadWriteProcessMemory(t *testing.T) {
	testBuffer := []byte{0xBA, 0xAD, 0xF0, 0x0D}

	process, err := windows.GetCurrentProcess()
	if err != nil {
		t.Fatalf("unable to get current process: %v", err)
	}

	buffer := make([]byte, len(testBuffer))
	err = windows.ReadProcessMemory(process, uintptr(unsafe.Pointer(&testBuffer[0])), &buffer[0], uintptr(len(buffer)), nil)
	if err != nil {
		t.Errorf("ReadProcessMemory failed: %v", err)
	}
	if !bytes.Equal(testBuffer, buffer) {
		t.Errorf("bytes read does not match buffer: 0x%X != 0x%X", testBuffer, buffer)
	}

	buffer = []byte{0xDE, 0xAD, 0xBE, 0xEF}
	err = windows.WriteProcessMemory(process, uintptr(unsafe.Pointer(&testBuffer[0])), &buffer[0], uintptr(len(buffer)), nil)
	if err != nil {
		t.Errorf("WriteProcessMemory failed: %v", err)
	}
	if !bytes.Equal(testBuffer, buffer) {
		t.Errorf("bytes written does not match buffer: 0x%X != 0x%X", testBuffer, buffer)
	}
}

func TestSystemModuleVersions(t *testing.T) {
	var modules []windows.RTL_PROCESS_MODULE_INFORMATION
	for bufferSize := uint32(128 * 1024); ; {
		moduleBuffer := make([]byte, bufferSize)
		err := windows.NtQuerySystemInformation(windows.SystemModuleInformation, unsafe.Pointer(&moduleBuffer[0]), bufferSize, &bufferSize)
		switch err {
		case windows.STATUS_INFO_LENGTH_MISMATCH:
			continue
		case nil:
			break
		default:
			t.Error(err)
			return
		}
		mods := (*windows.RTL_PROCESS_MODULES)(unsafe.Pointer(&moduleBuffer[0]))
		hdr := (*unsafeheader.Slice)(unsafe.Pointer(&modules))
		hdr.Data = unsafe.Pointer(&mods.Modules[0])
		hdr.Len = int(mods.NumberOfModules)
		hdr.Cap = int(mods.NumberOfModules)
		break
	}
	for i := range modules {
		moduleName := windows.ByteSliceToString(modules[i].FullPathName[modules[i].OffsetToFileName:])
		driverPath := `\\?\GLOBALROOT` + windows.ByteSliceToString(modules[i].FullPathName[:])
		var zero windows.Handle
		infoSize, err := windows.GetFileVersionInfoSize(driverPath, &zero)
		if err != nil {
			if err != windows.ERROR_FILE_NOT_FOUND {
				t.Error(err)
			}
			continue
		}
		versionInfo := make([]byte, infoSize)
		err = windows.GetFileVersionInfo(driverPath, 0, infoSize, unsafe.Pointer(&versionInfo[0]))
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND {
			t.Error(err)
			continue
		}
		var fixedInfo *windows.VS_FIXEDFILEINFO
		fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
		err = windows.VerQueryValue(unsafe.Pointer(&versionInfo[0]), `\`, (unsafe.Pointer)(&fixedInfo), &fixedInfoLen)
		if err != nil {
			t.Error(err)
			continue
		}
		t.Logf("%s: v%d.%d.%d.%d", moduleName,
			(fixedInfo.FileVersionMS>>16)&0xff,
			(fixedInfo.FileVersionMS>>0)&0xff,
			(fixedInfo.FileVersionLS>>16)&0xff,
			(fixedInfo.FileVersionLS>>0)&0xff)
	}
}

type fileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

func TestNtCreateFileAndNtSetInformationFile(t *testing.T) {
	var iosb windows.IO_STATUS_BLOCK
	var allocSize int64 = 0
	// Open test directory with NtCreateFile.
	testDirPath := t.TempDir()
	objectName, err := windows.NewNTUnicodeString("\\??\\" + testDirPath)
	if err != nil {
		t.Fatal(err)
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		ObjectName: objectName,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))
	var testDirHandle windows.Handle
	err = windows.NtCreateFile(&testDirHandle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, oa, &iosb,
		&allocSize, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE, 0, 0)
	if err != nil {
		t.Fatalf("NtCreateFile(%v) failed: %v", testDirPath, err)
	}
	defer windows.CloseHandle(testDirHandle)
	// Create a file in test directory with NtCreateFile.
	fileName := "filename"
	filePath := filepath.Join(testDirPath, fileName)
	objectName, err = windows.NewNTUnicodeString(fileName)
	if err != nil {
		t.Fatal(err)
	}
	oa.RootDirectory = testDirHandle
	oa.ObjectName = objectName
	var fileHandle windows.Handle
	err = windows.NtCreateFile(&fileHandle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE, oa, &iosb,
		&allocSize, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_CREATE,
		0, 0, 0)
	if err != nil {
		t.Fatalf("NtCreateFile(%v) failed: %v", filePath, err)
	}
	defer windows.CloseHandle(fileHandle)
	_, err = os.Stat(filePath)
	if err != nil {
		t.Fatalf("cannot stat file created with NtCreatefile: %v", err)
	}
	// Rename file with NtSetInformationFile.
	newName := "newname"
	newPath := filepath.Join(testDirPath, newName)
	newNameUTF16, err := windows.UTF16FromString(newName)
	if err != nil {
		t.Fatal(err)
	}
	fileNameLen := len(newNameUTF16)*2 - 2
	var dummyFileRenameInfo fileRenameInformation
	bufferSize := int(unsafe.Offsetof(dummyFileRenameInfo.FileName)) + fileNameLen
	buffer := make([]byte, bufferSize)
	typedBufferPtr := (*fileRenameInformation)(unsafe.Pointer(&buffer[0]))
	typedBufferPtr.ReplaceIfExists = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	typedBufferPtr.FileNameLength = uint32(fileNameLen)
	copy((*[windows.MAX_LONG_PATH]uint16)(unsafe.Pointer(&typedBufferPtr.FileName[0]))[:fileNameLen/2:fileNameLen/2], newNameUTF16)
	err = windows.NtSetInformationFile(fileHandle, &iosb, &buffer[0], uint32(bufferSize), windows.FileRenameInformation)
	if err != nil {
		t.Fatalf("NtSetInformationFile(%v) failed: %v", newPath, err)
	}
	_, err = os.Stat(newPath)
	if err != nil {
		t.Fatalf("cannot stat rename target %v: %v", newPath, err)
	}
}

var deviceClassNetGUID = &windows.GUID{0x4d36e972, 0xe325, 0x11ce, [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
var deviceInterfaceNetGUID = &windows.GUID{0xcac88484, 0x7515, 0x4c03, [8]byte{0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61}}

func TestListLoadedNetworkDevices(t *testing.T) {
	devInfo, err := windows.SetupDiGetClassDevsEx(deviceClassNetGUID, "", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer devInfo.Close()
	for i := 0; ; i++ {
		devInfoData, err := devInfo.EnumDeviceInfo(i)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}
		friendlyName, err := devInfo.DeviceRegistryProperty(devInfoData, windows.SPDRP_DEVICEDESC)
		if err != nil {
			t.Fatal(err)
		}
		var status, problemCode uint32
		err = windows.CM_Get_DevNode_Status(&status, &problemCode, devInfoData.DevInst, 0)
		if err != nil || (status&windows.DN_DRIVER_LOADED|windows.DN_STARTED) != windows.DN_DRIVER_LOADED|windows.DN_STARTED {
			continue
		}
		instanceId, err := devInfo.DeviceInstanceID(devInfoData)
		if err != nil {
			t.Fatal(err)
		}
		interfaces, err := windows.CM_Get_Device_Interface_List(instanceId, deviceInterfaceNetGUID, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
		if err != nil || len(interfaces) == 0 {
			continue
		}
		t.Logf("%s - %s", friendlyName, interfaces[0])
	}
}

func TestListWireGuardDrivers(t *testing.T) {
	devInfo, err := windows.SetupDiCreateDeviceInfoListEx(deviceClassNetGUID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer devInfo.Close()
	devInfoData, err := devInfo.CreateDeviceInfo("WireGuard", deviceClassNetGUID, "", 0, windows.DICD_GENERATE_ID)
	if err != nil {
		t.Fatal(err)
	}
	err = devInfo.SetDeviceRegistryProperty(devInfoData, windows.SPDRP_HARDWAREID, []byte("W\x00i\x00r\x00e\x00G\x00u\x00a\x00r\x00d\x00\x00\x00\x00\x00"))
	if err != nil {
		t.Fatal(err)
	}
	err = devInfo.BuildDriverInfoList(devInfoData, windows.SPDIT_COMPATDRIVER)
	if err != nil {
		t.Fatal(err)
	}
	defer devInfo.DestroyDriverInfoList(devInfoData, windows.SPDIT_COMPATDRIVER)
	for i := 0; ; i++ {
		drvInfoData, err := devInfo.EnumDriverInfo(devInfoData, windows.SPDIT_COMPATDRIVER, i)
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			continue
		}
		drvInfoDetailData, err := devInfo.DriverInfoDetail(devInfoData, drvInfoData)
		if err != nil {
			t.Error(err)
			continue
		}
		t.Logf("%s - %s", drvInfoData.Description(), drvInfoDetailData.InfFileName())
	}
}
