package core

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultTrimSet = "\r\n\t "
)

// Trim remove trailing spaces from a string.
func Trim(s string) string {
	return strings.Trim(s, defaultTrimSet)
}

// Exec spawns a new process and reurns the output.
func Exec(executable string, args []string) (string, error) {
	path, err := exec.LookPath(executable)
	if err != nil {
		return "", err
	}

	raw, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return "", err
	}
	return Trim(string(raw)), nil
}

// Exists checks if a path exists.
func Exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// ExpandPath replaces '~' shorthand with the user's home directory.
func ExpandPath(path string) (string, error) {
	// Check if path is empty
	if path != "" {
		if strings.HasPrefix(path, "~") {
			usr, err := user.Current()
			if err != nil {
				return "", err
			}
			// Replace only the first occurrence of ~
			path = strings.Replace(path, "~", usr.HomeDir, 1)
		}
		return filepath.Abs(path)
	}
	return "", nil
}

// IsAbsPath verifies if a path is absolute or not
func IsAbsPath(path string) bool {
	return path[0] == 47 // 47 == '/'
}

// GetFileModTime checks if a file has been modified.
func GetFileModTime(filepath string) (time.Time, error) {
	fi, err := os.Stat(filepath)
	if err != nil || fi.IsDir() {
		return time.Now(), fmt.Errorf("GetFileModTime() Invalid file")
	}
	return fi.ModTime(), nil
}

// ConcatStrings joins the provided strings.
func ConcatStrings(args ...string) string {
	return strings.Join(args, "")
}
