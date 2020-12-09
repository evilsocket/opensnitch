package core

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
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
