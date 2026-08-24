package procmon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseContainer(t *testing.T) {
	oldMonitors := cgroupMonitors
	oldDockerLookup := dockerContainerNameLookup
	t.Cleanup(func() {
		cgroupMonitors = oldMonitors
		dockerContainerNameLookup = oldDockerLookup
		dockerContainerNameCache.Reset()
	})
	dockerContainerNameCache.Reset()

	monitors := []*CgroupMonitorConfig{
		{
			Name:               "docker",
			Enabled:            true,
			BasePath:           "docker",
			RegexStr:           "docker[/-](?P<id>[a-f0-9]{64})",
			DisplayName:        "Docker",
			ContainerNameRegex: "docker-(?P<name>[a-zA-Z0-9._-]+?)-[a-f0-9]{64}",
		},
		{
			Name:               "podman_rootless",
			Enabled:            true,
			BasePath:           "libpod",
			RegexStr:           "libpod-(?P<id>[a-f0-9]{64})\\.scope",
			DisplayName:        "Podman (Rootless)",
			ContainerNameRegex: "libpod-(?P<name>.+?)-[a-f0-9]{64}",
		},
		{
			Name:               "containerd",
			Enabled:            true,
			BasePath:           "containerd",
			RegexStr:           "(?:containerd|crio)-(?P<id>[a-f0-9]{64})",
			DisplayName:        "Containerd",
			ContainerNameRegex: "(?:containerd|crio)-(?P<name>.+?)-[a-f0-9]{64}",
		},
	}
	InitCgroupMonitors(monitors)

	dockerID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	podmanID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	containerdID := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	dockerContainerNameLookup = func(containerID string) string {
		if containerID == dockerID {
			return "foo"
		}
		return ""
	}

	tests := []struct {
		name        string
		content     string
		env         map[string]string
		wantNil     bool
		wantRuntime string
		wantCgroup  string
		wantID      string
		wantName    string
	}{
		{
			name:        "docker cgroup v1 prefers container name",
			content:     "11:memory:/docker/" + dockerID + "\n",
			env:         map[string]string{"CONTAINER_NAME": "web"},
			wantRuntime: "Docker",
			wantCgroup:  "/docker/" + dockerID,
			wantID:      dockerID,
			wantName:    "web",
		},
		{
			name:        "podman cgroup v2 ignores hostname and falls back to short id",
			content:     "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + podmanID + ".scope\n",
			env:         map[string]string{"HOSTNAME": "pod-a"},
			wantRuntime: "Podman (Rootless)",
			wantCgroup:  "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + podmanID + ".scope",
			wantID:      podmanID,
			wantName:    "abcdef0",
		},
		{
			name:        "docker cgroup v2 gets name from docker metadata",
			content:     "0::/system.slice/docker-" + dockerID + ".scope\n",
			env:         map[string]string{"HOSTNAME": "adrian-QEMU-Virtual-Machine"},
			wantRuntime: "Docker",
			wantCgroup:  "/system.slice/docker-" + dockerID + ".scope",
			wantID:      dockerID,
			wantName:    "foo",
		},
		{
			name:        "containerd falls back to short id when env is empty",
			content:     "0::/system.slice/containerd.service/containerd-" + containerdID + ".scope\n",
			env:         map[string]string{},
			wantRuntime: "Containerd",
			wantCgroup:  "/system.slice/containerd.service/containerd-" + containerdID + ".scope",
			wantID:      containerdID,
			wantName:    "fedcba9",
		},
		{
			name:        "crio cgroup is recognized by the containerd monitor",
			content:     "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/crio-" + containerdID + ".scope\n",
			env:         map[string]string{},
			wantRuntime: "Containerd",
			wantCgroup:  "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/crio-" + containerdID + ".scope",
			wantID:      containerdID,
			wantName:    "fedcba9",
		},
		{
			name:    "returns nil when no monitor matches",
			content: "0::/user.slice/user-1000.slice/session-2.scope\n",
			env:     map[string]string{"HOSTNAME": "host"},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cgroupPath := writeTempCgroupFile(t, tt.content)
			got := ParseContainer(cgroupPath, tt.env)

			if tt.wantNil {
				if got != nil {
					t.Fatalf("ParseContainer() = %#v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("ParseContainer() = nil, want container context")
			}
			if !got.IsContainer {
				t.Fatal("ParseContainer() returned a non-container context")
			}
			if got.Runtime != tt.wantRuntime {
				t.Fatalf("Runtime = %q, want %q", got.Runtime, tt.wantRuntime)
			}
			if got.CgroupPath != tt.wantCgroup {
				t.Fatalf("CgroupPath = %q, want %q", got.CgroupPath, tt.wantCgroup)
			}
			if got.ContainerID != tt.wantID {
				t.Fatalf("ContainerID = %q, want %q", got.ContainerID, tt.wantID)
			}
			if got.ContainerName != tt.wantName {
				t.Fatalf("ContainerName = %q, want %q", got.ContainerName, tt.wantName)
			}
		})
	}
}

func TestParseContainerReturnsNilWithoutMonitors(t *testing.T) {
	oldMonitors := cgroupMonitors
	cgroupMonitors = nil
	t.Cleanup(func() {
		cgroupMonitors = oldMonitors
	})

	cgroupPath := writeTempCgroupFile(t, "11:memory:/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
	if got := ParseContainer(cgroupPath, map[string]string{"CONTAINER_NAME": "web"}); got != nil {
		t.Fatalf("ParseContainer() = %#v, want nil when monitors are not initialized", got)
	}
}

func TestInitCgroupMonitorsDisablesInvalidRegex(t *testing.T) {
	oldMonitors := cgroupMonitors
	t.Cleanup(func() {
		cgroupMonitors = oldMonitors
	})

	monitors := []*CgroupMonitorConfig{
		{
			Name:        "broken",
			Enabled:     true,
			BasePath:    "docker",
			RegexStr:    "(",
			DisplayName: "Broken",
		},
	}

	InitCgroupMonitors(monitors)

	var brokenMonitor *CgroupMonitorConfig
	for _, m := range cgroupMonitors {
		if m.Name == "broken" {
			brokenMonitor = m
			break
		}
	}

	if brokenMonitor == nil {
		t.Fatal("broken monitor not found")
	}
	if brokenMonitor.Enabled {
		t.Fatal("InitCgroupMonitors() left an invalid regex monitor enabled")
	}
	if brokenMonitor.compiledRe != nil {
		t.Fatal("InitCgroupMonitors() compiled an invalid regex")
	}

	cgroupPath := writeTempCgroupFile(t, "11:memory:/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
	if got := ParseContainer(cgroupPath, map[string]string{"CONTAINER_NAME": "web"}); got != nil {
		t.Fatalf("ParseContainer() = %#v, want nil when the only monitor is invalid", got)
	}
}

func TestDefaultCgroupMonitors(t *testing.T) {
	monitors := DefaultCgroupMonitors()
	if len(monitors) == 0 {
		t.Fatal("DefaultCgroupMonitors() returned no monitors")
	}

	names := make(map[string]bool)
	for _, m := range monitors {
		names[m.Name] = true
	}

	if !names["docker"] {
		t.Fatal("DefaultCgroupMonitors() is missing docker")
	}
	if !names["podman_rootless"] {
		t.Fatal("DefaultCgroupMonitors() is missing podman_rootless")
	}
	if !names["containerd"] {
		t.Fatal("DefaultCgroupMonitors() is missing containerd")
	}
}

func TestLookupDockerContainerNameDoesNotCacheMisses(t *testing.T) {
	oldDockerLookup := dockerContainerNameLookup
	t.Cleanup(func() {
		dockerContainerNameLookup = oldDockerLookup
		dockerContainerNameCache.Reset()
	})
	dockerContainerNameCache.Reset()

	containerID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	lookupCalls := 0
	dockerContainerNameLookup = func(id string) string {
		lookupCalls++
		if id != containerID {
			t.Fatalf("lookup called with %q, want %q", id, containerID)
		}
		return ""
	}

	if got := lookupDockerContainerName(containerID); got != "" {
		t.Fatalf("lookupDockerContainerName() = %q, want empty string", got)
	}
	if got := lookupDockerContainerName(containerID); got != "" {
		t.Fatalf("lookupDockerContainerName() second call = %q, want empty string", got)
	}
	if lookupCalls != 2 {
		t.Fatalf("lookupDockerContainerName() called lookup %d times, want 2", lookupCalls)
	}

	if _, ok := dockerContainerNameCache.Load(containerID); ok {
		t.Fatal("lookupDockerContainerName() cached a missing container name")
	}
}

func writeTempCgroupFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", path, err)
	}
	return path
}
