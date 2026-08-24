package procmon

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
)

type CgroupMonitorConfig struct {
	Name               string `json:"name"`
	Enabled            bool   `json:"enabled"`
	BasePath           string `json:"base_path"`
	RegexStr           string `json:"regex"`
	DisplayName        string `json:"display_name"`
	ContainerNameRegex string `json:"container_name_regex,omitempty"`
	compiledRe         *regexp.Regexp
	compiledNameRe     *regexp.Regexp
}

type ContainerContext struct {
	IsContainer   bool   `json:"is_container"`
	Runtime       string `json:"runtime,omitempty"`
	CgroupPath    string `json:"cgroup_path,omitempty"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"` // Derived from runtime metadata/env vars
}

const maxDockerContainerNameCacheEntries = 1024

type dockerContainerNameCacheStore struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[string]string
	order      []string
}

func newDockerContainerNameCache(maxEntries int) *dockerContainerNameCacheStore {
	if maxEntries <= 0 {
		maxEntries = maxDockerContainerNameCacheEntries
	}
	return &dockerContainerNameCacheStore{
		maxEntries: maxEntries,
		entries:    make(map[string]string, maxEntries),
		order:      make([]string, 0, maxEntries),
	}
}

func (c *dockerContainerNameCacheStore) Load(containerID string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	name, ok := c.entries[containerID]
	return name, ok
}

func (c *dockerContainerNameCacheStore) Store(containerID, name string) {
	if c == nil || containerID == "" || name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[containerID]; !ok {
		if len(c.entries) >= c.maxEntries {
			if len(c.order) == 0 {
				return
			}
			oldest := c.order[0]
			delete(c.entries, oldest)
			c.order = c.order[1:]
		}
		c.order = append(c.order, containerID)
	}
	c.entries[containerID] = name
}

func (c *dockerContainerNameCacheStore) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]string, c.maxEntries)
	c.order = c.order[:0]
}

var cgroupMonitors []*CgroupMonitorConfig
var dockerContainerNameCache = newDockerContainerNameCache(maxDockerContainerNameCacheEntries)

var dockerContainerNameLookup = lookupDockerContainerNameFromConfig

func lookupDockerContainerName(containerID string) string {
	if containerID == "" {
		return ""
	}

	if cached, ok := dockerContainerNameCache.Load(containerID); ok {
		return cached
	}

	name := dockerContainerNameLookup(containerID)
	if name == "" {
		return ""
	}

	dockerContainerNameCache.Store(containerID, name)
	return name
}

func lookupDockerContainerNameFromConfig(containerID string) string {
	configPath := filepath.Join("/var/lib/docker/containers", containerID, "config.v2.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	var cfg struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}

	return strings.TrimPrefix(strings.TrimSpace(cfg.Name), "/")
}

// DefaultCgroupMonitors returns the built-in cgroup monitor configuration.
func DefaultCgroupMonitors() []*CgroupMonitorConfig {
	return []*CgroupMonitorConfig{
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
			BasePath:           "containerd|crio",
			RegexStr:           "(?:containerd|crio)-(?P<id>[a-f0-9]{64})",
			DisplayName:        "Containerd",
			ContainerNameRegex: "(?:containerd|crio)-(?P<name>.+?)-[a-f0-9]{64}",
		},
		{
			Name:               "k8s",
			Enabled:            false,
			BasePath:           "/kubepods",
			RegexStr:           "kubepods.*pod(?P<pod_id>[a-f0-9_-]+)[./].*(?P<id>[a-f0-9]{64})",
			DisplayName:        "Kubernetes",
			ContainerNameRegex: "kubepods.*pod(?P<name>[a-f0-9_-]+)",
		},
	}
}

// InitCgroupMonitors initializes the global cgroup monitors config and compiles regexes
func InitCgroupMonitors(monitors []*CgroupMonitorConfig) {
	cgroupMonitors = monitors
	for _, m := range cgroupMonitors {
		if !m.Enabled {
			continue
		}
		re, err := regexp.Compile(m.RegexStr)
		if err != nil {
			log.Error("Failed to compile regex for cgroup monitor %s: %v", m.Name, err)
			m.Enabled = false
			continue
		}
		m.compiledRe = re

		// Compile container name regex if provided
		if m.ContainerNameRegex != "" {
			nameRe, err := regexp.Compile(m.ContainerNameRegex)
			if err != nil {
				log.Error("Failed to compile container name regex for cgroup monitor %s: %v", m.Name, err)
				// Don't disable the monitor, just skip the name extraction
			} else {
				m.compiledNameRe = nameRe
			}
		}
	}
}

// ParseContainer checks if a process belongs to a container by reading its cgroup file.
func ParseContainer(cgroupPath string, env map[string]string) *ContainerContext {
	if len(cgroupMonitors) == 0 {
		return nil
	}

	file, err := os.Open(cgroupPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Strip hierarchy prefixes for cgroup v1 (e.g. 11:memory:/docker/...)
		// and cgroup v2 (e.g. 0::/user.slice/...)
		parts := strings.SplitN(line, ":", 3)
		var cPath string
		if len(parts) == 3 {
			cPath = parts[2]
		} else {
			cPath = line
		}

		for _, monitor := range cgroupMonitors {
			if !monitor.Enabled {
				continue
			}

			if monitor.BasePath == "" || strings.Contains(cPath, monitor.BasePath) || (monitor.Name == "containerd" && (strings.Contains(cPath, "containerd") || strings.Contains(cPath, "crio"))) {
				matches := monitor.compiledRe.FindStringSubmatch(cPath)
				if matches != nil {
					idIndex := monitor.compiledRe.SubexpIndex("id")
					if idIndex != -1 {
						containerID := matches[idIndex]

						// Determine container name from env, runtime metadata or cgroup path
						// Priority:
						// 1. CONTAINER_NAME env var (explicit name)
						// 2. Runtime specific metadata (Docker config)
						// 3. Extract from cgroup path regex
						// 4. Fall back to container ID short form
						containerName := ""
						if name, ok := env["CONTAINER_NAME"]; ok {
							containerName = name
						} else if monitor.Name == "docker" {
							containerName = lookupDockerContainerName(containerID)
						} else if monitor.compiledNameRe != nil {
							// Try to extract container name from cgroup path
							nameMatches := monitor.compiledNameRe.FindStringSubmatch(cPath)
							if nameMatches != nil {
								nameIndex := monitor.compiledNameRe.SubexpIndex("name")
								if nameIndex != -1 {
									containerName = nameMatches[nameIndex]
								}
							}
						}

						// Fallback to container ID short form if no name found
						if containerName == "" && len(containerID) >= 7 {
							containerName = containerID[:7]
						}

						return &ContainerContext{
							IsContainer:   true,
							Runtime:       monitor.DisplayName,
							CgroupPath:    cPath,
							ContainerID:   containerID,
							ContainerName: containerName,
						}
					}
				}
			}
		}
	}
	return nil
}
