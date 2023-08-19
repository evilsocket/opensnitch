// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cache

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/internal/event"
	"golang.org/x/tools/internal/event/keys"
	"golang.org/x/tools/internal/gocommand"
	"golang.org/x/tools/internal/imports"
	"golang.org/x/tools/internal/lsp/source"
)

type importsState struct {
	ctx context.Context

	mu                   sync.Mutex
	processEnv           *imports.ProcessEnv
	cleanupProcessEnv    func()
	cacheRefreshDuration time.Duration
	cacheRefreshTimer    *time.Timer
	cachedModFileHash    string
	cachedBuildFlags     []string
}

func (s *importsState) runProcessEnvFunc(ctx context.Context, snapshot *snapshot, fn func(*imports.Options) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the hash of the active mod file, if any. Using the unsaved content
	// is slightly wasteful, since we'll drop caches a little too often, but
	// the mod file shouldn't be changing while people are autocompleting.
	var modFileHash string
	if snapshot.workspaceMode()&usesWorkspaceModule == 0 {
		for m := range snapshot.workspace.getActiveModFiles() { // range to access the only element
			modFH, err := snapshot.GetFile(ctx, m)
			if err != nil {
				return err
			}
			modFileHash = modFH.FileIdentity().Hash
		}
	} else {
		modFile, err := snapshot.workspace.modFile(ctx, snapshot)
		if err != nil {
			return err
		}
		modBytes, err := modFile.Format()
		if err != nil {
			return err
		}
		modFileHash = hashContents(modBytes)
	}

	// view.goEnv is immutable -- changes make a new view. Options can change.
	// We can't compare build flags directly because we may add -modfile.
	snapshot.view.optionsMu.Lock()
	localPrefix := snapshot.view.options.Local
	currentBuildFlags := snapshot.view.options.BuildFlags
	changed := !reflect.DeepEqual(currentBuildFlags, s.cachedBuildFlags) ||
		snapshot.view.options.VerboseOutput != (s.processEnv.Logf != nil) ||
		modFileHash != s.cachedModFileHash
	snapshot.view.optionsMu.Unlock()

	// If anything relevant to imports has changed, clear caches and
	// update the processEnv. Clearing caches blocks on any background
	// scans.
	if changed {
		// As a special case, skip cleanup the first time -- we haven't fully
		// initialized the environment yet and calling GetResolver will do
		// unnecessary work and potentially mess up the go.mod file.
		if s.cleanupProcessEnv != nil {
			if resolver, err := s.processEnv.GetResolver(); err == nil {
				if modResolver, ok := resolver.(*imports.ModuleResolver); ok {
					modResolver.ClearForNewMod()
				}
			}
			s.cleanupProcessEnv()
		}
		s.cachedModFileHash = modFileHash
		s.cachedBuildFlags = currentBuildFlags
		var err error
		s.cleanupProcessEnv, err = s.populateProcessEnv(ctx, snapshot)
		if err != nil {
			return err
		}
	}

	// Run the user function.
	opts := &imports.Options{
		// Defaults.
		AllErrors:   true,
		Comments:    true,
		Fragment:    true,
		FormatOnly:  false,
		TabIndent:   true,
		TabWidth:    8,
		Env:         s.processEnv,
		LocalPrefix: localPrefix,
	}

	if err := fn(opts); err != nil {
		return err
	}

	if s.cacheRefreshTimer == nil {
		// Don't refresh more than twice per minute.
		delay := 30 * time.Second
		// Don't spend more than a couple percent of the time refreshing.
		if adaptive := 50 * s.cacheRefreshDuration; adaptive > delay {
			delay = adaptive
		}
		s.cacheRefreshTimer = time.AfterFunc(delay, s.refreshProcessEnv)
	}

	return nil
}

// populateProcessEnv sets the dynamically configurable fields for the view's
// process environment. Assumes that the caller is holding the s.view.importsMu.
func (s *importsState) populateProcessEnv(ctx context.Context, snapshot *snapshot) (cleanup func(), err error) {
	pe := s.processEnv

	if snapshot.view.Options().VerboseOutput {
		pe.Logf = func(format string, args ...interface{}) {
			event.Log(ctx, fmt.Sprintf(format, args...))
		}
	} else {
		pe.Logf = nil
	}

	// Take an extra reference to the snapshot so that its workspace directory
	// (if any) isn't destroyed while we're using it.
	release := snapshot.generation.Acquire()
	_, inv, cleanupInvocation, err := snapshot.goCommandInvocation(ctx, source.LoadWorkspace, &gocommand.Invocation{
		WorkingDir: snapshot.view.rootURI.Filename(),
	})
	if err != nil {
		return nil, err
	}
	pe.WorkingDir = inv.WorkingDir
	pe.BuildFlags = inv.BuildFlags
	pe.WorkingDir = inv.WorkingDir
	pe.ModFile = inv.ModFile
	pe.ModFlag = inv.ModFlag
	pe.Env = map[string]string{}
	for _, kv := range inv.Env {
		split := strings.SplitN(kv, "=", 2)
		if len(split) != 2 {
			continue
		}
		pe.Env[split[0]] = split[1]
	}

	return func() {
		cleanupInvocation()
		release()
	}, nil
}

func (s *importsState) refreshProcessEnv() {
	start := time.Now()

	s.mu.Lock()
	env := s.processEnv
	if resolver, err := s.processEnv.GetResolver(); err == nil {
		resolver.ClearForNewScan()
	}
	s.mu.Unlock()

	event.Log(s.ctx, "background imports cache refresh starting")
	if err := imports.PrimeCache(context.Background(), env); err == nil {
		event.Log(s.ctx, fmt.Sprintf("background refresh finished after %v", time.Since(start)))
	} else {
		event.Log(s.ctx, fmt.Sprintf("background refresh finished after %v", time.Since(start)), keys.Err.Of(err))
	}
	s.mu.Lock()
	s.cacheRefreshDuration = time.Since(start)
	s.cacheRefreshTimer = nil
	s.mu.Unlock()
}

func (s *importsState) destroy() {
	s.mu.Lock()
	if s.cleanupProcessEnv != nil {
		s.cleanupProcessEnv()
	}
	s.mu.Unlock()
}
