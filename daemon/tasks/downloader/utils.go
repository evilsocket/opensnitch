// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package downloader

import (
	"os"
	"path/filepath"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
)

func (pm *Downloader) parseInterval() (time.Duration, error) {
	if pm.Config.Interval == "" {
		pm.Config.Interval = DefaultInterval
	}
	return time.ParseDuration(pm.Config.Interval)
}

func (pm *Downloader) parseTimeout() (time.Duration, error) {
	if pm.Config.Timeout == "" {
		pm.Config.Timeout = DefaultTimeout
	}
	return time.ParseDuration(pm.Config.Timeout)
}

// the urls have this format:
// {
//   "name": "name-of-the-url-list",
//   "enabled": true,
//   "remote": "https://adaway.org/hosts.txt",
//   "localfile": "/tmp/blacklist/ads-adaway-hosts.txt"
// }
//
// XXX: we may need to have a interval option per list.
// The lists are not updated on the same date, and they may fail or stop working.
// so a Interval field per list could be used to update them at different intervals,
// or disable them (interval == 0) if they fail after n errors.
func (pm *Downloader) loadUrls() error {

	for _, url := range pm.Config.Urls {
		localdir := filepath.Dir(url.LocalFile)
		if !core.Exists(localdir) {
			err := os.MkdirAll(localdir, 0700)
			if err != nil {
				log.Warning("[Downloader] url %s localdir create error %s: %s", url.Name, localdir, err)
				continue
			}
			log.Debug("[Downloader] localdir created %s", localdir)
		} else {
			log.Debug("[Downloader] localdir exists %s", localdir)
		}

		pm.Urls[url.Remote] = url.LocalFile
	}

	return nil
}
