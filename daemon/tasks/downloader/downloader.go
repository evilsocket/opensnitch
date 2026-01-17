// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package downloader

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

import (
	"github.com/evilsocket/opensnitch/daemon/log"
)

// DownProgress ...
type DownProgress struct {
	URL   string
	Error error
	Bytes int64
}

// DownMgr ...
type DownMgr struct {
	// Urls holds the map of urls to download
	// key: remote url
	// value: local file
	Urls map[string]string

	Timeout time.Duration

	Results chan DownProgress
}

// NewDownloaderMgr ...
func NewDownloaderMgr(urls map[string]string, timeout time.Duration) *DownMgr {
	return &DownMgr{
		Urls:    urls,
		Timeout: timeout,
		Results: make(chan DownProgress),
	}
}

// Start ...
func (nd *DownMgr) Start() *sync.WaitGroup {
	var wg sync.WaitGroup
	for url, localFile := range nd.Urls {
		wg.Add(1)
		log.Debug("[DownloadManager] scheduling download %s -> %s\n", url, localFile)
		go nd.downloadFile(&wg, url, localFile)
	}
	return &wg
}

func (nd *DownMgr) downloadFile(wg *sync.WaitGroup, url, localFile string) {
	defer wg.Done()

	log.Debug("[DownloadManager] downloadFile: %s -> %s\n", url, localFile)
	out, err := os.OpenFile(localFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Warning("[DownloadManager] downloadFile, Create() error: %s, %s -> %s", err, url, localFile)
		nd.Results <- DownProgress{URL: url, Error: err}
		return
	}
	defer out.Close()

	client := http.Client{Timeout: nd.Timeout}
	resp, err := client.Get(url)
	if err != nil {
		log.Warning("[DownloadManager] downloadFile, http connect() error: %s, %s -> %s", err, url, localFile)
		nd.Results <- DownProgress{URL: url, Error: err}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warning("[DownloadManager] http status error (%d): %s, %s -> %s", resp.StatusCode, err, url, localFile)
		nd.Results <- DownProgress{URL: url, Error: err}
		return
	}

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		log.Warning("[DownloadManager] Copy() error: %s, %s -> %s", err, url, localFile)
		nd.Results <- DownProgress{URL: url, Error: err}
		return
	}

	if n == 0 {
		log.Warning("[DownloadManager] 0 bytes (list empty/moved?): %s, %s -> %s", err, url, localFile)
		nd.Results <- DownProgress{URL: url, Error: fmt.Errorf("list is empty")}
		return
	}
	nd.Results <- DownProgress{URL: url, Error: nil, Bytes: n}
}

// Progress ...
func (nd *DownMgr) Progress() <-chan DownProgress {
	return nd.Results
}
