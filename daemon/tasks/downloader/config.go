// Copyright 2025 The OpenSnitch Authors. All rights reserved.
// Use of this source code is governed by the GPLv3
// license that can be found in the LICENSE file.

package downloader

import (
	"encoding/json"
)

type NotifyType string

var (
	Enabled       = "enabled"
	NotifyDesktop = NotifyType("desktop")
)

type NotifyObj map[string]interface{}

type NotifyStatus struct {
	Type    NotifyType `json:"type"`
	Message string     `json:"message"`
}

type NotifyOpts struct {
	Success NotifyStatus `json:"success"`
	Error   NotifyStatus `json:"error"`
	Enabled bool         `json:"enabled"`
}

type UrlOptions struct {
	Name      string
	Remote    string
	LocalFile string
	Enabled   bool
}

type DownloaderConfig struct {
	Interval string
	Timeout  string

	Urls   []UrlOptions
	Notify NotifyOpts
}

func loadConfig(data map[string]interface{}) (DownloaderConfig, error) {
	dataStr, err := json.Marshal(data)
	if err != nil {
		return DownloaderConfig{}, err
	}
	var dc DownloaderConfig
	err = json.Unmarshal([]byte(dataStr), &dc)
	return dc, err
}
