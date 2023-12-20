package config

import (
	"testing"
)

func preloadConfCallback() {
}

func reloadConfCallback() {
}

func TestNftLoadFromDisk(t *testing.T) {
	/*skipIfNotPrivileged(t)

	conn, newNS = OpenSystemConn(t)
	defer CleanupSystemConn(t, newNS)
	nft.conn = conn
	*/
	cfg := &Config{}
	cfg.NewSystemFwConfig("", preloadConfCallback, reloadConfCallback)
	cfg.SetConfigFile("../nftables/testdata/test-sysfw-conf.json")
	if err := cfg.LoadDiskConfiguration(false); err != nil {
		t.Errorf("Error loading config from disk: %s", err)
	}
}
